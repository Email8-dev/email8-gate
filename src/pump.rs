// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Connection pump (design §3.2): accept → upstream select → PROXY v2
//! prepend → `copy_bidirectional`.
//!
//! One spawned task per accepted connection. Upstream selection pins
//! for the connection's life; a failed connect evicts the instance and
//! tries the next Active instance; empty Active set → immediate close
//! (counted). Graceful shutdown: listeners close first, established
//! pumps drain naturally within the captain grace period.

use crate::config::{GateConfig, Listener};
use crate::counters;
use crate::registry::Registry;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Bind a raw listener. When `EMAIL8_GATE_REUSE_PORT=true`, sets
/// SO_REUSEPORT *and* SO_REUSEADDR before bind so multiple gate
/// instances can hold the same well-known ports concurrently — the
/// kernel load-balances new connections across them, making gate
/// upgrades zero-downtime (design §4.2, story 7.6). Standard bind
/// otherwise.
async fn bind_listener(addr: &str) -> anyhow::Result<TcpListener> {
    let sock: std::net::SocketAddr =
        addr.parse().map_err(|e| anyhow::anyhow!("bad listener addr {addr}: {e}"))?;
    let reuse = std::env::var("EMAIL8_GATE_REUSE_PORT")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    #[cfg(unix)]
    if reuse {
        let domain = if sock.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let s2 = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        s2.set_reuse_address(true)?;
        s2.set_reuse_port(true)?;
        s2.set_nonblocking(true)?;
        s2.bind(&sock.into())?;
        s2.listen(1024)?;
        tracing::info!(addr, "email8:gate: listener bound with SO_REUSEPORT");
        return Ok(TcpListener::from_std(s2.into())?);
    }

    Ok(TcpListener::bind(&addr).await?)
}

/// Per-listener accept loop. Runs until shutdown; each accepted
/// connection is handled in its own task.
pub async fn serve_listener(
    listener: Listener,
    config: Arc<GateConfig>,
    registry: Registry,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", listener.port);
    let sock = bind_listener(&addr).await?;
    tracing::info!(
        listener = listener.name,
        port = listener.port,
        upstream = listener.upstream_service,
        "email8:gate: listener bound"
    );
    let sem = Arc::new(Semaphore::new(config.max_conns));
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!(listener = listener.name, "email8:gate: listener closing (drain)");
                break;
            }
            accepted = sock.accept() => {
                let (mut client, client_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(listener = listener.name, error = %e, "email8:gate: accept error");
                        continue;
                    }
                };
                let permit = match sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Backpressure at the gate ahead of upstream
                        // session machinery (design §5).
                        tracing::warn!(listener = listener.name, "email8:gate: connection cap reached — refusing");
                        let _ = client.shutdown().await;
                        continue;
                    }
                };
                let cfg = config.clone();
                let reg = registry.clone();
                let name = listener.name;
                tokio::spawn(async move {
                    handle_connection(name, &cfg, &reg, client, client_addr).await;
                    drop(permit);
                });
            }
        }
    }
    Ok(())
}

/// Forward one client connection: select upstream (round-robin,
/// failover on connect failure), prepend PROXY v2 when enabled, pump.
async fn handle_connection(
    listener: &'static str,
    config: &GateConfig,
    registry: &Registry,
    mut client: TcpStream,
    client_addr: std::net::SocketAddr,
) {
    let service = listener_upstream(config, listener);
    let timeout = Duration::from_millis(config.connect_timeout_ms);
    // Dial target resolution (design §4.1): the upstream publishes its
    // actual raw listener map to Valkey (`captain:listeners:*`); the gate
    // dials that. Fall back to the catalog-declared fallback port only
    // when nothing is published (dev direct-bind mode).
    let map = registry.listener_map(&service).await;
    let upstream_port = map
        .ports
        .get(listener)
        .map(|(p, _)| *p)
        .or_else(|| listener_upstream_port_opt(config, listener));
    let Some(upstream_port) = upstream_port else {
        counters::record_upstream_unavailable();
        tracing::error!(listener, service = %service, "email8:gate: no published listener map and no fallback — refusing");
        return;
    };
    let mut upstream: Option<(TcpStream, String)> = None;
    // Bounded failover: at most 3 upstream attempts per accept, then
    // give up (avoids pathological retry loops when everything is down).
    for _ in 0..3 {
        let inst = match registry.next_instance(&service).await {
            Ok(i) => i,
            Err(crate::GateError::NoUpstream { .. }) => {
                counters::record_upstream_unavailable();
                tracing::warn!(listener, service = %service, "email8:gate: no Active upstream");
                return;
            }
            Err(e) => {
                tracing::error!(listener, error = %e, "email8:gate: registry error");
                return;
            }
        };
        // Dial the upstream's PUBLISHED raw listener port for this
        // protocol (the registry's local_port is the upstream's shell
        // HTTPS port — design §4.1).
        let dial = format!("{}:{}", inst.local_ip, upstream_port);
        match tokio::time::timeout(timeout, TcpStream::connect(&dial)).await {
            Ok(Ok(stream)) => {
                upstream = Some((stream, inst.key.clone()));
                break;
            }
            Ok(Err(e)) => {
                tracing::warn!(listener, upstream = %dial, error = %e, "email8:gate: upstream connect failed — evicting");
                registry.evict(&service, &inst.key).await;
                counters::record_upstream_unavailable();
            }
            Err(_) => {
                tracing::warn!(listener, upstream = %dial, "email8:gate: upstream connect timeout — evicting");
                registry.evict(&service, &inst.key).await;
                counters::record_upstream_unavailable();
            }
        }
    }
    let Some((mut upstream, _key)) = upstream else {
        return; // client sees a plain close (design §3.4)
    };

    // PROXY v2 header (design §3.3): prepend the client address before
    // any byte of the client stream is forwarded. The upstream parses
    // it when `accept_proxy` is enabled on the gated listener.
    if config.proxy_proto {
        let dst_addr = upstream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid addr"));
        let header = crate::proxy_v2::header_for(client_addr, dst_addr);
        if upstream.write_all(&header).await.is_err() {
            return;
        }
    }

    counters::record_connection(0, 0); // byte totals settle at pump exit
    let (bytes_in, bytes_out) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await.unwrap_or((0, 0));
    // FIN propagation both directions is copy_bidirectional's job; no
    // extra half-close dance needed. Idle reaping stays upstream's job.
    counters::record_connection_bytes(bytes_in, bytes_out);
}

/// Listener → upstream service: re-read the config table (small, per
/// accept is fine) so mapping stays declarative.
fn listener_upstream(config: &GateConfig, listener_name: &str) -> String {
    listener_config(config, listener_name)
        .map(|l| l.upstream_service.to_string())
        .unwrap_or_else(|| "email8:mta".to_string())
}

/// Listener → the catalog fallback raw port (used only when the
/// upstream published no listener map).
fn listener_upstream_port_opt(config: &GateConfig, listener_name: &str) -> Option<u16> {
    listener_config(config, listener_name).map(|l| l.upstream_port)
}

fn listener_config<'c>(config: &'c GateConfig, listener_name: &str) -> Option<&'c crate::config::Listener> {
    config.listeners.iter().find(|l| l.name == listener_name)
}