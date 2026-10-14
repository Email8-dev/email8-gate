// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Gate configuration: listener table + upstream mapping from env.
//!
//! Env surface (design §2/§4.1):
//! - `EMAIL8_GATE_SMTP_PORT=25`, `EMAIL8_GATE_SUBMISSION_PORT=587`,
//!   `EMAIL8_GATE_SUBMISSIONS_PORT=465`, `EMAIL8_GATE_IMAP_PORT=143`,
//!   `EMAIL8_GATE_IMAPS_PORT=993`, `EMAIL8_GATE_POP3_PORT=110`,
//!   `EMAIL8_GATE_POP3S_PORT=995`, `EMAIL8_GATE_SIEVE_PORT=4190`.
//!   An empty value disables that listener (dev boxes without
//!   CAP_NET_BIND_SERVICE).
//! - `EMAIL8_GATE_PROXY_PROTO` — emit PROXY protocol v2 (default true;
//!   upstreams must enable `accept_proxy` on the gated listeners).
//! - `EMAIL8_GATE_MTA_UPSTREAMS=email8-mta:smtp,submission,submissions`
//! - `EMAIL8_GATE_ACCESS_UPSTREAMS=email8-access:imap,imaps,pop3,pop3s,sieve`
//!   (`service:listener` CSV — declarative, no hardcoded knowledge).
//! - `EMAIL8_GATE_MAX_CONNS=2048` — per-listener concurrency cap.
//! - `VALKEY_URL` / `SENTIN8_VALKEY_URL` — registry reads.
//!
//! Listener→upstream wiring is derived by convention: listener keys map
//! to upstream service via the CSV mapping above, and the upstream's
//! own port env is `{SERVICE_PREFIX}_{LISTENER}_PORT` — but the gate
//! never reads upstream envs; it discovers `{ip}:{port}` from the
//! registry, so the CSV only partitions listeners per service.

use std::collections::HashMap;

/// One forwarded listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// Stable listener name (used in metrics + PROXY v2 logging).
    pub name: &'static str,
    /// Well-known port to bind (0 = disabled).
    pub port: u16,
    /// Upstream service type in the captain registry.
    pub upstream_service: &'static str,
    /// The RAW port the upstream service binds for this protocol (the
    /// non-privileged fallback — upstreams no longer own well-known
    /// ports; design §4.1). Overridable via EMAIL8_GATE_{NAME}_UPSTREAM_PORT.
    pub upstream_port: u16,
}

/// Declarative listener → upstream partition, from
/// `EMAIL8_GATE_{MTA,ACCESS}_UPSTREAMS` CSVs. The service identity is
/// the colon form `email8:mta` (architecture-principles §6.0), so the
/// prefix split is on the LAST colon — `email8:mta:smtp submission`
/// yields service `email8:mta`, listeners `smtp submission`.
fn parse_upstreams(spec: &str, default_service: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (service, listeners) = match entry.rsplit_once(':') {
            Some((svc, lst)) => (svc.trim().to_string(), lst.to_string()),
            None => (default_service.to_string(), entry.to_string()),
        };
        // A bare listener name may still carry no service prefix; a name
        // that accidentally contains a colon is the service-type form.
        for l in listeners.split_whitespace() {
            map.insert(l.to_string(), service.clone());
        }
    }
    map
}

impl Listener {
    /// The full listener table from env. Disabled listeners (empty env
    /// value) are omitted.
    pub fn from_env() -> Vec<Listener> {
        let mta = parse_upstreams(
            &env_str(
                "EMAIL8_GATE_MTA_UPSTREAMS",
                "email8:mta:smtp submission submissions",
            ),
            "email8:mta",
        );
        let access = parse_upstreams(
            &env_str(
                "EMAIL8_GATE_ACCESS_UPSTREAMS",
                "email8:access:imap imaps pop3 pop3s sieve",
            ),
            "email8:access",
        );
        // (name, env-suffix, default-port, lookup table)
        // (name, env-suffix, well-known port, upstream fallback port, owners)
        let table: &[(&str, &str, u16, u16, &HashMap<String, String>)] = &[
            ("smtp", "SMTP", 25, 2525, &mta),
            ("submission", "SUBMISSION", 587, 3587, &mta),
            ("submissions", "SUBMISSIONS", 465, 3465, &mta),
            ("imap", "IMAP", 143, 1143, &access),
            ("imaps", "IMAPS", 993, 1993, &access),
            ("pop3", "POP3", 110, 1110, &access),
            ("pop3s", "POP3S", 995, 1995, &access),
            ("sieve", "SIEVE", 4190, 4190, &access),
        ];
        table
            .iter()
            .filter_map(|(name, suffix, default_port, default_upstream, owners)| {
                let port =
                    env_u16_listener(&format!("EMAIL8_GATE_{suffix}_PORT"), *default_port)?;
                let upstream_port = env_u16_listener(
                    &format!("EMAIL8_GATE_{suffix}_UPSTREAM_PORT"),
                    *default_upstream,
                )
                .unwrap_or(*default_upstream);
                let upstream_service = owners
                    .get(*name)
                    .map(|s| Box::leak(s.clone().into_boxed_str()) as &str);
                Some(Listener {
                    name: leak(name),
                    port,
                    upstream_service: upstream_service.unwrap_or_else(|| leak("email8:mta")),
                    upstream_port,
                })
            })
            .collect()
    }
}

fn leak(s: &'static str) -> &'static str {
    s
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// `0`/empty → listener disabled (returns None); parse failure → None
/// with a warning surfaced by the caller via tracing.
fn env_u16_listener(key: &str, default: u16) -> Option<u16> {
    match std::env::var(key) {
        Ok(v) if v.trim().is_empty() || v.trim() == "0" => None,
        Ok(v) => v.trim().parse().ok(),
        Err(_) => Some(default),
    }
}

/// Gate runtime config.
#[derive(Debug, Clone)]
pub struct GateConfig {
    pub listeners: Vec<Listener>,
    /// Emit PROXY protocol v2 on forwarded streams (design §3.3).
    pub proxy_proto: bool,
    /// Per-listener concurrent connection cap.
    pub max_conns: usize,
    /// Upstream connect timeout (ms).
    pub connect_timeout_ms: u64,
    /// Registry read cache TTL (ms).
    pub registry_ttl_ms: u64,
    pub valkey_url: String,
}

impl GateConfig {
    pub fn from_env() -> Self {
        Self {
            listeners: Listener::from_env(),
            proxy_proto: std::env::var("EMAIL8_GATE_PROXY_PROTO")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            max_conns: std::env::var("EMAIL8_GATE_MAX_CONNS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2048),
            connect_timeout_ms: std::env::var("EMAIL8_GATE_CONNECT_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3_000),
            registry_ttl_ms: std::env::var("EMAIL8_GATE_REGISTRY_TTL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_000),
            valkey_url: std::env::var("VALKEY_URL")
                .or_else(|_| std::env::var("SENTIN8_VALKEY_URL"))
                .unwrap_or_else(|_| sentin8::config::Sentin8Config::default_valkey_url().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_csv_partitions_listeners() {
        // Upstream identities use the colon form (architecture-principles
        // .md §6.0); the CSV "email8:mta:smtp" prefix is listener parsing
        // syntax, not the identity.
        let mta = parse_upstreams("email8:mta:smtp submission,submissions", "email8:mta");
        assert_eq!(mta.get("smtp").unwrap(), "email8:mta");
        assert_eq!(mta.get("submission").unwrap(), "email8:mta");
        assert_eq!(mta.get("submissions").unwrap(), "email8:mta");
        let access =
            parse_upstreams("email8:access:imap imaps pop3 pop3s sieve", "email8:access");
        assert_eq!(access.get("sieve").unwrap(), "email8:access");
        assert!(mta.get("imap").is_none());
    }

    #[test]
    fn listener_table_env_semantics() {
        // Env is process-global — run both env-dependent checks in ONE
        // test so parallel execution cannot race the set/remove calls.
        for k in [
            "EMAIL8_GATE_SMTP_PORT",
            "EMAIL8_GATE_SUBMISSION_PORT",
            "EMAIL8_GATE_SUBMISSIONS_PORT",
            "EMAIL8_GATE_IMAP_PORT",
            "EMAIL8_GATE_IMAPS_PORT",
            "EMAIL8_GATE_POP3_PORT",
            "EMAIL8_GATE_POP3S_PORT",
            "EMAIL8_GATE_SIEVE_PORT",
        ] {
            std::env::remove_var(k);
        }
        // Defaults: all eight listeners present on the well-known ports.
        let listeners = Listener::from_env();
        let ports: Vec<u16> = listeners.iter().map(|l| l.port).collect();
        for p in [25u16, 587, 465, 143, 993, 110, 995, 4190] {
            assert!(ports.contains(&p), "missing default port {p}");
        }
        assert_eq!(listeners.len(), 8);
        for l in &listeners {
            assert!(
                l.upstream_service == "email8:mta" || l.upstream_service == "email8:access",
                "listener {} maps to {}",
                l.name,
                l.upstream_service
            );
        }
        // Empty env value disables that listener.
        std::env::set_var("EMAIL8_GATE_SIEVE_PORT", "");
        let listeners = Listener::from_env();
        assert_eq!(listeners.len(), 7);
        assert!(listeners.iter().all(|l| l.name != "sieve"));
        std::env::remove_var("EMAIL8_GATE_SIEVE_PORT");
    }
}
