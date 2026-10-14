// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Valkey registry reader: Active-instance discovery for upstream
//! services (design §3.1).
//!
//! Reads the same `captain:svc:{service_type}` HASH captain maintains
//! (field = `{ip}:{port}`, value = JSON `ServiceInstance`). Read-only —
//! the gate never writes registry state. A 1 s TTL cache collapses the
//! per-connection read cost; failed connects evict the instance from
//! the in-memory set immediately (pump calls `evict`).

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Mirror of captain's `ServiceInstance` (only the fields the gate
/// needs; unknown fields are ignored via serde).
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryInstance {
    /// Hash field key `{ip}:{port}`.
    pub key: String,
    pub service_type: String,
    pub local_ip: String,
    pub local_port: u16,
    pub status: String,
    #[serde(default)]
    pub last_health_check: Option<i64>,
}

impl RegistryInstance {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.local_ip, self.local_port)
    }
}

// The local mirror alias keeps the field names aligned with captain.
use RegistryInstance as ServiceInstance;

/// One upstream's listener map: proto → (port, implicit_tls), plus the
/// instance key (`{ip}:{shell_port}`) it came from.
#[derive(Debug, Clone, Default)]
pub struct ListenerMap {
    pub ports: std::collections::HashMap<String, (u16, bool)>,
}

/// Cached Active set for one upstream service.
#[derive(Debug)]
struct ServiceSet {
    instances: Vec<ServiceInstance>,
    fetched_at: Instant,
    /// Round-robin cursor (atomic-ish via the RwLock write path).
    next: usize,
}

/// Registry client: one GLIDE client shared by all lookups (the
/// cert-identity factory presents the gate's `email8:gate` workload —
/// platform group DESIGN.md §3.1), with a per-service TTL cache.
#[derive(Clone)]
pub struct Registry {
    client: glide::GlideClient,
    ttl: Duration,
    cache: Arc<RwLock<HashMap<String, ServiceSet>>>,
}

impl Registry {
    /// Connect over the Valkey TLS plane, presenting the `email8:gate`
    /// workload certificate identity (CN→ACL user — group DESIGN.md
    /// §3.1; the user is provisioned by `vertical enroll` from the
    /// gate's `m2m_grants` declaration).
    ///
    /// # Errors
    /// Returns the factory's connect failure (TLS scheme gate, missing
    /// workload pair, unreachable plane).
    pub async fn connect(url: &str, ttl_ms: u64) -> Result<Self, sentin8::middleware::ValkeyError> {
        let client = sentin8::middleware::valkey_client(url, "email8:gate").await?;
        Ok(Self {
            client,
            ttl: Duration::from_millis(ttl_ms),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Active instances for `service_type` (fresh within TTL, sorted
    /// deterministically so round-robin is stable across refreshes).
    ///
    /// Mirrors captain's `list_active_for_type` freshness rule: status
    /// `Active` AND a health check within the last 30 s.
    pub async fn active_instances(&self, service_type: &str) -> Vec<ServiceInstance> {
        {
            let cache = self.cache.read().await;
            if let Some(set) = cache.get(service_type) {
                if set.fetched_at.elapsed() < self.ttl && !set.instances.is_empty() {
                    return set.instances.clone();
                }
            }
        }
        let fresh = self.fetch_active(service_type).await.unwrap_or_default();
        let mut cache = self.cache.write().await;
        let set = cache
            .entry(service_type.to_string())
            .or_insert_with(|| ServiceSet {
                instances: Vec::new(),
                fetched_at: Instant::now(),
                next: 0,
            });
        // Preserve stable ordering: sort by (ip, port) like captain does.
        let mut sorted = fresh;
        sorted.sort_by(|a, b| {
            a.local_ip
                .cmp(&b.local_ip)
                .then(a.local_port.cmp(&b.local_port))
        });
        // Keep the old set if the refresh came back empty (registry
        // blip) — better to route to a possibly-stale instance than to
        // refuse everything. Eviction on failed connect is the real
        // removal path.
        if !sorted.is_empty() {
            set.instances = sorted;
        }
        set.fetched_at = Instant::now();
        set.instances.clone()
    }

    /// Round-robin next instance for `service_type`. Returns
    /// `NoUpstream` when the Active set is empty.
    pub async fn next_instance(
        &self,
        service_type: &str,
    ) -> Result<ServiceInstance, crate::GateError> {
        let instances = self.active_instances(service_type).await;
        if instances.is_empty() {
            return Err(crate::GateError::NoUpstream {
                service: service_type.to_string(),
            });
        }
        let mut cache = self.cache.write().await;
        let set = cache
            .get_mut(service_type)
            .expect("cache entry populated above");
        // Defensive: the cached set may have been replaced concurrently.
        let len = set.instances.len().max(1);
        let idx = set.next % len;
        set.next = (set.next + 1) % usize::MAX;
        Ok(set.instances[idx.min(set.instances.len() - 1)].clone())
    }

    /// Evict a failed instance from the cache immediately (design §3.2:
    /// the next accept must not pick the same dead upstream).
    pub async fn evict(&self, service_type: &str, key: &str) {
        let mut cache = self.cache.write().await;
        if let Some(set) = cache.get_mut(service_type) {
            set.instances.retain(|i| i.key != key);
            set.fetched_at = Instant::now(); // force refresh on next miss
        }
    }

    /// The listener map published by the *first Active instance* of
    /// `service_type` (`captain:listeners:{svc}:{instance_key}` hash:
    /// field = proto, value = JSON `{port, implicit_tls}`). Empty map
    /// when nothing is published yet (gate then refuses — visible).
    pub async fn listener_map(&self, service_type: &str) -> ListenerMap {
        let instances = self.active_instances(service_type).await;
        let Some(inst) = instances.first() else {
            return ListenerMap::default();
        };
        let key = format!(
            "captain:listeners:{service_type}:{}:{}",
            inst.local_ip, inst.local_port
        );
        use glide::AsyncCommands as _;
        let entries: std::collections::HashMap<String, String> =
            self.client.hgetall(&key).await.unwrap_or_default();
        let mut ports = std::collections::HashMap::new();
        for (proto, json) in &entries {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
                if let (Some(p), t) = (
                    v.get("port").and_then(|x| x.as_u64()),
                    v.get("implicit_tls")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false),
                ) {
                    ports.insert(proto.clone(), (p as u16, t));
                }
            }
        }
        ListenerMap { ports }
    }

    async fn fetch_active(
        &self,
        service_type: &str,
    ) -> Result<Vec<ServiceInstance>, sentin8::middleware::ValkeyError> {
        let key = format!("captain:svc:{service_type}");
        use glide::AsyncCommands as _;
        let entries: std::collections::HashMap<String, String> =
            self.client.hgetall(&key).await.unwrap_or_default();
        let now = chrono::Utc::now().timestamp();
        let mut result = Vec::new();
        for json in entries.values() {
            if let Ok(inst) = serde_json::from_str::<ServiceInstance>(json) {
                if inst.status == "Active" {
                    if let Some(ts) = inst.last_health_check {
                        if now - ts < 30 {
                            result.push(inst);
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(ip: &str, port: u16, status: &str, health_age: i64) -> ServiceInstance {
        let now = chrono::Utc::now().timestamp();
        serde_json::from_str(
            &serde_json::json!({
                "key": format!("{ip}:{port}"),
                "service_type": "email8:mta",
                "local_ip": ip,
                "local_port": port,
                "pid": 1,
                "start_priority": 10,
                "cpu_avg_1m": 0.0,
                "memory_avg_1m": 0.0,
                "rss_mb_avg_1m": 0.0,
                "latency_avg_1m_ms": 0.0,
                "last_health_check": now - health_age,
                "status": status,
                "restarts": 0,
                "started_at": now,
                "version": "0.1.0"
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn parses_and_filters_active() {
        let active = inst("10.0.0.1", 8031, "Active", 5);
        let draining = inst("10.0.0.2", 8032, "Inactive", 1);
        let stale = inst("10.0.0.3", 8033, "Active", 120);
        // Filter logic mirror (fetch_active needs a live Valkey; unit-
        // test the predicate the same way captain's does).
        let is_active = |i: &ServiceInstance| {
            i.status == "Active"
                && i.last_health_check
                    .map(|ts| chrono::Utc::now().timestamp() - ts < 30)
                    .unwrap_or(false)
        };
        assert!(is_active(&active));
        assert!(!is_active(&draining));
        assert!(!is_active(&stale));
        assert_eq!(active.addr(), "10.0.0.1:8031");
    }
}
