// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Gate counters (design §3.5).
//!
//! v1 keeps counters in-process, published through the shell's standard
//! error/traffic metrics channel (`sentin8-middleware::error_metrics`,
//! the same mechanism every shell service uses). A dedicated Stat
//! dashboard rides story 7.6.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

/// Monotonic counter names (design §3.5).
pub struct Counters {
    pub connections_total: AtomicU64,
    pub upstream_unavailable_total: AtomicU64,
    pub active_connections: AtomicU64,
    pub bytes_in_total: AtomicU64,
    pub bytes_out_total: AtomicU64,
}

pub static COUNTERS: LazyLock<Counters> = LazyLock::new(|| Counters {
    connections_total: AtomicU64::new(0),
    upstream_unavailable_total: AtomicU64::new(0),
    active_connections: AtomicU64::new(0),
    bytes_in_total: AtomicU64::new(0),
    bytes_out_total: AtomicU64::new(0),
});

/// Record one accepted+forwarded connection (entry: active gauge up).
pub fn record_connection(bytes_in: u64, bytes_out: u64) {
    COUNTERS.connections_total.fetch_add(1, Ordering::Relaxed);
    COUNTERS.active_connections.fetch_add(1, Ordering::Relaxed);
    COUNTERS.bytes_in_total.fetch_add(bytes_in, Ordering::Relaxed);
    COUNTERS.bytes_out_total.fetch_add(bytes_out, Ordering::Relaxed);
}

/// Pump exit: settle byte totals and drop the active gauge.
pub fn record_connection_bytes(bytes_in: u64, bytes_out: u64) {
    COUNTERS.active_connections.fetch_sub(1, Ordering::Relaxed);
    COUNTERS.bytes_in_total.fetch_add(bytes_in, Ordering::Relaxed);
    COUNTERS.bytes_out_total.fetch_add(bytes_out, Ordering::Relaxed);
}

/// Record a failed upstream selection/connect.
pub fn record_upstream_unavailable() {
    COUNTERS.upstream_unavailable_total.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot for the telemetry endpoint.
pub fn snapshot() -> serde_json::Value {
    serde_json::json!({
        "connections_total": COUNTERS.connections_total.load(Ordering::Relaxed),
        "upstream_unavailable_total": COUNTERS.upstream_unavailable_total.load(Ordering::Relaxed),
        "active_connections": COUNTERS.active_connections.load(Ordering::Relaxed),
        "bytes_in_total": COUNTERS.bytes_in_total.load(Ordering::Relaxed),
        "bytes_out_total": COUNTERS.bytes_out_total.load(Ordering::Relaxed),
    })
}