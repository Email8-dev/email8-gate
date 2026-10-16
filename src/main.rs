// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Email8:Gate — raw-TCP passthrough for the well-known mail
//! protocol ports (25/587/465/143/993/110/995/4190).
//!
//! See `email8/design/sentin8-email8-gate-technical-design.md`.
//!
//! Boot: registration flag → PQ provider → dotenv → shell serve() with
//! a gate state builder (config + Valkey registry + raw listeners in
//! the background, shutdown-watch drained) → HTTPS health/telemetry.
//! No DB writes, no events, no domain logic (design §7).

use email8_gate_server::state::GateState;
use email8_gate_server::{config, counters, registry};
use std::sync::Arc;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(build_shell()).await
}

mod registration {
    //! Thin bin-side wrapper: re-exports the lib registration printer and
    //! hosts the OpenApi derive the shell builder needs.
    use sentin8::registration::AdminScope;
    use utoipa::OpenApi;

    pub use email8_gate_server::registration::print;

    const ADMIN_SCOPES: &[AdminScope] = &[AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:gate:telemetry:read",
    }];

    #[derive(OpenApi)]
    #[openapi(info(
        title = "Email8:Gate",
        description = "Raw-TCP passthrough telemetry/health surface"
    ))]
    pub struct GateOpenApi;

    #[allow(dead_code)]
    pub fn openapi_spec() -> serde_json::Value {
        serde_json::to_value(GateOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
    }

    #[allow(dead_code)]
    pub fn admin_scopes() -> &'static [AdminScope] {
        ADMIN_SCOPES
    }
}

fn build_shell() -> sentin8::shell::Sentin8Shell<Arc<GateState>> {
    sentin8::shell::Sentin8Shell::new("email8:gate", "EMAIL8_GATE")
        .with_registration(registration::print)
        .with_state(|core| async move {
            // 2. PQ crypto provider before any TLS use (platform pattern —
            //    serve() installs dotenvy itself at step 3).
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
            bootstrap(core).await
        })
        // with_own_health suppresses the shell's health mount — the gate
        // provides its own /v1/health inside gate_routes (plus telemetry).
        .with_own_health()
        .with_router(gate_routes)
        .with_openapi(<registration::GateOpenApi as utoipa::OpenApi>::openapi())
}

/// Bootstrap the gate state: config, Valkey registry, raw listeners in
/// the background. Returns the lib-owned GateState (story 7.6 unified
/// the type into the lib so the RFW admin module can use it).
async fn bootstrap(core: sentin8::shell::ServiceCore) -> anyhow::Result<Arc<GateState>> {
    let config = Arc::new(config::GateConfig::from_env());
    if config.listeners.is_empty() {
        anyhow::bail!("email8-gate: no listeners enabled (all EMAIL8_GATE_*_PORT empty?)");
    }
    let registry = registry::Registry::connect(&config.valkey_url, config.registry_ttl_ms)
        .await
        .map_err(|e| anyhow::anyhow!("email8-gate: registry connect failed: {e}"))?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let n_listeners = config.listeners.len();
    let listeners = config.listeners.clone();
    for l in listeners {
        let cfg = config.clone();
        let reg = registry.clone();
        let rx = shutdown_rx.clone();
        let name = l.name;
        tokio::spawn(async move {
            if let Err(e) = email8_gate_server::pump::serve_listener(l, cfg, reg, rx).await {
                tracing::error!(listener = name, error = %e, "email8:gate: listener failed");
            }
        });
    }
    tracing::info!(
        listeners = n_listeners,
        "email8:gate: raw listeners started"
    );
    // Auth client for the RFW telemetry page (scope-gated).
    let auth_client = sentin8::auth::client::Client::new(sentin8::auth::client::ClientOptions {
        base_url: std::env::var("SENTIN8_AUTH_ISSUER")
            .unwrap_or_else(|_| "https://auth.ops.sys.sentin8.local".to_string()),
        ..Default::default()
    });
    // Sentin8:Policy engine (Phase 28, §4.2b — shell-owned boot): the
    // engine arrived booted in `core.admin.policy` (load + shared deps +
    // hot-reload + stat emitter). Gate only consumes the Arc.
    let engine = core.admin.policy.clone();

    Ok(Arc::new(GateState {
        config,
        registry,
        shutdown: shutdown_tx,
        auth_client,
        engine,
        admin: core.admin,
    }))
}

fn gate_routes(
    router: axum::Router<Arc<GateState>>,
    _state: Arc<GateState>,
) -> axum::Router<Arc<GateState>> {
    use axum::routing::{get, post};
    router
        // Own health (captain probes this; `with_own_health` suppressed
        // the shell's default mount).
        .route(
            "/v1/health",
            // Carries the binary's build identity (`version`/`build`,
            // BUILDID-1) so captain's monitor populates `make status`'s
            // VERSION column — the consuming BINARY's identity, never a
            // shared crate's.
            get(|| async {
                axum::Json(serde_json::json!({
                    "service": "email8:gate",
                    "status": "ok",
                    "version": sentin8::build_info::id(),
                    "build": sentin8::build_info::build_hash(),
                }))
            }),
        )
        // Lightweight unauthenticated telemetry snapshot (ops probing).
        .route(
            "/v1/gate/telemetry",
            get(|| async {
                axum::Json(serde_json::json!({
                    "counters": counters::snapshot(),
                }))
            }),
        )
        // RFW telemetry page + its data endpoints (story 7.6,
        // scope-gated by email8:gate:telemetry:read).
        .route(
            "/v1/admin/ui/{page}",
            get(email8_gate_server::admin::get_admin_ui),
        )
        .route(
            "/v1/admin/{page}",
            post(email8_gate_server::admin::admin_data),
        )
        // ── Sentin8:Policy admin API (Phase 28 §3.6 — shared
        // implementation; handlers generic over this state via
        // HasPolicyAdmin).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<Arc<GateState>>)
                .put(sentin8::shield::admin::put_policy_set::<Arc<GateState>>)
                .delete(sentin8::shield::admin::delete_policy_set::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<Arc<GateState>>)
                .put(sentin8::shield::admin::put_relation::<Arc<GateState>>)
                .delete(sentin8::shield::admin::delete_relation::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<Arc<GateState>>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<Arc<GateState>>)
                .put(sentin8::shield::admin::put_attribute::<Arc<GateState>>)
                .delete(sentin8::shield::admin::delete_attribute::<Arc<GateState>>),
        )
}
