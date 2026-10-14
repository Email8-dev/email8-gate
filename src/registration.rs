// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Email8:Gate.
//!
//! Output via `--print-registration` flag. The gate is
//! infrastructure-only: no PG role, no SQL migrations, no error codes;
//! the typed `email8:gate:telemetry:read` scope gates the RFW
//! telemetry page (listener/upstream/counter view, story 7.6).

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, M2mGrant, PgRole, Registration, PolicySetDecl, RelationDecl,
};
use utoipa::OpenApi;


/// The Shield text of the declared scope-mirror set — public so the
/// policy wiring tests (POLICY-7) assert against the REAL seed.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"email8:gate:telemetry:read\", resource) when { principal.scopes.contains(\"email8:gate:telemetry:read\") };
permit(principal, action == Action::\"email8:gate:telemetry:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:gate:telemetry:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:gate:telemetry:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set — the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Enforced (decision 2026-09-07): step 5 is the
/// only gate; shadow is the emergency one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for email8:gate over the LIVE effective scope set (policy design §3.1d). Enforced (decision 2026-09-07) — step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) — none declared by this
/// service today.
const RELATIONS: &[RelationDecl] = &[];

/// M2M workload declarations (CERTFREE-4V): the `email8:gate` workload
/// row drives `vertical enroll`'s Valkey ACL-user provisioning — the
/// certificate CN `m2m-email8:gate` maps to the ACL user of the same
/// name (group DESIGN.md §3.1), without which the gate's GLIDE
/// registry reads can never connect. No cross-service scopes are
/// needed (the gate makes no M2M HTTP calls; the row exists for the
/// Valkey identity).
const M2M_GRANTS: &[M2mGrant] = &[M2mGrant {
    workload: "email8:gate",
    scopes: &[],
}, M2mGrant {
    // Shield hot-reload consumer (BUSPOLICY-1 — see email8-access).
    workload: "email8:gate-policy",
    scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
}];

/// The gate's PostgreSQL role (group DESIGN.md §3.2): the shell boot's
/// step-6 pool + the policy-admin surface (ServiceCore.admin) run
/// against the vertical's database under this role — NOBYPASSRLS,
/// certificate identity, no password.
const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "email8:gate:telemetry:read",
    role: "email8_gate_service",
    bypass_rls: false,
    database: "email8",
    cross_schema_grants: &[],
}];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed { role: "email8:admin", scope: "email8:gate:telemetry:read" },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed { role: "email8:gate:admin", scope: "email8:gate:policy:read" },
    AdminScope::Typed { role: "email8:gate:admin", scope: "email8:gate:policy:write" },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "gate",
        label: "Gate",
        ui_endpoint: "/v1/admin/ui/gate",
        data_endpoint: "/v1/admin/gate",
        icon: "0xe30a", // Material Icons "settings_ethernet" — network passthrough
    },
];

fn openapi_spec() -> serde_json::Value {

    // Portable stub when #[path]-included from tests (POLICY-7).
    #[cfg(not(test))]
    { return serde_json::to_value(crate::registration::GateOpenApi::openapi())
        .unwrap_or(serde_json::Value::Null); }
    #[cfg(test)]
    return serde_json::Value::Null;
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "email8:gate",
        subdomain: "email8-gate",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Gate",
            icon: "0xe30a",
            service_flag: "email8",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        // The shell's step-6 DB pool (ServiceCore.admin backs the policy
        // admin surface) requires the service's own role — same as every
        // shell service (group DESIGN.md §3.2; the DSNDERIVE-1 derived DSN
        // names `email8_gate_service`).
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}

#[derive(OpenApi)]
#[openapi(info(title = "Email8:Gate", description = "Raw-TCP passthrough telemetry/health surface"))]
pub struct GateOpenApi;