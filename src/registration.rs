// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Email8:Gate.
//!
//! Output via `--print-registration` flag. The gate is
//! infrastructure-only for DOMAIN tables (no error codes; the typed
//! `email8:gate:telemetry:read` scope gates the RFW telemetry page,
//! story 7.6) — but it carries the platform-standard producer tables:
//! the `gate.audit_journal` leaf-schema table (AUDJOUR-1, migration v2)
//! that the shell's boot-8c pusher drains to Sys's audit ingest API.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, M2mGrant, PgRole, PolicySetDecl, Registration, RelationDecl,
    SqlMigration,
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
/// AUDJOUR-1: the local audit journal DDL (sql/audit.sql) — the gate's
/// first SQL migration. The `gate` leaf schema is created by the file
/// itself (it holds nothing else today).
const SQL_1_AUDIT: &str = include_str!("../sql/audit.sql");

const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "email8:gate",
        scopes: &[],
    },
    M2mGrant {
        // Shield hot-reload consumer (BUSPOLICY-1 — see email8-access).
        workload: "email8:gate-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        // Audit-journal pusher's sys-ingest scope (AUDJOUR-1): the shell's
        // boot-8c pusher presents the `gate-audit` certificate to Sys
        // `POST /v1/audit` — this grant row is what makes the workload
        // enrollable (the BUSPOLICY-1 class: an undeclared cert mints but
        // can never be authorized).
        workload: "gate-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
];

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
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:gate:telemetry:read",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "email8:gate:admin",
        scope: "email8:gate:policy:read",
    },
    AdminScope::Typed {
        role: "email8:gate:admin",
        scope: "email8:gate:policy:write",
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[AdminUiPage {
    route: "gate",
    label: "Gate",
    ui_endpoint: "/v1/admin/ui/gate",
    data_endpoint: "/v1/admin/gate",
    icon: "0xe30a", // Material Icons "settings_ethernet" — network passthrough
}];

fn openapi_spec() -> serde_json::Value {
    // Portable stub when #[path]-included from tests (POLICY-7).
    #[cfg(not(test))]
    {
        serde_json::to_value(crate::registration::GateOpenApi::openapi())
            .unwrap_or(serde_json::Value::Null)
    }
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
        sql_migrations: vec![SqlMigration {
            // AUDJOUR-1 migration v2: the local audit journal in the
            // `gate` leaf schema — the 15-column contract of
            // `sentin8_audit::audit_journal_sql` (design/sentin8-audit-
            // journal-provisioning-design.md §2.1). v2 (not v1) keeps the
            // never-reuse invariant — v1 never existed for gate, but the
            // version ladder starts where the platform's
            // `vertical_migrations` table will never collide.
            version: 2,
            name: "audit",
            sql: SQL_1_AUDIT,
        }],
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

/// Spec wrappers for the gate's two inline closures (health + telemetry —
/// OAPEC §2; the closures aren't named fns in `main.rs`).
pub mod spec_helpers {
    /// Spec wrapper for the inline `/v1/health` closure.
    #[utoipa::path(
        get,
        path = "/v1/health",
        responses(
            (status = 200, description = "Service is healthy", body = serde_json::Value),
        ),
        security(),
        tag = "email8-gate",
    )]
    #[allow(dead_code)]
    pub async fn gate_health_spec() {}

    /// Spec wrapper for the inline `/v1/gate/telemetry` closure.
    #[utoipa::path(
        get,
        path = "/v1/gate/telemetry",
        responses(
            (status = 200, description = "Telemetry snapshot", body = serde_json::Value),
        ),
        security(),
        tag = "email8-gate",
    )]
    #[allow(dead_code)]
    pub async fn gate_telemetry_spec() {}
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Email8:Gate",
        description = "Raw-TCP passthrough telemetry/health surface"
    ),
    paths(
        crate::admin::get_admin_ui,
        crate::admin::admin_data,
        spec_helpers::gate_health_spec,
        spec_helpers::gate_telemetry_spec,
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_test_set,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_delete_attribute,
    ),
    components(schemas(
        sentin8::shield::admin::PutPolicySetBody,
        sentin8::shield::admin::TestPolicySetBody,
        sentin8::shield::admin::PolicyModeBody,
        sentin8::shield::admin::PutRelationBody,
        sentin8::shield::admin::DeleteRelationQuery,
        sentin8::shield::admin::RelationCheckQuery,
        sentin8::shield::admin::PutAttributeBody,
        sentin8::shield::admin::ListAttributesQuery,
        sentin8::shield::admin::DeleteAttributeQuery,
    )),
    security(),
    tags(
        (name = "email8-gate", description = "Sentin8 Email8:Gate — the mail-protocol ingress (IMAP/POP3/SMTP/DAV proxy)"),
        (name = "admin-ui", description = "RFW telemetry admin UI"),
        (name = "policy", description = "Shield policy admin (shared annotated wrappers)"),
    ),
)]
pub struct GateOpenApi;
