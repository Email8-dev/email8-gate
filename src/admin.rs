// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Email8:Gate admin — RFW telemetry page (listener/upstream/counter
//! view) + data endpoint. Scope-gated: `email8:gate:telemetry:read`
//! (gate design §3.5, story 7.6).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;

use crate::state::GateState;

/// `GET /v1/admin/ui/gate` — RFW definition of the telemetry page.
pub async fn get_admin_ui(
    State(state): State<std::sync::Arc<GateState>>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth = sentin8::auth::client::verify_bearer_token(&state.auth_client, &headers)
        .await?;
    // Step-5 policy decision (Phase 28 §4.3): the scope-mirror carries
    // the telemetry scope + platform-admin permits.
    sentin8::shell::policy::require(
        &state.engine,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("email8:gate:telemetry:read"),
    )
    .await?;

    if page != "gate" {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Unknown admin UI page: {page}"),
        ));
    }
    let def = AdminPage::new("Gate Telemetry")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Listener".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "port".into(),
                    label: "Well-known port".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "upstream".into(),
                    label: "Upstream service".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "upstream_port".into(),
                    label: "Upstream raw port".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/listeners".into(),
            sortable: true,
            filterable: false,
            page_size: 50,
            empty_message: Some("No listeners enabled".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "metric".into(),
                    label: "Metric".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "value".into(),
                    label: "Value".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/counters".into(),
            sortable: false,
            filterable: false,
            page_size: 10,
            empty_message: Some("No counters".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build();
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `POST /v1/admin/gate` — page data: counters + listener table split by
/// the sub-endpoint path the RFW widgets post to.
pub async fn admin_data(
    State(state): State<std::sync::Arc<GateState>>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth = sentin8::auth::client::verify_bearer_token(&state.auth_client, &headers)
        .await?;
    // Step-5 policy decision (Phase 28 §4.3) — telemetry governs.
    sentin8::shell::policy::require(
        &state.engine,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("email8:gate:telemetry:read"),
    )
    .await?;

    if page != "gate" {
        return Err((StatusCode::NOT_FOUND, format!("Unknown admin page: {page}")));
    }
    // RFW data endpoints are keyed by page path; the page's widgets post
    // /v1/admin/gate/listeners and /v1/admin/gate/counters.
    if let Some(rest) = page_tail(&page) {
        return match rest {
            "listeners" => Ok(Json(serde_json::json!(state
                .config
                .listeners
                .iter()
                .map(|l| serde_json::json!({
                    "name": l.name,
                    "port": l.port,
                    "upstream": l.upstream_service,
                    "upstream_port": l.upstream_port,
                }))
                .collect::<Vec<_>>()))),
            "counters" => {
                let snap = crate::counters::snapshot();
                let rows = serde_json::json!(snap
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .map(|(k, v)| serde_json::json!({"metric": k, "value": v}))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default());
                Ok(Json(rows))
            }
            _ => Err((
                StatusCode::NOT_FOUND,
                format!("Unknown data endpoint: {rest}"),
            )),
        };
    }
    Err((StatusCode::BAD_REQUEST, "Missing data sub-endpoint".into()))
}

/// The sub-endpoint after the page route (`gate/listeners` → `listeners`).
fn page_tail(page: &str) -> Option<&str> {
    let mut parts = page.splitn(2, '/');
    let first = parts.next()?;
    if first != "gate" {
        return None;
    }
    parts.next()
}

/// Shared policy-admin surface accessor (Phase 28 §3.6): the boot
/// loaded the engine into `GateState::engine` and stashed the shell's
/// shared admin surface alongside it; the shared handlers extract it
/// via `HasPolicyAdmin` so the admin surface and the request path
/// evaluate the SAME cache. (Impl lives in the lib — `GateState` is
/// lib-owned and the bin crate cannot impl a foreign trait on it.)
impl sentin8::shield::admin::HasPolicyAdmin for GateState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
