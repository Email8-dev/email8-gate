// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Gate runtime state — shared by the bin routes and the RFW admin
//! module (story 7.6). Clone is required by axum Router<S>.

use std::sync::Arc;
use tokio::sync::watch;

#[derive(Clone)]
pub struct GateState {
    pub config: Arc<crate::config::GateConfig>,
    pub registry: crate::registry::Registry,
    pub shutdown: watch::Sender<bool>,
    /// Auth client for the RFW telemetry page token verification.
    pub auth_client: sentin8::auth::client::Client,
    /// The service policy engine (step-5 gate; Phase 28). The gate
    /// carries no DB pool — the engine is a fresh in-memory cache that
    /// hot-reloads from the Bus (policy design §3.5).
    pub engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    /// The shared policy-admin surface built by the shell boot (the
    /// SAME engine instance this state's `engine` holds).
    pub admin: sentin8::shield::admin::SharedAdminState,
}
