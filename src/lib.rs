// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Email8:Gate — service library root.
//!
//! See `email8/design/sentin8-email8-gate-technical-design.md`.

pub mod admin;
pub mod config;
pub mod counters;
pub mod proxy_v2;
pub mod pump;
pub mod registry;
pub mod registration;
pub mod state;

/// Shared gate error type (thiserror).
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("no Active upstream for {service}")]
    NoUpstream { service: String },
    #[error("listener {port} disabled")]
    ListenerDisabled { port: u16 },
    #[error("registry: {0}")]
    Registry(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type GateResult<T> = Result<T, GateError>;