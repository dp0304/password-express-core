// SPDX-License-Identifier: Apache-2.0
//! # aipass-broker — Access Broker
//!
//! The component that decides whether an AI connection may do something, and records
//! what happened (CONTRACTS §6, §7; design doc §8, §9.2, §12.3):
//!
//! * [`Broker`] backed by SQLite (`<data>/broker.db`, WAL, migrations): AppConnections and
//!   pairing, projects, resources (no secrets), device-signed policies, approval requests,
//!   grants, operations, leases, the hash-chained audit log, trusted approver devices,
//!   throttles and the persisted `AIPass-Sig` nonce cache;
//! * the operation state machine with idempotency, grant matching, rule auto-approval
//!   (test + read-only only), throttling after denial, approval TTLs (never approves on
//!   timeout), executor / control-channel checks, atomic cumulative budgets, output caps,
//!   unknown-outcome handling and cancellation;
//! * signed approval decisions (digest + Ed25519 via `aipass_types::approval`), credential
//!   envelope installation through [`aipass_types::exec::ExecutorBackend`], automatic
//!   resumption of the waiting operation;
//! * three-level revocation with an honest [`aipass_types::models::RevocationReport`];
//! * hooks: [`ApprovalNotifier`] (in-process UI), [`DeviceOutbox`] (sealed relay
//!   envelopes to trusted devices), [`CredentialSource`] (desktop trusted client), and
//!   [`Broker::handle_device_message`] for inbound device messages;
//! * [`http::router`] exposing every CONTRACTS §6.3 endpoint with auth classes C/D/A/P,
//!   plus [`http::serve_uds`] (0600 socket) and [`http::serve_tcp`].
//!
//! The broker executes exclusively through the `ExecutorBackend` trait, so it never
//! depends on connector crates and never sees credentials. Never blocks waiting for a
//! phone; never approves on timeout; IDs are never capabilities.
//!
//! Status: not yet independently security-audited.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod audit;
mod broker;
pub mod clock;
pub mod config;
mod db;
mod error;
mod handle;
pub mod http;
pub mod notify;
pub mod principal;
mod ratelimit;
mod redact;
mod store;
mod summary;
pub mod types;

pub use audit::MAX_AUDIT_PAGE;
pub use broker::{BackgroundTask, Broker};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::BrokerConfig;
pub use error::OpenError;
pub use handle::ConnectionHandle;
pub use http::{BrokerState, UdsOptions, router, serve_tcp, serve_uds};
pub use notify::{ApprovalNotifier, BrokerEvent, CredentialSource, DeviceOutbox, RelayIdentity};
pub use principal::{Actor, AuthVia, ConnectionPrincipal, VerifiedPrincipal};
pub use types::*;

/// Throttle window after a denial, in seconds.
pub const DENIAL_THROTTLE_SECS: i64 = broker::DENIAL_THROTTLE_SECS_PUB;
/// Pending approvals per connection above which new requests are `RATE_LIMITED`.
pub const MAX_PENDING_APPROVALS_PER_CONNECTION: u64 = broker::MAX_PENDING_PUB;
