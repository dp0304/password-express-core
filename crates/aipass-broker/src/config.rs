// SPDX-License-Identifier: Apache-2.0
//! Broker configuration.

use std::path::PathBuf;
use std::time::Duration;

use aipass_types::models::Limits;

/// File name of the SQLite database inside the data directory (CONTRACTS §6).
pub const DB_FILE: &str = "broker.db";
/// File name of the local admin bearer token inside the data directory (CONTRACTS §6.3, 0600).
pub const ADMIN_TOKEN_FILE: &str = "admin.token";
/// Prefix of the local admin token (stored on disk only in `admin.token`, in memory only as a hash).
pub const ADMIN_TOKEN_PREFIX: &str = "aipadm_";

/// Configuration of a [`crate::Broker`].
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Data directory (`broker.db`, `admin.token`). `None` = in-memory database, no admin
    /// token file (tests and ephemeral embedding).
    pub data_dir: Option<PathBuf>,
    /// Version string reported by `GET /v1/health`.
    pub version: String,
    /// Enable V1.1 experimental features (`/credentials/delegate`, `v1.1` operations).
    pub experimental: bool,
    /// Limits proposed in operation-triggered approval requests and used for access
    /// requests that do not specify limits. Defaults to CONTRACTS §6.1 (1000/5000/20/262144).
    pub default_limits: Limits,
    /// Hard upper bound for limits an AI connection may *request*.
    pub max_limits: Limits,
    /// Broker-side safety timeout for one `ExecutorBackend::execute` call.
    pub operation_timeout: Duration,
    /// How long `submit_decision` waits for the resumed operation before answering
    /// (the operation keeps running in the background either way).
    pub decision_wait: Duration,
    /// How long `cancel_operation` waits for a running operation to stop.
    pub cancel_wait: Duration,
    /// Upper bound for each executor call made during revocation (`cancel`,
    /// `end_sessions`, `revoke_upstream`); a slower executor is reported as `pending`.
    pub revoke_step_timeout: Duration,
    /// Grace period after cancelling a running execution before its future is dropped.
    pub cancel_grace: Duration,
    /// Operation results are kept for this long (so `operations.status` can return them),
    /// then purged from the database. Audit never stores results.
    pub result_retention: Duration,
    /// Interval of the background expiry sweeper.
    pub sweep_interval: Duration,
    /// Validity of a connection pairing request.
    pub pairing_ttl: Duration,
    /// Maximum simultaneously pending connection pairings (flood protection for `P`).
    pub max_pending_pairings: u32,
    /// Maximum simultaneously pending pairings from one peer (IP, or the local socket):
    /// one client can neither take every slot nor flood the devices with prompts.
    pub max_pending_pairings_per_peer: u32,
    /// Maximum concurrently executing operations per executor; excess operations wait in
    /// the `authorized` state (the queue that `stop_access` rejects).
    pub executor_concurrency: usize,
    /// Maximum queued + running operations per connection.
    pub max_inflight_per_connection: usize,
    /// Maximum HTTP request body.
    pub max_body_bytes: usize,
    /// Requests per minute per peer on public (`P`) endpoints.
    pub public_rate_per_minute: u32,
    /// Maximum nonces remembered by the replay cache before failing closed.
    pub max_nonces: u64,
    /// Maximum live nonces per signing key: one principal can neither fill the global
    /// replay cache nor flood the database (`RATE_LIMITED` for that key only).
    pub max_nonces_per_kid: u64,
}

impl BrokerConfig {
    /// Persistent broker in `data_dir`.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: Some(data_dir.into()),
            ..Self::in_memory()
        }
    }

    /// In-memory broker (no files).
    pub fn in_memory() -> Self {
        Self {
            data_dir: None,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            experimental: false,
            default_limits: Limits::default(),
            max_limits: Limits {
                max_rows_per_operation: 10_000,
                max_rows_per_grant: 100_000,
                max_requests_per_grant: 1_000,
                max_result_bytes: 4 * 1024 * 1024,
            },
            operation_timeout: Duration::from_secs(60),
            decision_wait: Duration::from_secs(30),
            cancel_wait: Duration::from_secs(3),
            revoke_step_timeout: Duration::from_millis(1500),
            cancel_grace: Duration::from_millis(1500),
            result_retention: Duration::from_secs(3600),
            sweep_interval: Duration::from_secs(1),
            pairing_ttl: Duration::from_secs(600),
            max_pending_pairings: 10,
            max_pending_pairings_per_peer: 3,
            executor_concurrency: 8,
            max_inflight_per_connection: 16,
            max_body_bytes: 1024 * 1024,
            public_rate_per_minute: 30,
            max_nonces: 1_000_000,
            max_nonces_per_kid: 20_000,
        }
    }

    /// `<data>/broker.db`.
    pub fn db_path(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|d| d.join(DB_FILE))
    }

    /// `<data>/admin.token`.
    pub fn admin_token_path(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|d| d.join(ADMIN_TOKEN_FILE))
    }
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self::in_memory()
    }
}
