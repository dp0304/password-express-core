// SPDX-License-Identifier: Apache-2.0
//! # aipass-sync-server — HTTP sync API and E2E relay mailbox (embeddable axum routers)
//!
//! Used by `aipass-node` (self-host) and the commercial cloud. Both routers carry full
//! paths, so the embedding application simply merges them:
//!
//! ```no_run
//! use std::sync::Arc;
//! use aipass_storage::LocalDirStore;
//! use aipass_sync_server::{relay, sync};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let blobs = Arc::new(LocalDirStore::open("/var/lib/aipass/blobs")?);
//! let admission = Arc::new(sync::EnrollTokenAdmission::new());
//! let sync_state = sync::SyncState::new(blobs, admission);
//! let relay_store = Arc::new(relay::SqliteRelayStore::open("/var/lib/aipass/relay.db")?);
//! let relay_state = relay::RelayState::builder(
//!         relay_store,
//!         Arc::new(relay::SyncDirectory::new(sync_state.clone())),
//!     )
//!     .nonce_cache(sync_state.nonce_cache())
//!     .build();
//! let _gc = relay::spawn_relay_gc(relay_state.clone(), std::time::Duration::from_secs(60));
//! let app = axum::Router::new()
//!     .merge(sync::sync_router(sync_state))
//!     .merge(relay::relay_router(relay_state));
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:7878").await?;
//! axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
//! # Ok(()) }
//! ```
//!
//! * [`sync`] — CONTRACTS §3.3 over any `aipass_storage::ObjectStore` blob backend, with
//!   pluggable [`sync::VaultAdmission`] and [`sync::QuotaPolicy`].
//! * [`relay`] — CONTRACTS §4 with [`relay::RelayStore`] (memory / SQLite),
//!   [`relay::RelayDirectory`] and [`relay::PushNotifier`].
//! * Errors use the §1.5 envelope ([`error::HttpError`]).
//!
//! The server never holds vault keys and never sees plaintext: it stores ciphertext,
//! signed metadata and sealed relay envelopes. It does see metadata (object counts, sizes,
//! timing, relay envelope headers) — see the [`relay`] module docs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod auth;
pub mod clock;
pub mod error;
pub mod ratelimit;
pub mod relay;
pub mod sync;

pub use clock::{Clock, ManualClock, SystemClock};
pub use error::HttpError;
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use relay::{RelayConfig, RelayState, relay_router, spawn_relay_gc};
pub use sync::{SyncConfig, SyncState, sync_router};

// Shared wire types of the sync API (defined once in aipass-storage).
pub use aipass_storage::http::{
    ListObjectsResponse, PutObjectResponse, VaultInfo, create_vault_body,
};
