// SPDX-License-Identifier: Apache-2.0
//! # aipass-sync — client sync engine and vault facade
//!
//! Responsibilities (CONTRACTS §3.2, §12; design doc §10.3–§10.6, A11–A14):
//!
//! * [`engine::SyncEngine`] — pull (signature chain, `prev_hash`, author membership,
//!   checkpoint rollback detection, tombstones), create-only commit with rebase loop;
//! * [`merge`] — per-field 3-way merge; secret-bearing conflicts pause automatic use
//!   (`conflict_versions` non-empty → `SYNC_CONFLICT`); notes concatenated;
//! * [`outbox`] — encrypted local outbox for offline edits;
//! * [`planners`] — outbox application, member add / revoke + key rotation, recovery key
//!   replacement, conflict resolution;
//! * [`client::VaultClient`] — the facade for CLI, desktop and FFI: create / unlock / lock,
//!   items (masked), reveal, save, delete, generate, TOTP, import / export, sync,
//!   conflicts, devices / revoke, recovery verification and kit, storage test + migration,
//!   autofill, approvals and pairing. A UI never needs raw VMK access.
//!
//! Storage access goes exclusively through `aipass_storage::ObjectStore`; the local cache
//! ([`cache::FileStore`]) holds only verified ciphertext.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cache;
pub mod client;
mod client_ops;
pub mod engine;
pub mod factory;
pub mod merge;
pub mod models;
pub mod outbox;
pub mod planners;

pub use aipass_vault::{Result, VaultError};
pub use client::{
    ClientConfig, DeviceFile, MemoryStoreFactory, StateFile, StoreContext, StoreFactory,
    VaultClient,
};
pub use client_ops::executor_principal;
pub use engine::{CommitOutcome, CommitPlanner, PlanContext, PullStats, SyncEngine};
pub use factory::StandardStoreFactory;
pub use models::*;
