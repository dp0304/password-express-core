// SPDX-License-Identifier: Apache-2.0
//! # aipass-storage — object storage abstraction for encrypted vault sync
//!
//! The [`ObjectStore`] trait (CONTRACTS §3.1) is the only way the sync engine, vault core
//! and sync server touch storage. Storage only ever holds ciphertext, signed manifests and
//! member records; it is **not** a real-time authorization server (design doc §10.4).
//!
//! * [`MemoryStore`] — in-memory backend with exact conditional semantics (tests).
//! * [`capability_test`] — read / write / list / conditional create & update / delete /
//!   roundtrip probe that decides `sync_capable` vs `backup_only` (§10.1–§10.2, A15).
//! * [`LocalDirStore`] — encrypted files in a local directory (hard-link / `O_EXCL`
//!   create-only, lock-file guarded `If-Match`).
//! * [`S3Store`] — S3-compatible buckets (SigV4 in [`sigv4`], path-style or virtual-host,
//!   `If-None-Match: *` / `If-Match`, ListObjectsV2, static or session credentials).
//! * [`HttpSyncStore`] — the device-signed HTTP sync API (CONTRACTS §3.3) of the official
//!   service and self-hosted nodes.
//! * [`WebDavStore`] — **experimental (V1.1)** WebDAV backend; the capability test decides
//!   between sync and backup-only.
//! * [`PrefixedStore`] — namespaces any store under a key prefix.
//! * [`relay_client::RelayClient`] — client of the E2E relay mailbox (CONTRACTS §4).
//! * [`profile::open_store`] — build a backend from a non-secret [`StorageProfile`] plus
//!   secrets supplied separately.
//!
//! ETags are for concurrency control only — never a substitute for content signatures or
//! integrity checks (§10.3). Storage profiles and descriptions never contain secrets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod capability;
pub mod error;
pub mod http;
mod httputil;
pub mod local;
pub mod memory;
pub mod prefixed;
pub mod profile;
pub mod relay_client;
pub mod s3;
pub mod sigv4;
pub mod webdav;
mod xml;

pub use aipass_types::storage::{StorageKind, StorageProfile, StorageVerdict};
pub use capability::{CapabilityReport, capability_test};
pub use error::StorageError;
pub use http::HttpSyncStore;
pub use local::LocalDirStore;
pub use memory::MemoryStore;
pub use prefixed::PrefixedStore;
pub use relay_client::RelayClient;
pub use s3::{S3Config, S3Credentials, S3Store};
pub use webdav::{WebDavConfig, WebDavStore};

/// A stored object.
#[derive(Clone, PartialEq, Eq)]
pub struct Object {
    /// Content (ciphertext / signed JSON).
    pub bytes: Vec<u8>,
    /// Backend ETag (opaque; compare only for equality).
    pub etag: String,
}

impl core::fmt::Debug for Object {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Object")
            .field("len", &self.bytes.len())
            .field("etag", &self.etag)
            .finish()
    }
}

/// Listing entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Key relative to the store root.
    pub key: String,
    /// ETag.
    pub etag: String,
    /// Size in bytes.
    pub size: u64,
    /// Last modification, when the backend reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<DateTime<Utc>>,
}

/// Write precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutCondition {
    /// Unconditional write.
    None,
    /// Create only if the key does not exist (`If-None-Match: *`).
    IfAbsent,
    /// Replace only if the current ETag equals this value (`If-Match`).
    IfMatch(String),
}

/// Write result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutOutcome {
    /// Written; new ETag.
    Written {
        /// New ETag.
        etag: String,
    },
    /// The precondition did not hold; nothing was written.
    PreconditionFailed,
}

/// Non-secret description of a store: kind + endpoint, never credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDescription {
    /// `memory`, `local`, `s3`, `http`, `webdav`, …
    pub kind: String,
    /// Endpoint / path / base URL for display (no credentials, no signed query strings).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Extra non-secret detail (bucket, prefix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Object storage used for encrypted sync.
///
/// Semantics every backend must provide (and [`capability_test`] verifies):
/// * `get` of a missing key → `Ok(None)`;
/// * `put` with [`PutCondition::IfAbsent`] writes only when the key is absent, atomically;
///   [`PutCondition::IfMatch`] only when the current ETag matches (absent → precondition
///   failed); a failed precondition returns [`PutOutcome::PreconditionFailed`], not an error;
/// * `delete` is idempotent;
/// * `list` returns keys starting with `prefix`, strictly after `start_after`, in
///   lexicographic (byte) order, at most `limit` entries.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Read an object.
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError>;
    /// Write an object under a condition.
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError>;
    /// Delete an object (idempotent).
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    /// List objects lexicographically.
    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError>;
    /// Kind + endpoint, never secrets.
    fn describe(&self) -> StorageDescription;
}

/// Page size used by [`list_all`].
pub const LIST_PAGE: usize = 1000;

/// List every object under `prefix`, following pagination.
pub async fn list_all(
    store: &dyn ObjectStore,
    prefix: &str,
) -> Result<Vec<ObjectMeta>, StorageError> {
    let mut out: Vec<ObjectMeta> = Vec::new();
    loop {
        let after = out.last().map(|m| m.key.clone());
        let page = store.list(prefix, after.as_deref(), LIST_PAGE).await?;
        let n = page.len();
        if let (Some(last_prev), Some(first)) = (after.as_deref(), page.first()) {
            // guard against backends that ignore start_after (would loop forever)
            if first.key.as_str() <= last_prev {
                return Err(StorageError::Backend {
                    status: None,
                    message: "listing did not advance".into(),
                });
            }
        }
        out.extend(page);
        if n < LIST_PAGE {
            return Ok(out);
        }
    }
}

/// ETag used by content-addressed backends: b64u(SHA-256(bytes)).
pub fn etag_for(bytes: &[u8]) -> String {
    aipass_crypto::sha256_b64u(bytes)
}

/// Reject keys that are not valid vault object keys (path traversal, odd characters).
pub fn validate_key(key: &str) -> Result<(), StorageError> {
    if aipass_types::vault::keys::is_valid(key) {
        Ok(())
    } else {
        Err(StorageError::InvalidKey)
    }
}

/// Validate a listing prefix: empty, or a key prefix made of `[A-Za-z0-9._-]` segments
/// separated by `/` (the last segment may be partial or empty, e.g. `"entries/"` or
/// `"manifests/0000"`). No leading `/`, no empty inner segments, no `.` / `..` segments.
pub fn validate_prefix(prefix: &str) -> Result<(), StorageError> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.len() > aipass_types::vault::keys::MAX_KEY_LEN {
        return Err(StorageError::InvalidKey);
    }
    let segs: Vec<&str> = prefix.split('/').collect();
    let last = segs.len() - 1;
    for (i, seg) in segs.iter().enumerate() {
        let charset_ok = seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !charset_ok {
            return Err(StorageError::InvalidKey);
        }
        if i < last && (seg.is_empty() || *seg == "." || *seg == "..") {
            return Err(StorageError::InvalidKey);
        }
        if i == last && *seg == ".." {
            return Err(StorageError::InvalidKey);
        }
    }
    Ok(())
}

/// Normalize a store-level key prefix (e.g. an S3 `prefix` setting): `""` stays empty,
/// otherwise the result is validated and ends with exactly one `/`.
pub fn normalize_root_prefix(prefix: &str) -> Result<String, StorageError> {
    let p = prefix.trim_matches('/');
    if p.is_empty() {
        return Ok(String::new());
    }
    validate_key(p)?;
    Ok(format!("{p}/"))
}
