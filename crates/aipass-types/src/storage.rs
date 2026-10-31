// SPDX-License-Identifier: Apache-2.0
//! Non-secret storage profile (CONTRACTS §3.1). Re-exported by `aipass-storage`.
//!
//! Storage secrets (access keys, passwords) never appear here: they live in the platform
//! secret store (referenced by `credential_ref`) and as a copy in a `storage_credential`
//! vault entry. A storage key is **never** automatically an AI resource (§10.2).

use serde::{Deserialize, Serialize};

use crate::time::{Timestamp, rfc3339_option};

/// Storage backend kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    /// Local directory.
    Local,
    /// Official ciphertext sync (cloud).
    Official,
    /// S3-compatible bucket.
    S3,
    /// WebDAV (V1.1, experimental).
    Webdav,
    /// Self-hosted `aipass-node` sync API.
    Selfhost,
}

/// Result of the capability test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageVerdict {
    /// Conditional create/update proven: usable for encrypted sync (UI: 加密同步可用).
    SyncCapable,
    /// Conditional writes not proven: backup only (UI: 仅可备份).
    BackupOnly,
}

/// Persisted, non-secret storage configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageProfile {
    /// Backend kind.
    pub kind: StorageKind,
    /// S3 / WebDAV endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// S3 region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// S3 bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    /// Key prefix (dedicated to AI Pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// S3 path-style addressing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_style: Option<bool>,
    /// Official / self-host sync base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// WebDAV username / S3 access key id (not secret by itself).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Reference into the platform secret store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Additive extension: directory for `kind: local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Last capability-test verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<StorageVerdict>,
    /// When it was tested.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub tested_at: Option<Timestamp>,
}

impl StorageProfile {
    /// A profile of `kind` with nothing else set.
    pub fn new(kind: StorageKind) -> Self {
        Self {
            kind,
            endpoint: None,
            region: None,
            bucket: None,
            prefix: None,
            path_style: None,
            base_url: None,
            username: None,
            credential_ref: None,
            path: None,
            verdict: None,
            tested_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_shape() {
        let p = StorageProfile {
            endpoint: Some("https://s3.example".into()),
            bucket: Some("b".into()),
            path_style: Some(true),
            verdict: Some(StorageVerdict::BackupOnly),
            ..StorageProfile::new(StorageKind::S3)
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind":"s3","endpoint":"https://s3.example","bucket":"b","path_style":true,"verdict":"backup_only"})
        );
        assert_eq!(serde_json::from_value::<StorageProfile>(v).unwrap(), p);
    }
}
