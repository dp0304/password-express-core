// SPDX-License-Identifier: Apache-2.0
//! Storage quota hook for the sync API. The node uses [`StaticQuota`] (or none); the cloud
//! plugs its per-account quota (`QUOTA_EXCEEDED`).

use aipass_types::ids::{PrincipalId, VaultId};
use aipass_types::{ApiError, ErrorCode};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Current usage of one vault namespace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultUsage {
    /// Objects stored.
    pub object_count: u64,
    /// Bytes stored.
    pub bytes_used: u64,
}

/// One pending write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteDelta {
    /// Bytes of the new object.
    pub added_bytes: u64,
    /// Bytes of the object it replaces (0 for a new object).
    pub removed_bytes: u64,
    /// Whether this creates a new object.
    pub new_object: bool,
}

/// Quota policy.
#[async_trait]
pub trait QuotaPolicy: Send + Sync {
    /// Quota shown in `GET /v1/vaults/{id}` (`None` = unlimited).
    async fn quota_bytes(&self, vault_id: &VaultId) -> Result<Option<u64>, ApiError>;
    /// Decide whether a write may proceed.
    async fn check_write(
        &self,
        vault_id: &VaultId,
        writer: &PrincipalId,
        usage: &VaultUsage,
        delta: &WriteDelta,
    ) -> Result<(), ApiError>;
    /// Usage changed after a write or delete (accounting hook).
    async fn usage_changed(&self, _vault_id: &VaultId, _usage: &VaultUsage) {}
}

/// Fixed per-vault limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StaticQuota {
    /// Maximum bytes per vault.
    pub max_bytes_per_vault: Option<u64>,
    /// Maximum objects per vault.
    pub max_objects_per_vault: Option<u64>,
}

impl StaticQuota {
    /// No limits.
    pub const fn unlimited() -> Self {
        Self {
            max_bytes_per_vault: None,
            max_objects_per_vault: None,
        }
    }
}

fn exceeded() -> ApiError {
    ApiError::new(ErrorCode::QuotaExceeded).with_message(
        "已超出此账号库的存储配额",
        "This vault's storage quota is exceeded.",
    )
}

#[async_trait]
impl QuotaPolicy for StaticQuota {
    async fn quota_bytes(&self, _vault_id: &VaultId) -> Result<Option<u64>, ApiError> {
        Ok(self.max_bytes_per_vault)
    }

    async fn check_write(
        &self,
        _vault_id: &VaultId,
        _writer: &PrincipalId,
        usage: &VaultUsage,
        delta: &WriteDelta,
    ) -> Result<(), ApiError> {
        if let Some(max) = self.max_bytes_per_vault {
            let after = usage
                .bytes_used
                .saturating_add(delta.added_bytes)
                .saturating_sub(delta.removed_bytes);
            if after > max && delta.added_bytes > delta.removed_bytes {
                return Err(exceeded());
            }
        }
        if let Some(max) = self.max_objects_per_vault
            && delta.new_object
            && usage.object_count >= max
        {
            return Err(exceeded());
        }
        Ok(())
    }
}
