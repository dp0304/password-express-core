// SPDX-License-Identifier: Apache-2.0
//! Who may use the relay: resolving principal keys and deciding whether a sender may post
//! into a recipient's mailbox ("sender must share a vault with the recipient", CONTRACTS §4).
//!
//! * [`SyncDirectory`] — derives both from the vaults hosted by the co-located sync server
//!   (signed member records; executors included, revoked members excluded).
//! * [`StaticDirectory`] — explicit principals and groups (e.g. a node's paired approver
//!   devices when the vault itself lives on the user's own S3 bucket).
//! * [`ChainDirectory`] — first directory that knows a principal wins; sends are allowed
//!   when any directory allows them.
//!
//! The commercial cloud plugs its own implementation (account-scoped devices, `relay`
//! entitlement → `PAYMENT_REQUIRED`).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use aipass_types::ids::{PrincipalId, VaultId};
use aipass_types::{ApiError, ErrorCode};
use async_trait::async_trait;

use crate::sync::{SyncState, member_device_for};

/// Relay authorization source.
#[async_trait]
pub trait RelayDirectory: Send + Sync {
    /// Ed25519 key of an **active** `dev_` / `exe_` principal, or `None` if unknown.
    async fn principal_key(&self, principal: &PrincipalId) -> Result<Option<[u8; 32]>, ApiError>;
    /// `Ok(())` when `sender` may post into `recipient`'s mailbox; an error otherwise
    /// (`FORBIDDEN`, or e.g. `PAYMENT_REQUIRED` in the cloud).
    async fn authorize_send(
        &self,
        sender: &PrincipalId,
        recipient: &PrincipalId,
    ) -> Result<(), ApiError>;
}

pub(crate) fn not_shared() -> ApiError {
    ApiError::new(ErrorCode::Forbidden).with_message(
        "收件设备与发送方不属于同一个账号库",
        "The recipient does not share a vault with the sender.",
    )
}

/// Directory backed by the vaults of a [`SyncState`].
#[derive(Clone, Debug)]
pub struct SyncDirectory {
    sync: SyncState,
}

impl SyncDirectory {
    /// Wrap a sync state.
    pub fn new(sync: SyncState) -> Self {
        Self { sync }
    }

    async fn active_vaults(&self, p: &PrincipalId) -> Result<Vec<(VaultId, [u8; 32])>, ApiError> {
        let Some(dev) = member_device_for(p) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for v in self.sync.vaults_of(&dev).await? {
            if let Some(m) = self.sync.resolve_member(&v, p).await?
                && m.is_active()
            {
                out.push((v, m.sign_pk));
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl RelayDirectory for SyncDirectory {
    /// The key of `principal` across **all** vaults where it is an active member. Member
    /// records are bound to the device id's server-wide key on upload, so every vault
    /// agrees; if they ever do not (records stored before key binding existed), fail closed
    /// rather than trusting whichever vault sorts first.
    async fn principal_key(&self, principal: &PrincipalId) -> Result<Option<[u8; 32]>, ApiError> {
        let keys: BTreeSet<[u8; 32]> = self
            .active_vaults(principal)
            .await?
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        if keys.len() > 1 {
            tracing::warn!(principal = %principal, "principal has different keys in different vaults; relay access denied");
            return Ok(None);
        }
        Ok(keys.into_iter().next())
    }

    async fn authorize_send(
        &self,
        sender: &PrincipalId,
        recipient: &PrincipalId,
    ) -> Result<(), ApiError> {
        let a: BTreeSet<VaultId> = self
            .active_vaults(sender)
            .await?
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        if a.is_empty() {
            return Err(not_shared());
        }
        let b = self.active_vaults(recipient).await?;
        if b.iter().any(|(v, _)| a.contains(v)) {
            Ok(())
        } else {
            Err(not_shared())
        }
    }
}

#[derive(Debug, Clone)]
struct StaticEntry {
    sign_pk: [u8; 32],
    groups: BTreeSet<String>,
}

/// Explicitly configured principals and groups.
#[derive(Debug, Default)]
pub struct StaticDirectory {
    entries: RwLock<HashMap<PrincipalId, StaticEntry>>,
}

impl StaticDirectory {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a principal with its signing key and groups (e.g. vault ids).
    pub fn insert(
        &self,
        principal: PrincipalId,
        sign_pk: [u8; 32],
        groups: impl IntoIterator<Item = String>,
    ) {
        self.entries
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                principal,
                StaticEntry {
                    sign_pk,
                    groups: groups.into_iter().collect(),
                },
            );
    }

    /// Remove a principal (revocation).
    pub fn remove(&self, principal: &PrincipalId) {
        self.entries
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .remove(principal);
    }
}

#[async_trait]
impl RelayDirectory for StaticDirectory {
    async fn principal_key(&self, principal: &PrincipalId) -> Result<Option<[u8; 32]>, ApiError> {
        Ok(self
            .entries
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal)
            .map(|e| e.sign_pk))
    }

    async fn authorize_send(
        &self,
        sender: &PrincipalId,
        recipient: &PrincipalId,
    ) -> Result<(), ApiError> {
        let map = self.entries.read().unwrap_or_else(|p| p.into_inner());
        match (map.get(sender), map.get(recipient)) {
            (Some(a), Some(b)) if a.groups.intersection(&b.groups).next().is_some() => Ok(()),
            _ => Err(not_shared()),
        }
    }
}

/// Several directories in order.
pub struct ChainDirectory {
    dirs: Vec<Arc<dyn RelayDirectory>>,
}

impl core::fmt::Debug for ChainDirectory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainDirectory")
            .field("len", &self.dirs.len())
            .finish()
    }
}

impl ChainDirectory {
    /// Construct.
    pub fn new(dirs: Vec<Arc<dyn RelayDirectory>>) -> Self {
        Self { dirs }
    }
}

#[async_trait]
impl RelayDirectory for ChainDirectory {
    async fn principal_key(&self, principal: &PrincipalId) -> Result<Option<[u8; 32]>, ApiError> {
        for d in &self.dirs {
            if let Some(k) = d.principal_key(principal).await? {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    async fn authorize_send(
        &self,
        sender: &PrincipalId,
        recipient: &PrincipalId,
    ) -> Result<(), ApiError> {
        let mut last = not_shared();
        for d in &self.dirs {
            match d.authorize_send(sender, recipient).await {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}
