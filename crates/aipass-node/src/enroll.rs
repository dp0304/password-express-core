// SPDX-License-Identifier: Apache-2.0
//! Vault-creation admission for the self-hosted sync server: one-time enroll tokens
//! (`aipe_…`) whose SHA-256 hashes are persisted in `<data>/enroll-tokens.json` (0600).
//! The plaintext token is printed once by `aipass-node enroll-token create` and never stored.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aipass_sync_server::sync::{Admission, AdmissionRequest, ENROLL_TOKEN_PREFIX, VaultAdmission};
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::ids::VaultId;
use aipass_types::signing::token_hash;
use aipass_types::time::{self, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::fsutil;

/// File name inside the data directory.
pub const ENROLL_FILE: &str = "enroll-tokens.json";

/// One stored token (hash only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRecord {
    /// b64u SHA-256 of the token.
    pub hash: String,
    /// Remaining vault creations.
    pub uses_left: u32,
    /// Expiry.
    #[serde(with = "aipass_types::time::rfc3339_option", default)]
    pub expires_at: Option<Timestamp>,
    /// Creation time.
    #[serde(with = "aipass_types::time::rfc3339")]
    pub created_at: Timestamp,
    /// Vaults created with it.
    #[serde(default)]
    pub vaults: Vec<VaultId>,
    /// Uses reserved by an in-flight vault creation (taken from `uses_left` by `admit`,
    /// settled by `commit` / given back by `abort`). A crash in between keeps the use
    /// consumed (fail closed).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pending: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EnrollFile {
    tokens: Vec<EnrollRecord>,
}

/// File-backed admission.
#[derive(Debug)]
pub struct FileEnrollAdmission {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileEnrollAdmission {
    /// Admission backed by `<data_dir>/enroll-tokens.json`.
    pub fn new(data_dir: &Path) -> Self {
        Self { path: data_dir.join(ENROLL_FILE), lock: Mutex::new(()) }
    }

    fn load(&self) -> anyhow::Result<EnrollFile> {
        Ok(fsutil::read_json(&self.path)?.unwrap_or_default())
    }

    /// Create a token; returns the plaintext (show once).
    pub fn create(&self, uses: u32, ttl_secs: Option<i64>) -> anyhow::Result<aipass_crypto::SecretString> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let token = aipass_crypto::rng::random_token(ENROLL_TOKEN_PREFIX, 32)?;
        let mut f = self.load()?;
        let now = time::now();
        f.tokens.retain(|t| t.pending > 0 || (t.uses_left > 0 && t.expires_at.is_none_or(|e| e > now)));
        f.tokens.push(EnrollRecord {
            hash: token_hash(token.expose()),
            uses_left: uses.max(1),
            expires_at: ttl_secs.map(|s| time::add_secs(&now, s)),
            created_at: now,
            vaults: Vec::new(),
            pending: 0,
        });
        fsutil::write_json(&self.path, &f)?;
        Ok(token)
    }

    /// Stored records (hashes only).
    pub fn list(&self) -> anyhow::Result<Vec<EnrollRecord>> {
        Ok(self.load()?.tokens)
    }
}

fn denied() -> ApiError {
    ApiError::new(ErrorCode::Unauthenticated).with_message(
        "需要有效的注册令牌（aipass-node enroll-token create）",
        "a valid enroll token is required (aipass-node enroll-token create)",
    )
}

/// Reservation protocol (same as the sync server's reference admission): `admit`
/// atomically takes one use under the lock and persists it *before* the vault is written,
/// so concurrent creations with one token can never exceed its uses; `abort` gives the use
/// back when creation fails; `commit` only records the vault. Expiry is enforced at
/// `admit`, the reservation point — the vault is already on disk by the time `commit`
/// runs, so refusing there would only orphan it.
#[async_trait]
impl VaultAdmission for FileEnrollAdmission {
    async fn admit(&self, bearer: Option<&str>, _req: &AdmissionRequest) -> Result<Admission, ApiError> {
        let token = bearer.filter(|b| b.starts_with(ENROLL_TOKEN_PREFIX)).ok_or_else(denied)?;
        let hash = token_hash(token);
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = self.load().map_err(|_| ApiError::internal())?;
        let now = time::now();
        let Some(t) = f
            .tokens
            .iter_mut()
            .find(|t| aipass_crypto::ct_eq(t.hash.as_bytes(), hash.as_bytes()) && t.uses_left > 0 && t.expires_at.is_none_or(|e| e > now))
        else {
            return Err(denied());
        };
        t.uses_left -= 1;
        t.pending = t.pending.saturating_add(1);
        fsutil::write_json(&self.path, &f).map_err(|_| ApiError::internal())?;
        Ok(Admission { account: None, reservation: Some(hash) })
    }

    async fn commit(&self, admission: &Admission, vault_id: &VaultId) -> Result<(), ApiError> {
        let Some(hash) = &admission.reservation else { return Err(denied()) };
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = self.load().map_err(|_| ApiError::internal())?;
        if let Some(t) = f.tokens.iter_mut().find(|t| &t.hash == hash) {
            t.pending = t.pending.saturating_sub(1);
            if !t.vaults.contains(vault_id) {
                t.vaults.push(vault_id.clone());
            }
            fsutil::write_json(&self.path, &f).map_err(|_| ApiError::internal())?;
        }
        Ok(())
    }

    async fn abort(&self, admission: &Admission) {
        let Some(hash) = &admission.reservation else { return };
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(mut f) = self.load() else { return };
        if let Some(t) = f.tokens.iter_mut().find(|t| &t.hash == hash && t.pending > 0) {
            t.pending -= 1;
            t.uses_left = t.uses_left.saturating_add(1);
            if let Err(e) = fsutil::write_json(&self.path, &f) {
                tracing::warn!(error = %e, "cannot release an enroll-token reservation");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> AdmissionRequest {
        AdmissionRequest { vault_id: VaultId::generate(), genesis_device_id: aipass_types::ids::DeviceId::generate(), genesis_sign_pk: [7; 32] }
    }

    #[tokio::test]
    async fn token_is_single_use_and_stored_hashed() {
        let dir = tempfile::tempdir().expect("tmp");
        let a = FileEnrollAdmission::new(dir.path());
        let tok = a.create(1, Some(3600)).expect("create");
        let raw = std::fs::read_to_string(dir.path().join(ENROLL_FILE)).expect("file");
        assert!(!raw.contains(tok.expose()));
        assert!(a.admit(None, &req()).await.is_err());
        assert!(a.admit(Some("aipe_wrong"), &req()).await.is_err());
        let adm = a.admit(Some(tok.expose()), &req()).await.expect("admit");
        a.commit(&adm, &VaultId::generate()).await.expect("commit");
        assert!(a.admit(Some(tok.expose()), &req()).await.is_err(), "used up");
    }

    /// MNC-02: the use is reserved at `admit`, so N concurrent creations with a 1-use
    /// token admit exactly one; `abort` gives the use back.
    #[tokio::test]
    async fn concurrent_admits_reserve_the_single_use() {
        let dir = tempfile::tempdir().expect("tmp");
        let a = std::sync::Arc::new(FileEnrollAdmission::new(dir.path()));
        let tok = a.create(1, Some(3600)).expect("create");
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let a = a.clone();
            let t = tok.expose().to_string();
            tasks.push(tokio::spawn(async move { a.admit(Some(&t), &req()).await }));
        }
        let mut admitted = Vec::new();
        for t in tasks {
            if let Ok(adm) = t.await.expect("join") {
                admitted.push(adm);
            }
        }
        assert_eq!(admitted.len(), 1, "exactly one admission for a 1-use token");
        // a failed creation releases the use; a second try can then succeed exactly once
        a.abort(&admitted[0]).await;
        let adm = a.admit(Some(tok.expose()), &req()).await.expect("re-admit after abort");
        assert!(a.admit(Some(tok.expose()), &req()).await.is_err());
        let vault = VaultId::generate();
        a.commit(&adm, &vault).await.expect("commit");
        let rec = &a.list().expect("list")[0];
        assert_eq!((rec.uses_left, rec.pending), (0, 0));
        assert_eq!(rec.vaults, vec![vault]);
        // a token with an in-flight reservation is not pruned by `create`
        let tok2 = a.create(1, None).expect("create 2");
        let adm2 = a.admit(Some(tok2.expose()), &req()).await.expect("admit 2");
        a.create(1, None).expect("create 3");
        a.commit(&adm2, &VaultId::generate()).await.expect("commit 2");
        assert!(a.list().expect("list").iter().any(|r| r.vaults.len() == 1 && r.hash == token_hash(tok2.expose())));
    }
}
