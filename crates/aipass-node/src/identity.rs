// SPDX-License-Identifier: Apache-2.0
//! The node's long-term executor identity (`<data>/executor.key`, 0600).
//!
//! One identity serves three roles with the same ULID: executor principal `exe_X`
//! (broker relay mailbox, sync/relay signatures, cloud tunnel), vault member `dev_X`
//! (role executor, written by the trusted device during pairing) and the HPKE recipient
//! for credential envelopes.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use aipass_crypto::{DeviceIdentity, SecretBytes, b64u};
use aipass_types::ids::{DeviceId, ExecutorId};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// File name inside the data directory.
pub const IDENTITY_FILE: &str = "executor.key";

/// Loaded identity.
#[derive(Clone)]
pub struct NodeIdentity {
    /// Executor / broker principal.
    pub executor_id: ExecutorId,
    /// Keys.
    pub identity: Arc<DeviceIdentity>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity").field("executor_id", &self.executor_id).finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    format: u32,
    kind: String,
    executor_id: ExecutorId,
    /// b64u(seed ‖ kem secret), 64 bytes.
    secret: String,
}

impl NodeIdentity {
    /// Vault member id of this executor (`dev_X` for `exe_X`).
    pub fn member_device_id(&self) -> DeviceId {
        aipass_vault::member::executor_member_id(&self.executor_id)
    }

    /// Path of the identity file.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(IDENTITY_FILE)
    }

    /// Load the identity, creating it (CSPRNG) on first start.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        let path = Self::path(data_dir);
        if path.exists() {
            return Self::load(data_dir);
        }
        crate::fsutil::private_dir(data_dir)?;
        let identity = DeviceIdentity::generate();
        let executor_id = ExecutorId::generate();
        let secret = identity.to_secret_bytes();
        let file = IdentityFile {
            format: 1,
            kind: "aipass-node-identity".into(),
            executor_id: executor_id.clone(),
            secret: b64u::encode(secret.expose()),
        };
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(&file)?);
        let mut f = OpenOptions::new();
        f.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            f.mode(0o600);
        }
        let mut fh = f.open(&path).with_context(|| format!("cannot create {}", path.display()))?;
        fh.write_all(&bytes)?;
        fh.sync_all()?;
        drop(Zeroizing::new(file.secret));
        Ok(Self { executor_id, identity: Arc::new(identity) })
    }

    /// Load an existing identity; refuses group/other-readable files.
    pub fn load(data_dir: &Path) -> anyhow::Result<Self> {
        let path = Self::path(data_dir);
        crate::fsutil::check_private_file(&path)?;
        let bytes = Zeroizing::new(std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?);
        let file: IdentityFile = serde_json::from_slice(&bytes).context("identity file is corrupt")?;
        let secret_text = Zeroizing::new(file.secret);
        if file.format != 1 || file.kind != "aipass-node-identity" {
            bail!("unsupported identity file format");
        }
        let raw = SecretBytes::new(b64u::decode(&secret_text).context("identity file is corrupt")?);
        let identity = DeviceIdentity::from_secret_bytes(raw.expose()).context("identity file is corrupt")?;
        Ok(Self { executor_id: file.executor_id, identity: Arc::new(identity) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tmp");
        let a = NodeIdentity::load_or_create(dir.path()).expect("create");
        let b = NodeIdentity::load_or_create(dir.path()).expect("load");
        assert_eq!(a.executor_id, b.executor_id);
        assert_eq!(a.identity.public(), b.identity.public());
        assert_eq!(&a.member_device_id().as_str()[4..], &a.executor_id.as_str()[4..]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(NodeIdentity::path(dir.path())).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!format!("{a:?}").contains(&b64u::encode(a.identity.to_secret_bytes().expose())));
    }
}
