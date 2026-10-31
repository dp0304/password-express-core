// SPDX-License-Identifier: Apache-2.0
//! [`StandardStoreFactory`] — the production [`StoreFactory`] over the `aipass-storage`
//! backends (`aipass_storage::profile::open_store`): `local` (directory), `s3`
//! (capability-tested S3-compatible), `webdav` (experimental) and `official` / `selfhost`
//! (device-signed HTTP sync API).
//!
//! Secrets: for `s3` the storage secret is the secret access key (`username` = access key
//! id); for `webdav` the password; for `official` / `selfhost` requests are signed with the
//! device key from the [`StoreContext`] and the storage secret is only used as the bearer
//! (self-host enroll token or `aips_` session) of `POST /v1/vaults` when a vault is created.

use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_storage::profile::{DeviceAuth, ProfileSecrets, open_store};
use aipass_storage::{HttpSyncStore, ObjectStore, StorageKind, StorageProfile};
use aipass_types::ids::PrincipalId;
use aipass_types::vault::{MemberRecord, VaultHeader};
use aipass_vault::encoding::object_bytes;
use aipass_vault::{Result, VaultError};
use async_trait::async_trait;

use crate::client::{StoreContext, StoreFactory};

/// Production store factory.
#[derive(Debug, Clone, Default)]
pub struct StandardStoreFactory {
    /// Permit plain `http://` to non-loopback hosts (development only; loopback is always
    /// allowed by the backends).
    pub allow_http: bool,
}

impl StandardStoreFactory {
    /// Factory with https-only endpoints.
    pub fn new() -> Self {
        Self::default()
    }
}

fn device_auth(ctx: &StoreContext) -> Option<DeviceAuth> {
    let (Some(id), Some(identity)) = (&ctx.device_id, &ctx.identity) else {
        return None;
    };
    Some(DeviceAuth {
        vault_id: ctx.vault_id.clone(),
        kid: PrincipalId::Device(id.clone()),
        signer: Arc::new(identity.clone()),
    })
}

#[async_trait]
impl StoreFactory for StandardStoreFactory {
    async fn open(
        &self,
        profile: &StorageProfile,
        secret: Option<&SecretString>,
        ctx: &StoreContext,
    ) -> Result<Arc<dyn ObjectStore>> {
        let secrets = ProfileSecrets {
            secret: match profile.kind {
                // the HTTP sync API authenticates every request with the device key
                StorageKind::Official | StorageKind::Selfhost => None,
                _ => secret.cloned(),
            },
            session_token: None,
            device: device_auth(ctx),
            allow_http: self.allow_http,
        };
        Ok(open_store(profile, secrets)?)
    }

    async fn provision(
        &self,
        profile: &StorageProfile,
        secret: Option<&SecretString>,
        _ctx: &StoreContext,
        header: &VaultHeader,
        genesis: &MemberRecord,
    ) -> Result<()> {
        if !matches!(profile.kind, StorageKind::Official | StorageKind::Selfhost) {
            return Ok(());
        }
        let base = profile
            .base_url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .ok_or(VaultError::InvalidInput(
                "sync service base_url missing or invalid",
            ))?;
        let bearer = secret.ok_or(VaultError::Invalid(aipass_types::Localized::new(
            "创建账号库需要自托管注册令牌或官方服务登录会话",
            "Creating a vault needs a self-host enroll token or an official-service session.",
        )))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| VaultError::Internal("HTTP client"))?;
        HttpSyncStore::create_vault(
            &http,
            &base,
            bearer,
            &object_bytes(header)?,
            &object_bytes(genesis)?,
            self.allow_http,
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_types::ids::VaultId;

    #[tokio::test]
    async fn opens_local_profiles_and_rejects_incomplete_ones() {
        let d = tempfile::tempdir().unwrap();
        let mut p = StorageProfile::new(StorageKind::Local);
        p.path = Some(d.path().to_string_lossy().to_string());
        let ctx = StoreContext {
            vault_id: VaultId::generate(),
            device_id: None,
            identity: None,
        };
        let f = StandardStoreFactory::new();
        let s = f.open(&p, None, &ctx).await.unwrap();
        let r = aipass_storage::capability_test(s.as_ref(), "_captest").await;
        assert_eq!(
            r.verdict,
            aipass_storage::StorageVerdict::SyncCapable,
            "{:?}",
            r.details
        );
        let s3 = StorageProfile::new(StorageKind::S3);
        assert!(f.open(&s3, None, &ctx).await.is_err());
        let mut off = StorageProfile::new(StorageKind::Official);
        off.base_url = Some("https://cloud.aipass.example".into());
        assert!(
            f.open(&off, None, &ctx).await.is_err(),
            "HTTP sync needs a device identity"
        );
    }
}
