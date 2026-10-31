// SPDX-License-Identifier: Apache-2.0
//! Build an [`ObjectStore`] from a persisted, non-secret [`StorageProfile`] plus secrets
//! supplied separately from the platform secret store (CONTRACTS §3.1, design doc §10.2).
//!
//! | kind | profile fields | secrets |
//! | --- | --- | --- |
//! | `local` | `path` | — |
//! | `s3` | `endpoint`, `region` (default `us-east-1`), `bucket`, `prefix?`, `path_style?` (default true), `username` = access key id | `secret` = secret access key, `session_token?` |
//! | `webdav` (experimental) | `endpoint`, `username?` | `secret` = password |
//! | `official` / `selfhost` | `base_url` | `device` = (vault id, kid, signer) |

use std::path::PathBuf;
use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_types::ids::{PrincipalId, VaultId};
use url::Url;

use crate::http::DeviceSigner;
use crate::s3::{S3Config, S3Credentials, S3Store};
use crate::webdav::{WebDavConfig, WebDavStore};
use crate::{HttpSyncStore, LocalDirStore, ObjectStore, StorageError, StorageKind, StorageProfile};

/// Device identity used for `official` / `selfhost` profiles.
#[derive(Clone)]
pub struct DeviceAuth {
    /// Vault on the sync service.
    pub vault_id: VaultId,
    /// `dev_…` or `exe_…`.
    pub kid: PrincipalId,
    /// Signing key.
    pub signer: DeviceSigner,
}

impl core::fmt::Debug for DeviceAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceAuth")
            .field("vault_id", &self.vault_id)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Secrets accompanying a profile. Never persisted with the profile.
#[derive(Clone, Default)]
pub struct ProfileSecrets {
    /// S3 secret access key or WebDAV password.
    pub secret: Option<SecretString>,
    /// S3 session token for temporary credentials.
    pub session_token: Option<SecretString>,
    /// Device identity for the HTTP sync API.
    pub device: Option<DeviceAuth>,
    /// Permit plain http to non-loopback hosts (development only).
    pub allow_http: bool,
}

impl core::fmt::Debug for ProfileSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProfileSecrets")
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("device", &self.device)
            .field("allow_http", &self.allow_http)
            .finish()
    }
}

fn missing(what: &'static str) -> StorageError {
    StorageError::Backend {
        status: None,
        message: format!("storage profile is missing `{what}`"),
    }
}

fn parse_url(s: &Option<String>, what: &'static str) -> Result<Url, StorageError> {
    let s = s.as_deref().ok_or_else(|| missing(what))?;
    Url::parse(s).map_err(|_| StorageError::Backend {
        status: None,
        message: format!("storage profile `{what}` is not a valid URL"),
    })
}

/// Open the backend described by `profile`.
pub fn open_store(
    profile: &StorageProfile,
    secrets: ProfileSecrets,
) -> Result<Arc<dyn ObjectStore>, StorageError> {
    match profile.kind {
        StorageKind::Local => {
            let path = profile.path.as_deref().ok_or_else(|| missing("path"))?;
            Ok(Arc::new(LocalDirStore::open(PathBuf::from(path))?))
        }
        StorageKind::S3 => {
            let endpoint = parse_url(&profile.endpoint, "endpoint")?;
            let bucket = profile.bucket.clone().ok_or_else(|| missing("bucket"))?;
            let region = profile
                .region
                .clone()
                .unwrap_or_else(|| "us-east-1".to_owned());
            let mut cfg = S3Config::new(endpoint, region, bucket)
                .with_prefix(profile.prefix.clone().unwrap_or_default());
            cfg.path_style = profile.path_style.unwrap_or(true);
            cfg.allow_http = secrets.allow_http;
            let ak = profile
                .username
                .clone()
                .ok_or_else(|| missing("username"))?;
            let sk = secrets.secret.ok_or_else(|| missing("secret"))?;
            let mut creds = S3Credentials::new(ak, sk);
            if let Some(t) = secrets.session_token {
                creds = creds.with_session_token(t);
            }
            Ok(Arc::new(S3Store::new(cfg, Arc::new(creds))?))
        }
        StorageKind::Webdav => {
            let base = parse_url(&profile.endpoint, "endpoint")?;
            let mut cfg = WebDavConfig::new(base);
            cfg.allow_http = secrets.allow_http;
            if let Some(u) = profile.username.clone() {
                cfg = cfg.with_basic_auth(u, secrets.secret.unwrap_or_default());
            }
            Ok(Arc::new(WebDavStore::new(cfg)?))
        }
        StorageKind::Official | StorageKind::Selfhost => {
            let base = parse_url(&profile.base_url, "base_url")?;
            let dev = secrets.device.ok_or_else(|| missing("device"))?;
            let http = crate::httputil::build_client(std::time::Duration::from_secs(60))?;
            Ok(Arc::new(HttpSyncStore::with_client(
                base,
                dev.vault_id,
                dev.kid,
                dev.signer,
                http,
                secrets.allow_http,
            )?))
        }
    }
}
