// SPDX-License-Identifier: Apache-2.0
//! Vault creation admission (`POST /v1/vaults`, CONTRACTS §3.3). Pluggable so the
//! self-host node can use one-time enroll tokens while the commercial cloud checks its
//! session + `official_sync` entitlement + account quota.
//!
//! Admission only decides *whether a new vault namespace may be created*. It never grants
//! access to an existing vault: after creation every request is authorized by the vault's
//! own signed member records.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_types::ids::{DeviceId, VaultId};
use aipass_types::signing::token_hash;
use aipass_types::{ApiError, ErrorCode, Timestamp};
use async_trait::async_trait;

use crate::clock::{Clock, SystemClock};

/// What is being created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    /// New vault.
    pub vault_id: VaultId,
    /// Genesis device.
    pub genesis_device_id: DeviceId,
    /// Genesis device signing key.
    pub genesis_sign_pk: [u8; 32],
}

/// A granted admission, handed back to [`VaultAdmission::commit`] / [`VaultAdmission::abort`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admission {
    /// Account the vault belongs to (cloud), if any.
    pub account: Option<String>,
    /// Opaque reservation reference (e.g. the hash of a consumed enroll token).
    pub reservation: Option<String>,
}

/// Decides whether `POST /v1/vaults` may create a vault.
#[async_trait]
pub trait VaultAdmission: Send + Sync {
    /// `bearer` is the raw `Authorization: Bearer` token (treat as a secret: hash before
    /// comparing or storing, never log). Return an error to refuse (e.g. `UNAUTHENTICATED`,
    /// `PAYMENT_REQUIRED`, `QUOTA_EXCEEDED`).
    async fn admit(
        &self,
        bearer: Option<&str>,
        req: &AdmissionRequest,
    ) -> Result<Admission, ApiError>;
    /// The vault was created.
    async fn commit(&self, _admission: &Admission, _vault_id: &VaultId) -> Result<(), ApiError> {
        Ok(())
    }
    /// Creation failed after `admit` (e.g. the vault already exists): release reservations.
    async fn abort(&self, _admission: &Admission) {}
}

/// Refuses every vault creation (servers that only host vaults created elsewhere).
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllAdmission;

#[async_trait]
impl VaultAdmission for DenyAllAdmission {
    async fn admit(
        &self,
        _bearer: Option<&str>,
        _req: &AdmissionRequest,
    ) -> Result<Admission, ApiError> {
        Err(ApiError::new(ErrorCode::Forbidden).with_message(
            "此服务器不允许创建新的账号库",
            "This server does not accept new vaults.",
        ))
    }
}

#[derive(Debug, Clone)]
struct TokenSlot {
    uses_left: Option<u32>,
    expires_at: Option<Timestamp>,
}

/// Self-host admission with enroll tokens (`aipe_<b64u 32 bytes>`), stored only as
/// SHA-256 hashes. Tokens may be single- or multi-use and may expire.
pub struct EnrollTokenAdmission {
    tokens: Mutex<HashMap<String, TokenSlot>>,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for EnrollTokenAdmission {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnrollTokenAdmission")
            .field("tokens", &self.len())
            .finish()
    }
}

impl Default for EnrollTokenAdmission {
    fn default() -> Self {
        Self::new()
    }
}

/// Prefix of enroll tokens.
pub const ENROLL_TOKEN_PREFIX: &str = "aipe_";

impl EnrollTokenAdmission {
    /// No tokens yet.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    /// With an explicit clock.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Generate a token (CSPRNG). `uses = None` → unlimited; `ttl = None` → no expiry.
    /// The token is returned once; only its hash is kept.
    pub fn generate(
        &self,
        uses: Option<u32>,
        ttl: Option<Duration>,
    ) -> Result<SecretString, ApiError> {
        let token = aipass_crypto::rng::random_token(ENROLL_TOKEN_PREFIX, 32)
            .map_err(|_| ApiError::new(ErrorCode::Internal))?;
        let expires_at =
            ttl.map(|d| aipass_types::time::add_secs(&self.clock.now(), d.as_secs() as i64));
        self.insert_hash(token_hash(token.expose()), uses, expires_at);
        Ok(token)
    }

    /// Register a token by its hash (`aipass_types::signing::token_hash`), e.g. loaded from
    /// the node's configuration.
    pub fn insert_hash(&self, hash: String, uses: Option<u32>, expires_at: Option<Timestamp>) {
        self.tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                hash,
                TokenSlot {
                    uses_left: uses,
                    expires_at,
                },
            );
    }

    /// Remove every token.
    pub fn clear(&self) {
        self.tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Number of registered tokens.
    pub fn len(&self) -> usize {
        self.tokens.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// True when no token is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn token_required() -> ApiError {
    ApiError::new(ErrorCode::Unauthenticated).with_message(
        "需要有效的注册令牌才能在此服务器创建账号库",
        "A valid enroll token is required to create a vault on this server.",
    )
}

#[async_trait]
impl VaultAdmission for EnrollTokenAdmission {
    async fn admit(
        &self,
        bearer: Option<&str>,
        _req: &AdmissionRequest,
    ) -> Result<Admission, ApiError> {
        let token = bearer.ok_or_else(token_required)?;
        if !token.starts_with(ENROLL_TOKEN_PREFIX) {
            return Err(token_required());
        }
        let hash = token_hash(token);
        let now = self.clock.now();
        let mut map = self.tokens.lock().unwrap_or_else(|p| p.into_inner());
        let Some(slot) = map.get_mut(&hash) else {
            return Err(token_required());
        };
        if slot.expires_at.is_some_and(|e| e <= now) {
            map.remove(&hash);
            return Err(token_required());
        }
        match &mut slot.uses_left {
            Some(0) => return Err(token_required()),
            Some(n) => *n -= 1,
            None => {}
        }
        Ok(Admission {
            account: None,
            reservation: Some(hash),
        })
    }

    async fn abort(&self, admission: &Admission) {
        if let Some(h) = &admission.reservation
            && let Some(slot) = self
                .tokens
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(h)
            && let Some(n) = &mut slot.uses_left
        {
            *n += 1;
        }
    }
}
