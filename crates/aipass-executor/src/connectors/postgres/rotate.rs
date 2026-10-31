// SPDX-License-Identifier: Apache-2.0
//! Experimental (V1.1): `credentials.rotate` with scheme `postgres.password`
//! (design doc §6.6 "创建候选凭证→验证可用→更新已知依赖→撤销旧凭证").
//!
//! 1. Candidate password from the OS CSPRNG (256 bits, base64url).
//! 2. `ALTER ROLE <current_user> PASSWORD '<SCRAM verifier>'` on a session authenticated with
//!    the old password (the verifier is computed client-side; the cleartext never appears in
//!    SQL text or server logs).
//! 3. Verify: open a **new** session with the candidate and check `current_user`.
//! 4. Success → the grant's installed credential is replaced by the new one (subsequent
//!    operations use it) and a copy is held for delivery **only** to the approving device
//!    ([`crate::Executor::seal_rotation_result`]); the AI receives status metadata only.
//! 5. Verification failure → the old password is restored on the still-open old session and
//!    re-verified; if even that cannot be confirmed the outcome is reported as unknown and
//!    the candidate stays available to the trusted device for recovery.
//!
//! PostgreSQL keeps exactly one password per role, so "old stays valid until the new one is
//! verified" is implemented as *restore-on-failure*, not as two concurrently valid passwords.

use std::collections::HashMap;
use std::sync::Mutex;

use aipass_crypto::SecretString;
use aipass_types::exec::{CredentialMaterial, ExecutionOutcome};
use aipass_types::models::SideEffects;
use aipass_types::{ApiError, ErrorCode, OperationId, Timestamp};
use serde_json::json;

use super::config::{LeaseMode, PgConfig, quote_ident};
use super::lease::random_password;
use super::session::{self, PgTarget, SessionKind};
use crate::connectors::ExecContext;
use crate::errors;

/// Operation name.
pub const ROTATE: &str = "credentials.rotate";
/// The only scheme implemented.
pub const SCHEME_POSTGRES_PASSWORD: &str = "postgres.password";
/// How long an undelivered rotation result is held in executor memory.
pub const HOLD_TTL: std::time::Duration = std::time::Duration::from_secs(86_400);

/// State of a held rotation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    /// New password set and verified.
    Rotated,
    /// The database state could not be confirmed; the candidate is held for recovery.
    Unknown,
}

pub(crate) struct PendingRotation {
    pub material: CredentialMaterial,
    pub state: RotationState,
    pub created_at: Timestamp,
}

#[derive(Default)]
pub(crate) struct RotationStore {
    pending: Mutex<HashMap<OperationId, PendingRotation>>,
    #[cfg(feature = "test-util")]
    pub(crate) force_verify_failure: std::sync::atomic::AtomicBool,
}

impl RotationStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<OperationId, PendingRotation>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Run `f` with the held material of `rotation_id`.
    pub fn with<R>(
        &self,
        rotation_id: &OperationId,
        f: impl FnOnce(&PendingRotation) -> R,
    ) -> Option<R> {
        self.lock().get(rotation_id).map(f)
    }

    /// Drop a held result.
    pub fn remove(&self, rotation_id: &OperationId) -> bool {
        self.lock().remove(rotation_id).is_some()
    }

    /// Drop results older than `ttl`.
    pub fn sweep(&self, ttl: std::time::Duration) {
        let ttl = chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::hours(24));
        let now = chrono::Utc::now();
        self.lock().retain(|_, p| now - p.created_at < ttl);
    }

    fn insert(&self, id: OperationId, p: PendingRotation) {
        self.lock().insert(id, p);
    }

    fn verify_should_fail(&self) -> bool {
        #[cfg(feature = "test-util")]
        {
            self.force_verify_failure
                .load(std::sync::atomic::Ordering::SeqCst)
        }
        #[cfg(not(feature = "test-util"))]
        {
            false
        }
    }
}

async fn login_works(target: &PgTarget, user: &str, password: &str) -> bool {
    match session::connect(target, user, password, SessionKind::Query, 0).await {
        Ok(s) => {
            let ok = s
                .client
                .query_one("SELECT current_user::text", &[])
                .await
                .map(|r| r.get::<_, String>(0) == user)
                .unwrap_or(false);
            s.close();
            ok
        }
        Err(_) => false,
    }
}

fn verifier(password: &str) -> String {
    postgres_protocol::password::scram_sha_256(password.as_bytes())
}

/// Execute `credentials.rotate`.
pub(crate) async fn rotate(
    ctx: &ExecContext,
    cfg: &PgConfig,
    target: &PgTarget,
    store: &RotationStore,
) -> Result<ExecutionOutcome, ApiError> {
    if cfg.lease_mode == LeaseMode::TemporaryRole {
        return Err(errors::not_supported(
            "临时角色模式下不轮换签发凭证",
            "The issuer credential is not rotated in temporary-role mode.",
        ));
    }
    let old = ctx.credential.material();
    let user = old.username.clone().ok_or_else(|| {
        errors::secret_unavailable(
            "数据库凭证缺少用户名",
            "The database credential has no username.",
        )
    })?;
    let control =
        session::connect(target, &user, old.secret.expose(), SessionKind::Control, 0).await?;
    let result = rotate_on(ctx, cfg, target, store, &control, &user).await;
    control.close();
    result
}

async fn rotate_on(
    ctx: &ExecContext,
    cfg: &PgConfig,
    target: &PgTarget,
    store: &RotationStore,
    control: &session::Session,
    user: &str,
) -> Result<ExecutionOutcome, ApiError> {
    let old = ctx.credential.material();
    let privs = session::role_privileges(&control.client).await?;
    if privs.is_privileged() && !cfg.allow_superuser {
        return Err(session::privileged_role_error());
    }
    let current: String = control
        .client
        .query_one("SELECT current_user::text", &[])
        .await
        .map_err(|e| session::map_pg_error(&e))?
        .get(0);
    if current != user {
        return Err(errors::scope_denied(
            "数据库会话角色与凭证用户名不一致，已停止轮换",
            "The session role does not match the credential username; rotation stopped.",
        ));
    }
    if ctx.cancel.is_cancelled() {
        return Err(errors::cancelled());
    }
    let candidate: SecretString = random_password()?;
    let alter = |pw: &str| {
        format!(
            "ALTER ROLE {} PASSWORD '{}'",
            quote_ident(user),
            verifier(pw)
        )
    };
    // From here on the upstream state changes.
    control
        .client
        .batch_execute(&alter(candidate.expose()))
        .await
        .map_err(|e| session::map_pg_error(&e))?;

    let verified =
        !store.verify_should_fail() && login_works(target, user, candidate.expose()).await;
    if verified {
        let new = CredentialMaterial {
            entry_id: old.entry_id.clone(),
            version: old.version + 1,
            kind: old.kind,
            username: old.username.clone(),
            secret: candidate,
            database: old.database.clone(),
            expires_at: old.expires_at,
        };
        // Swap the grant's credential only if it is still the one this operation started
        // with: never resurrect a credential end_sessions dropped meanwhile. The upstream
        // already changed, so a failed swap must not lose the new password either — it is
        // kept below for delivery to the trusted device.
        match ctx.custody.replace_if_current(
            &ctx.grant_id,
            ctx.credential.install_id(),
            new.clone(),
        ) {
            Ok(Some(_)) => {}
            Ok(None) => tracing::info!(
                operation_id = %ctx.operation_id,
                "grant credential dropped or replaced during rotation; not reinstalled"
            ),
            Err(e) => tracing::warn!(
                operation_id = %ctx.operation_id, code = %e.code,
                "rotated credential could not be installed for the grant"
            ),
        }
        store.insert(
            ctx.operation_id.clone(),
            PendingRotation {
                material: new,
                state: RotationState::Rotated,
                created_at: aipass_types::time::now(),
            },
        );
        tracing::info!(operation_id = %ctx.operation_id, "postgres password rotated and verified");
        let data = json!({
            "status": "rotated",
            "scheme": SCHEME_POSTGRES_PASSWORD,
            "rotation_id": ctx.operation_id.as_str(),
            "entry_id": old.entry_id.as_str(),
            "new_version": old.version + 1,
            "verified": true,
            "delivery": "pending_trusted_device",
            "note": {
                "zh": "新密码已验证，仅会加密送达批准此操作的可信设备；AI 不会收到密码。",
                "en": "The new password was verified and is delivered, encrypted, only to the approving trusted device; the AI never receives it."
            }
        });
        let bytes = crate::connectors::json_len(&data);
        return Ok(ExecutionOutcome {
            data,
            rows: None,
            bytes,
            truncated: false,
            restricted_fields: Vec::new(),
            side_effects: SideEffects::Applied,
        });
    }

    // Restore the old password on the still-authenticated session.
    let restored = control
        .client
        .batch_execute(&alter(old.secret.expose()))
        .await
        .is_ok()
        && login_works(target, user, old.secret.expose()).await;
    if restored {
        tracing::warn!(operation_id = %ctx.operation_id, "rotation verify failed; old password restored");
        return Err(errors::upstream(
            "rotation_verify_failed",
            "新密码验证失败，已恢复原密码，凭证未改变",
            "The new password could not be verified; the old password was restored and nothing changed.",
        )
        .with_detail("rotation", "rolled_back"));
    }
    store.insert(
        ctx.operation_id.clone(),
        PendingRotation {
            material: CredentialMaterial {
                entry_id: old.entry_id.clone(),
                version: old.version + 1,
                kind: old.kind,
                username: old.username.clone(),
                secret: candidate,
                database: old.database.clone(),
                expires_at: old.expires_at,
            },
            state: RotationState::Unknown,
            created_at: aipass_types::time::now(),
        },
    );
    tracing::error!(operation_id = %ctx.operation_id, "rotation state unknown; candidate held for trusted device");
    Err(ApiError::new(ErrorCode::UpstreamOutcomeUnknown)
        .with_message(
            "无法确认数据库中的当前密码：新密码未通过验证，恢复原密码也未能确认。候选密码已保留，请在可信设备上处理。",
            "The database password state is unknown: the new password failed verification and restoring the old one could not be confirmed. The candidate is held for your trusted device.",
        )
        .with_detail("rotation", "unknown")
        .with_detail("rotation_id", ctx.operation_id.as_str().to_owned()))
}
