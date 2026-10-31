// SPDX-License-Identifier: Apache-2.0
//! Experimental (V1.1): `lease_mode: "temporary_role"`.
//!
//! The installed credential is an *issuer* role (`CREATEROLE`, `ADMIN OPTION` on the template
//! role, and ideally `pg_signal_backend`). For each grant the executor creates
//!
//! ```sql
//! CREATE ROLE "aipass_l_<random>" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
//!   NOREPLICATION NOBYPASSRLS INHERIT CONNECTION LIMIT <n>
//!   PASSWORD '<SCRAM-SHA-256 verifier>' VALID UNTIL '<expiry>' IN ROLE "<template>"
//! ```
//!
//! and runs the grant's queries as that role. The password comes from the OS CSPRNG and is
//! hashed client-side (the cleartext never appears in SQL or server logs). `revoke_upstream`
//! terminates the role's backends, drops the role and **verifies** both; anything that could
//! not be verified is reported as `pending` / `failed` with a plain explanation — never as
//! done. `VALID UNTIL` only stops *new* logins after expiry, which is why the executor also
//! revokes expired leases from its maintenance sweep.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_types::exec::LevelReport;
use aipass_types::models::{Lease, LevelStatus};
use aipass_types::{ApiError, GrantId, LeaseId, Timestamp};
use chrono::Utc;

use super::config::{PgConfig, quote_ident};
use super::session::{self, PgTarget, SessionKind};
use crate::custody::InstalledCredential;
use crate::errors;

/// Lease kind string.
pub const LEASE_KIND: &str = "postgres.temporary_role";
/// A lease with less than this left is replaced instead of reused.
const MIN_REMAINING: chrono::Duration = chrono::Duration::seconds(30);

struct LeaseRecord {
    lease: Lease,
    password: SecretString,
    cred_key: u64,
    /// Kept only to revoke the role later (dropped together with the record).
    issuer: Arc<InstalledCredential>,
    target: PgTarget,
}

/// Credentials of an active temporary role.
pub(crate) struct LeasedLogin {
    pub role: String,
    pub password: SecretString,
    pub cred_key: u64,
}

#[derive(Default)]
pub(crate) struct LeaseManager {
    leases: Mutex<HashMap<GrantId, Vec<LeaseRecord>>>,
    create_locks: Mutex<HashMap<GrantId, Arc<tokio::sync::Mutex<()>>>>,
    next_key: std::sync::atomic::AtomicU64,
}

fn verifier(password: &str) -> Result<String, ApiError> {
    let v = postgres_protocol::password::scram_sha_256(password.as_bytes());
    // The verifier alphabet is base64 + `$` + `:`; refuse anything that would need quoting.
    if v.chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=$:-".contains(c))
    {
        Ok(v)
    } else {
        Err(ApiError::internal())
    }
}

pub(crate) fn random_password() -> Result<SecretString, ApiError> {
    let bytes = aipass_crypto::rng::random_secret(32).map_err(|_| ApiError::internal())?;
    Ok(SecretString::new(aipass_crypto::b64u::encode(
        bytes.expose(),
    )))
}

fn random_role_name() -> Result<String, ApiError> {
    let b = aipass_crypto::rng::try_random_array::<8>().map_err(|_| ApiError::internal())?;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("aipass_l_{hex}"))
}

impl LeaseManager {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<GrantId, Vec<LeaseRecord>>> {
        self.leases.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Leases of a grant (metadata only).
    pub fn leases(&self, grant_id: &GrantId) -> Vec<Lease> {
        self.lock()
            .get(grant_id)
            .map(|v| v.iter().map(|r| r.lease.clone()).collect())
            .unwrap_or_default()
    }

    /// An active temporary role for `grant_id`, created on first use.
    pub async fn ensure(
        &self,
        grant_id: &GrantId,
        cfg: &PgConfig,
        target: &PgTarget,
        issuer: Arc<InstalledCredential>,
    ) -> Result<LeasedLogin, ApiError> {
        let tr = cfg
            .temporary_role
            .as_ref()
            .ok_or_else(|| errors::bad_config("temporary_role"))?;
        let lock = {
            let mut l = self.create_locks.lock().unwrap_or_else(|p| p.into_inner());
            l.entry(grant_id.clone()).or_default().clone()
        };
        let _guard = lock.lock().await;
        let now = Utc::now();
        if let Some(r) = self.lock().get(grant_id).and_then(|v| {
            v.iter().find(|r| {
                r.lease.revoke_status == LevelStatus::NotApplicable
                    && r.lease.expires_at - now > MIN_REMAINING
                    && r.issuer.install_id() == issuer.install_id()
            })
        }) {
            return Ok(LeasedLogin {
                role: r.lease.upstream_ref.clone(),
                password: r.password.clone(),
                cred_key: r.cred_key,
            });
        }

        let material = issuer.material();
        let user = material.username.as_deref().ok_or_else(|| {
            errors::secret_unavailable(
                "临时角色签发凭证缺少用户名",
                "The issuer credential has no username.",
            )
        })?;
        let control = session::connect(
            target,
            user,
            material.secret.expose(),
            SessionKind::Control,
            0,
        )
        .await?;
        let result = async {
            let privs = session::role_privileges(&control.client).await?;
            if privs.superuser && !cfg.allow_superuser {
                return Err(session::privileged_role_error());
            }
            let role = random_role_name()?;
            let password = random_password()?;
            let ttl = chrono::Duration::seconds(tr.ttl_seconds as i64);
            let expires_at: Timestamp =
                aipass_types::time::truncate(issuer.expires_at().min(now + ttl));
            let sql = format!(
                "CREATE ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION \
                 NOBYPASSRLS INHERIT CONNECTION LIMIT {} PASSWORD '{}' VALID UNTIL '{}' IN ROLE {}",
                quote_ident(&role),
                tr.connection_limit,
                verifier(password.expose())?,
                expires_at.format("%Y-%m-%d %H:%M:%S+00"),
                quote_ident(&tr.template_role),
            );
            control
                .client
                .batch_execute(&sql)
                .await
                .map_err(|e| session::map_pg_error(&e))?;
            Ok((role, password, expires_at))
        }
        .await;
        control.close();
        let (role, password, expires_at) = result?;
        let cred_key = 1u64 << 63
            | self
                .next_key
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let lease = Lease {
            lease_id: LeaseId::generate(),
            grant_id: grant_id.clone(),
            kind: LEASE_KIND.to_owned(),
            upstream_ref: role.clone(),
            expires_at,
            revoke_status: LevelStatus::NotApplicable,
        };
        tracing::info!(grant_id = %grant_id, lease_id = %lease.lease_id, "temporary role created");
        self.lock()
            .entry(grant_id.clone())
            .or_default()
            .push(LeaseRecord {
                lease,
                password: password.clone(),
                cred_key,
                issuer,
                target: target.clone(),
            });
        Ok(LeasedLogin {
            role,
            password,
            cred_key,
        })
    }

    /// Revoke every lease of `grant_id`.
    pub async fn revoke(&self, grant_id: &GrantId) -> LevelReport {
        let records: Vec<LeaseRecord> = self.lock().remove(grant_id).unwrap_or_default();
        if records.is_empty() {
            return LevelReport::not_applicable();
        }
        let mut keep = Vec::new();
        let mut failed = Vec::new();
        let mut pending = Vec::new();
        for mut r in records {
            let report = revoke_one(&r).await;
            r.lease.revoke_status = report.status;
            match report.status {
                LevelStatus::Done | LevelStatus::NotApplicable => {
                    tracing::info!(lease_id = %r.lease.lease_id, "temporary role revoked");
                }
                LevelStatus::Pending => {
                    pending.push(report.detail.unwrap_or_default());
                    keep.push(r);
                }
                LevelStatus::Failed => {
                    failed.push(report.detail.unwrap_or_default());
                    keep.push(r);
                }
            }
        }
        if !keep.is_empty() {
            self.lock()
                .entry(grant_id.clone())
                .or_default()
                .extend(keep);
        }
        if !failed.is_empty() {
            let mut all = failed;
            all.extend(pending);
            LevelReport::failed(all.join(" | "))
        } else if !pending.is_empty() {
            LevelReport::pending(pending.join(" | "))
        } else {
            LevelReport::done()
        }
    }

    /// Revoke expired leases and retry failed / pending revocations.
    pub async fn sweep(&self) {
        let now = Utc::now();
        let due: Vec<GrantId> = self
            .lock()
            .iter()
            .filter(|(_, v)| {
                v.iter().any(|r| {
                    r.lease.expires_at <= now || r.lease.revoke_status != LevelStatus::NotApplicable
                })
            })
            .map(|(g, _)| g.clone())
            .collect();
        for g in due {
            let _ = self.revoke(&g).await;
        }
    }
}

fn bi(zh: String, en: String) -> String {
    format!("{zh} / {en}")
}

async fn revoke_one(r: &LeaseRecord) -> LevelReport {
    let role = &r.lease.upstream_ref;
    let expiry = aipass_types::time::format_rfc3339(&r.lease.expires_at);
    let material = r.issuer.material();
    let Some(user) = material.username.as_deref() else {
        return LevelReport::failed(bi(
            format!(
                "无法撤销临时角色 {role}：签发凭证缺少用户名；该角色将于 {expiry} 到期，到期后无法再登录"
            ),
            format!(
                "Cannot revoke temporary role {role}: the issuer credential has no username; the role expires at {expiry} and cannot log in after that"
            ),
        ));
    };
    let control = match session::connect(
        &r.target,
        user,
        material.secret.expose(),
        SessionKind::Control,
        0,
    )
    .await
    {
        Ok(c) => c,
        Err(_) => {
            return LevelReport::failed(bi(
                format!(
                    "无法连接数据库撤销临时角色 {role}（已保留，稍后重试）；该角色将于 {expiry} 到期，到期后无法再登录，但已有会话可能仍在运行"
                ),
                format!(
                    "Could not reach the database to revoke temporary role {role} (kept for retry); it expires at {expiry} and cannot log in after that, but existing sessions may still run"
                ),
            ));
        }
    };
    let report = async {
        // 1. terminate the role's sessions (requires pg_signal_backend or membership).
        let terminate_ok = control
            .client
            .query(
                "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE usename = $1",
                &[role],
            )
            .await
            .is_ok();
        // 2. wait (bounded) until no backend of the role remains; None = could not count.
        let mut remaining: Option<i64> = None;
        for _ in 0..30 {
            match control
                .client
                .query_one(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename = $1",
                    &[role],
                )
                .await
            {
                Ok(row) => {
                    let n: i64 = row.get(0);
                    remaining = Some(n);
                    if n == 0 {
                        break;
                    }
                }
                Err(_) => {
                    remaining = None;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // 3. drop the role.
        let drop_err = control
            .client
            .batch_execute(&format!("DROP ROLE IF EXISTS {}", quote_ident(role)))
            .await
            .err();
        // 4. verify.
        let exists = control
            .client
            .query_one(
                "SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = $1",
                &[role],
            )
            .await
            .map(|row| row.get::<_, i64>(0) > 0);
        let hint_zh = if terminate_ok { "" } else { "（签发角色缺少终止会话的权限 pg_signal_backend）" };
        let hint_en = if terminate_ok { "" } else { " (the issuer lacks pg_signal_backend)" };
        match (exists, drop_err) {
            (Ok(false), _) if remaining == Some(0) => LevelReport::done(),
            (Ok(false), _) => LevelReport::pending(match remaining {
                Some(n) => bi(
                    format!("临时角色 {role} 已删除，但仍有 {n} 个会话未能确认终止{hint_zh}"),
                    format!("Temporary role {role} was dropped, but {n} session(s) could not be confirmed terminated{hint_en}"),
                ),
                None => bi(
                    format!("临时角色 {role} 已删除，但无法确认其会话是否全部终止{hint_zh}"),
                    format!("Temporary role {role} was dropped, but its sessions could not be confirmed terminated{hint_en}"),
                ),
            }),
            (Ok(true), Some(e)) => {
                let dependent = e.code()
                    == Some(&tokio_postgres::error::SqlState::DEPENDENT_OBJECTS_STILL_EXIST);
                LevelReport::failed(if dependent {
                    bi(
                        format!("未能删除临时角色 {role}（该角色仍拥有数据库对象）；该角色将于 {expiry} 到期，到期后无法再登录"),
                        format!("Could not drop temporary role {role} (it still owns database objects); it expires at {expiry} and cannot log in after that"),
                    )
                } else {
                    bi(
                        format!("未能删除临时角色 {role}（数据库拒绝删除）；该角色将于 {expiry} 到期，到期后无法再登录"),
                        format!("Could not drop temporary role {role} (the database refused); it expires at {expiry} and cannot log in after that"),
                    )
                })
            }
            (Ok(true), None) => LevelReport::failed(bi(
                format!("临时角色 {role} 删除后仍然存在；该角色将于 {expiry} 到期"),
                format!("Temporary role {role} still exists after DROP ROLE; it expires at {expiry}"),
            )),
            (Err(_), _) => LevelReport::pending(bi(
                format!("已请求删除临时角色 {role}，但无法确认结果"),
                format!("Requested dropping temporary role {role}, but the result could not be confirmed"),
            )),
        }
    }
    .await;
    control.close();
    report
}
