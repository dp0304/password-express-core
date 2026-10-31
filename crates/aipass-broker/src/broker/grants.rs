// SPDX-License-Identifier: Apache-2.0
//! Grants: listing, credential installation, release, and three-level revocation
//! (CONTRACTS §6.2, design doc §8.4):
//!
//! 1. `stop_access` — reject new and queued operations;
//! 2. `end_sessions` — also cancel running operations, close connector sessions and drop
//!    the credential at the executor;
//! 3. `revoke_upstream` — also revoke upstream leases/tokens where the connector supports it.
//!
//! The report is honest: a level is `done` only when it really completed; executor calls
//! that time out or fail are `pending` / `failed`, and the UI may only say "全部已收回"
//! when every level is `done` / `not_applicable`.

use std::sync::atomic::Ordering;
use std::time::Instant;

use aipass_crypto::SealedBox;
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::exec::CredentialAad;
use aipass_types::ids::{GrantId, LeaseId};
use aipass_types::models::{
    Grant, GrantStatus, GrantsResponse, Lease, LevelReport, LevelStatus, ReleaseResponse,
    Resource, RevocationLevel, RevocationReport,
};
use rusqlite::params;
use serde_json::json;

use super::Broker;
use crate::audit::{self, Audit};
use crate::db::{enc, enum_parse, enum_str, ts, unix};
use crate::notify::BrokerEvent;
use crate::principal::{Actor, ConnectionPrincipal};
use crate::store::{self, CredState, GrantRow};

impl Broker {
    /// `GET /v1/grants?status=` (expiry applied lazily to the view).
    pub async fn list_grants(&self, status: Option<GrantStatus>) -> Result<GrantsResponse, ApiError> {
        let now = self.now();
        let rows = self
            .db
            .call(|c| store::query_grants(c, "1 = 1 ORDER BY created_at DESC LIMIT 1000", &[]))
            .await?;
        let grants = rows
            .into_iter()
            .map(|mut r| {
                if matches!(r.grant.status, GrantStatus::Active | GrantStatus::Exhausted) && r.grant.expires_at <= now {
                    r.grant.status = GrantStatus::Expired;
                }
                r.grant
            })
            .filter(|g| status.is_none_or(|s| s == g.status))
            .collect();
        Ok(GrantsResponse { grants })
    }

    /// One grant.
    pub async fn get_grant(&self, id: &GrantId) -> Result<Grant, ApiError> {
        let id = id.clone();
        self.db
            .call(move |c| Ok(store::get_grant(c, &id)?.map(|g| g.grant)))
            .await?
            .ok_or_else(ApiError::not_found)
    }

    // ------------------------------------------------------------- credentials

    /// Install the credential of a fresh grant at its executor: the sealed envelope from
    /// the approving device if present, else the in-process [`crate::CredentialSource`].
    /// Returns the resulting state; failures are audited, never echoed.
    pub(crate) async fn install_credential_for(
        &self,
        row: &GrantRow,
        resource: &Resource,
        envelope: Option<(&SealedBox, CredentialAad)>,
    ) -> CredState {
        let grant_id = row.grant.grant_id.clone();
        let Some(slot) = self.executor_slot(&row.grant.executor_id) else {
            return CredState::None;
        };
        let result = match envelope {
            Some((sealed, aad)) => Some(slot.backend.install_credential(grant_id.as_str(), sealed, &aad).await),
            None => match self.credential_source() {
                Some(src) => match src.material_for_grant(&row.grant, resource).await {
                    Ok(Some(material)) => Some(slot.backend.install_plain_credential(grant_id.as_str(), material).await),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                },
                None => None,
            },
        };
        let (state, outcome) = match &result {
            Some(Ok(())) => (CredState::Installed, Some(("credential.installed", None))),
            Some(Err(e)) => (CredState::Failed, Some(("credential.install_failed", Some(e.code)))),
            None => (CredState::None, None),
        };
        let now = self.now();
        let gid = grant_id.clone();
        let rid = row.grant.resource_id.clone();
        let _ = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                store::set_cred_state(&tx, &gid, state)?;
                if let Some((action, code)) = outcome {
                    let mut a = Audit::new("system", action).grant(&gid).resource(&rid);
                    if let Some(code) = code {
                        a = a.error(code);
                    }
                    audit::append(&tx, now, a)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await;
        state
    }

    /// Drop a grant's credential at its executor once nothing runs under it any more and
    /// it can no longer be used. The state becomes `dropped` only when the executor
    /// confirmed the drop in time — an offline / slow executor leaves it for a later
    /// attempt (sweeper, next revocation) instead of claiming it is gone.
    pub(crate) async fn maybe_drop_credential(&self, grant_id: &GrantId) {
        if !self.inflight_for_grant(grant_id).is_empty() {
            return;
        }
        let gid = grant_id.clone();
        let Ok(Some(row)) = self.db.call(move |c| store::get_grant(c, &gid)).await else {
            return;
        };
        let usable = row.grant.status == GrantStatus::Active && row.grant.expires_at > self.now();
        if usable || matches!(row.cred, CredState::Dropped | CredState::None) {
            return;
        }
        self.drop_credential_confirmed(&row).await;
    }

    /// Drop the credential at the executor; `dropped` is recorded only when confirmed.
    async fn drop_credential_confirmed(&self, row: &GrantRow) -> bool {
        let Some(slot) = self.executor_slot(&row.grant.executor_id) else {
            return false;
        };
        let id = row.grant.grant_id.clone();
        if tokio::time::timeout(self.cfg.revoke_step_timeout, slot.backend.drop_credential(id.as_str()))
            .await
            .is_err()
        {
            return false;
        }
        self.db.call(move |c| store::set_cred_state(c, &id, CredState::Dropped)).await.is_ok()
    }

    // ------------------------------------------------------------- release (C)

    /// `POST /v1/access/grants/{id}/release` — the connection ends its own grant. Queued
    /// operations are cancelled; the credential is dropped once running ones finish.
    pub async fn release_grant(&self, p: &ConnectionPrincipal, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        let conn = self.active_connection(p).await?;
        let now = self.now();
        let (gid, cid) = (id.clone(), conn.connection_id.clone());
        let status = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let row = store::get_grant(&tx, &gid)?
                    .filter(|g| g.grant.connection_id == cid)
                    .ok_or_else(ApiError::not_found)?;
                let status = if store::set_grant_status(&tx, &gid, &[GrantStatus::Active, GrantStatus::Exhausted], GrantStatus::Released)? {
                    audit::append(&tx, now, Audit::new(cid.as_str(), "grant.released").grant(&gid).resource(&row.grant.resource_id))?;
                    GrantStatus::Released
                } else {
                    row.grant.status
                };
                tx.commit()?;
                Ok(status)
            })
            .await?;
        for (_, f) in self.inflight_for_grant(id) {
            if !f.started.load(Ordering::SeqCst) {
                f.cancel_with(Some(ErrorCode::GrantRevoked));
            }
        }
        self.maybe_drop_credential(id).await;
        self.emit(BrokerEvent::GrantUpdated { grant_id: id.clone(), status });
        Ok(ReleaseResponse { grant_id: id.clone(), status })
    }

    // ------------------------------------------------------------- revocation (D, A)

    /// Revoke a grant at `level` (each higher level includes the lower ones) and return an
    /// honest [`RevocationReport`]. In-process target: ≤ 5 s (A09).
    pub async fn revoke_grant(&self, actor: &Actor, id: &GrantId, level: RevocationLevel) -> Result<RevocationReport, ApiError> {
        let started = Instant::now();
        let row = self
            .stop_access(actor, std::slice::from_ref(id), level)
            .await?
            .pop()
            .ok_or_else(ApiError::not_found)?;
        self.finish_revocation(actor, row, level, started).await
    }

    /// Revoke several grants (revoke-all, device / resource / policy revocation).
    ///
    /// Level 1 is applied to **every** grant in one transaction before any executor call,
    /// so no grant stays usable while another one's executor or upstream is slow (A09);
    /// the executor / upstream steps then run concurrently. A failure finishing one grant
    /// is reported in its own report and never stops the others.
    pub(crate) async fn revoke_grants(&self, actor: &Actor, ids: Vec<GrantId>, level: RevocationLevel) -> Result<Vec<RevocationReport>, ApiError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let started = Instant::now();
        let rows = self.stop_access(actor, &ids, level).await?;
        let finishing = rows.into_iter().map(|row| async move {
            let gid = row.grant.grant_id.clone();
            match self.finish_revocation(actor, row, level, started).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(grant_id = %gid.as_str(), code = ?e.code, "revocation bookkeeping failed after stop_access");
                    RevocationReport {
                        grant_id: gid,
                        stop_access: LevelReport::done(),
                        end_sessions: LevelReport::pending("撤销未完成，请重试 / revocation incomplete; retry"),
                        revoke_upstream: LevelReport::pending("撤销未完成，请重试 / revocation incomplete; retry"),
                        completed_at: None,
                    }
                }
            }
        });
        Ok(futures::future::join_all(finishing).await)
    }

    /// Level 1 for a set of grants, atomically: `status = 'revoked'` (no new reservation
    /// can succeed), audit, then cancel their queued operations. Unknown ids are skipped.
    async fn stop_access(&self, actor: &Actor, ids: &[GrantId], level: RevocationLevel) -> Result<Vec<GrantRow>, ApiError> {
        let now = self.now();
        let (gids, act) = (ids.to_vec(), actor.audit_name());
        let rows = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut rows = Vec::with_capacity(gids.len());
                for gid in &gids {
                    let Some(row) = store::get_grant(&tx, gid)? else {
                        continue;
                    };
                    if row.grant.status != GrantStatus::Revoked {
                        tx.execute(
                            "UPDATE grants SET status = 'revoked', revoked_at = ?2 WHERE grant_id = ?1",
                            params![gid.as_str(), unix(&now)],
                        )?;
                    }
                    audit::append(
                        &tx,
                        now,
                        Audit::new(act.clone(), "grant.revoke_started")
                            .grant(gid)
                            .resource(&row.grant.resource_id)
                            .detail(json!({ "level": enum_str(&level), "previous_status": enum_str(&row.grant.status) })),
                    )?;
                    rows.push(row);
                }
                tx.commit()?;
                Ok(rows)
            })
            .await?;
        for row in &rows {
            self.emit(BrokerEvent::GrantUpdated {
                grant_id: row.grant.grant_id.clone(),
                status: GrantStatus::Revoked,
            });
            for (_, f) in self.inflight_for_grant(&row.grant.grant_id) {
                if !f.started.load(Ordering::SeqCst) {
                    f.cancel_with(Some(ErrorCode::GrantRevoked));
                }
            }
        }
        Ok(rows)
    }

    /// Levels 2 and 3 for one grant whose access is already stopped, then the report.
    async fn finish_revocation(&self, actor: &Actor, row: GrantRow, level: RevocationLevel, started: Instant) -> Result<RevocationReport, ApiError> {
        let id = &row.grant.grant_id;
        let running: Vec<_> = self
            .inflight_for_grant(id)
            .into_iter()
            .filter(|(_, f)| f.started.load(Ordering::SeqCst))
            .collect();
        let stop_access = LevelReport::done();

        let slot = self.executor_slot(&row.grant.executor_id);
        let step = self.cfg.revoke_step_timeout;

        // Level 2 — end sessions. At `stop_access` with nothing running, ending sessions
        // disrupts nothing, so it is done too whenever a credential may be present:
        // the report then shows what really happened (BRK-07) instead of claiming
        // `not_applicable` for sessions that were never closed.
        let cred_present = if running.is_empty() && level < RevocationLevel::EndSessions {
            let gid = id.clone();
            !matches!(
                self.db.call(move |c| store::get_grant(c, &gid)).await?.map(|g| g.cred),
                Some(CredState::None | CredState::Dropped)
            )
        } else {
            true
        };
        let end_sessions = if level >= RevocationLevel::EndSessions || (running.is_empty() && cred_present) {
            for (op_id, f) in &running {
                f.cancel_with(Some(ErrorCode::GrantRevoked));
                if let Some(s) = &slot {
                    let _ = tokio::time::timeout(step, s.backend.cancel(op_id.as_str())).await;
                }
            }
            let backend_report = match &slot {
                Some(s) => {
                    let r = match tokio::time::timeout(step, s.backend.end_sessions(id.as_str())).await {
                        Ok(r) => r,
                        Err(_) => LevelReport::pending("执行设备未在时限内确认结束会话 / executor did not confirm in time"),
                    };
                    if self.drop_credential_confirmed(&row).await || r.status != LevelStatus::Done {
                        r
                    } else {
                        LevelReport::pending("执行设备未确认删除凭证 / executor did not confirm the credential drop")
                    }
                }
                None => LevelReport::pending("执行设备离线，待其上线后结束会话 / executor offline; sessions end when it reconnects"),
            };
            let mut still_running = 0usize;
            for (_, f) in &running {
                let remaining = step.saturating_sub(started.elapsed().min(step));
                if !f.wait_done(remaining.max(std::time::Duration::from_millis(200))).await {
                    still_running += 1;
                }
            }
            if still_running > 0 {
                LevelReport::pending(format!("{still_running} 个操作仍在停止中 / operation(s) still stopping"))
            } else {
                backend_report
            }
        } else if running.is_empty() {
            // Nothing was ever installed: no credential and no session to end.
            LevelReport::not_applicable()
        } else {
            LevelReport::pending(format!(
                "{} 个正在运行的操作将继续完成；如需立即中止请选择“结束活动会话” / {} running operation(s) will finish; choose end_sessions to stop them",
                running.len(),
                running.len()
            ))
        };

        // Level 3 — revoke upstream.
        let gid = id.clone();
        let leases = self.db.call(move |c| leases_for(c, &gid)).await?;
        let revoke_upstream = if level == RevocationLevel::RevokeUpstream {
            let r = match &slot {
                Some(s) => match tokio::time::timeout(step, s.backend.revoke_upstream(id.as_str())).await {
                    Ok(r) => r,
                    Err(_) => LevelReport::pending("上游撤销未在时限内完成 / upstream revocation did not finish in time"),
                },
                None => LevelReport::pending("执行设备离线，上游撤销待处理 / executor offline; upstream revocation pending"),
            };
            if !leases.is_empty() {
                let gid = id.clone();
                let st = r.status;
                let _ = self
                    .db
                    .call(move |c| {
                        c.execute(
                            "UPDATE leases SET revoke_status = ?2 WHERE grant_id = ?1",
                            params![gid.as_str(), enum_str(&st)],
                        )?;
                        Ok(())
                    })
                    .await;
            }
            r
        } else if leases.iter().any(|l| l.revoke_status != LevelStatus::Done) {
            LevelReport::pending("存在尚未撤销的上游租约 / upstream leases not yet revoked")
        } else {
            LevelReport::not_applicable()
        };

        let mut report = RevocationReport {
            grant_id: id.clone(),
            stop_access,
            end_sessions,
            revoke_upstream,
            completed_at: None,
        };
        if report.fully_revoked() {
            report.completed_at = Some(self.now());
        }
        let now = self.now();
        let (gid, rep, act, rid) = (id.clone(), report.clone(), actor.audit_name(), row.grant.resource_id.clone());
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "UPDATE grants SET revocation = ?2 WHERE grant_id = ?1",
                    params![gid.as_str(), enc(&rep)?],
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act, "grant.revoked")
                        .grant(&gid)
                        .resource(&rid)
                        .outcome(if rep.fully_revoked() { "ok" } else { "partial" })
                        .detail(json!({
                            "level": enum_str(&level),
                            "stop_access": enum_str(&rep.stop_access.status),
                            "end_sessions": enum_str(&rep.end_sessions.status),
                            "revoke_upstream": enum_str(&rep.revoke_upstream.status),
                            "elapsed_ms": elapsed_ms,
                        })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        self.emit(BrokerEvent::Revoked { report: report.clone() });
        Ok(report)
    }

    /// Revoke every usable grant approved by `device` (used when a device is revoked).
    pub(crate) async fn revoke_grants_approved_by(&self, actor: &Actor, device: &str) -> Result<Vec<RevocationReport>, ApiError> {
        let d = device.to_owned();
        let grants = self
            .db
            .call(move |c| store::query_grants(c, "approved_by = ?1 AND status IN ('active', 'exhausted')", &[&d]))
            .await?;
        self.revoke_grants(actor, grants.into_iter().map(|g| g.grant.grant_id).collect(), RevocationLevel::EndSessions)
            .await
    }

    // ------------------------------------------------------------- leases

    /// Record an upstream lease created by the executor (temporary role, token). Only the
    /// upstream reference is stored — never the secret.
    pub async fn record_lease(&self, lease: Lease) -> Result<(), ApiError> {
        if crate::redact::looks_secret(&lease.upstream_ref) {
            return Err(ApiError::invalid_request("upstream_ref 不能包含凭证", "upstream_ref must not contain credentials"));
        }
        let now = self.now();
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                if store::get_grant(&tx, &lease.grant_id)?.is_none() {
                    return Err(ApiError::not_found().into());
                }
                tx.execute(
                    "INSERT INTO leases (lease_id, grant_id, kind, upstream_ref, expires_at, revoke_status) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(lease_id) DO UPDATE SET revoke_status = excluded.revoke_status, expires_at = excluded.expires_at",
                    params![
                        lease.lease_id.as_str(),
                        lease.grant_id.as_str(),
                        lease.kind,
                        lease.upstream_ref,
                        unix(&lease.expires_at),
                        enum_str(&lease.revoke_status)
                    ],
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new("system", "lease.recorded")
                        .grant(&lease.grant_id)
                        .detail(json!({ "lease_id": lease.lease_id.as_str(), "kind": lease.kind })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Leases of a grant.
    pub async fn leases(&self, grant: &GrantId) -> Result<Vec<Lease>, ApiError> {
        let g = grant.clone();
        self.db.call(move |c| leases_for(c, &g)).await
    }
}

fn leases_for(c: &rusqlite::Connection, grant: &GrantId) -> crate::error::SResult<Vec<Lease>> {
    let mut stmt = c.prepare(
        "SELECT lease_id, grant_id, kind, upstream_ref, expires_at, revoke_status FROM leases WHERE grant_id = ?1 ORDER BY lease_id",
    )?;
    let rows = stmt.query_map(params![grant.as_str()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (lid, gid, kind, upstream_ref, exp, st) = r?;
        out.push(Lease {
            lease_id: LeaseId::parse(&lid)?,
            grant_id: GrantId::parse(&gid)?,
            kind,
            upstream_ref,
            expires_at: ts(exp),
            revoke_status: enum_parse(&st)?,
        });
    }
    Ok(out)
}
