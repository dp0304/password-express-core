// SPDX-License-Identifier: Apache-2.0
//! Expiry sweeper and startup recovery.
//!
//! The sweeper only ever moves things toward *less* access: pending approvals → expired
//! (never approved), grants → expired (credentials dropped), pairings → expired, old
//! results purged. Every read path also applies expiry lazily, so correctness never
//! depends on the sweeper's timing.

use std::sync::{Arc, Weak};

use aipass_types::Timestamp;
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::ids::{ConnectionId, GrantId};
use aipass_types::models::GrantStatus;
use rusqlite::params;
use serde_json::json;
use tokio::task::JoinHandle;

use super::Broker;
use super::connections::expire_pairing;
use crate::audit::{self, Audit};
use crate::db::{enc, unix};
use crate::error::SResult;
use crate::notify::BrokerEvent;
use crate::store::StoredError;
use crate::types::SweepReport;

/// Handle of the background sweeper; aborts the task on drop.
#[derive(Debug)]
pub struct BackgroundTask {
    handle: JoinHandle<()>,
}

impl BackgroundTask {
    /// Stop the sweeper.
    pub fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl Broker {
    /// Start the periodic sweeper (`sweep_interval`). Holds only a weak reference, so it
    /// stops when the broker is dropped.
    pub fn spawn_background(self: &Arc<Self>) -> BackgroundTask {
        let weak: Weak<Broker> = Arc::downgrade(self);
        let every = self.cfg.sweep_interval;
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let Some(b) = weak.upgrade() else { break };
                if let Err(e) = b.sweep().await {
                    tracing::warn!(code = %e.code, "broker sweep failed");
                }
            }
        });
        BackgroundTask { handle }
    }

    /// One sweep pass (public so embedders and tests can drive it deterministically).
    pub async fn sweep(&self) -> Result<SweepReport, ApiError> {
        let approvals_expired = self.expire_due_approvals().await?;
        let now = self.now();

        // Grants past expires_at.
        let expired: Vec<GrantId> = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut stmt = tx.prepare(
                    "SELECT grant_id, resource_id FROM grants WHERE status IN ('active', 'exhausted') AND expires_at <= ?1",
                )?;
                let rows: Vec<(String, String)> = stmt
                    .query_map(params![unix(&now)], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                drop(stmt);
                let mut out = Vec::new();
                for (gid, rid) in rows {
                    let gid = GrantId::parse(&gid)?;
                    let rid = aipass_types::ids::ResourceId::parse(&rid)?;
                    tx.execute("UPDATE grants SET status = 'expired' WHERE grant_id = ?1", params![gid.as_str()])?;
                    audit::append(&tx, now, Audit::new("system", "grant.expired").grant(&gid).resource(&rid).outcome("expired"))?;
                    out.push(gid);
                }
                tx.commit()?;
                Ok(out)
            })
            .await?;
        for g in &expired {
            for (_, f) in self.inflight_for_grant(g) {
                if !f.started.load(std::sync::atomic::Ordering::SeqCst) {
                    f.cancel_with(Some(ErrorCode::GrantExpired));
                }
            }
            self.maybe_drop_credential(g).await;
            self.emit(BrokerEvent::GrantUpdated {
                grant_id: g.clone(),
                status: GrantStatus::Expired,
            });
        }

        // Pairings, throttles, nonces, relay replay cache, old results.
        let retention = i64::try_from(self.cfg.result_retention.as_secs()).unwrap_or(i64::MAX / 4);
        let (pairings_expired, results_purged) = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut stmt = tx.prepare("SELECT connection_id FROM pairings WHERE status = 'pending' AND expires_at <= ?1")?;
                let conns: Vec<String> = stmt
                    .query_map(params![unix(&now)], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                drop(stmt);
                for cid in &conns {
                    expire_pairing(&tx, &ConnectionId::parse(cid)?, &now)?;
                }
                tx.execute(
                    "DELETE FROM denials WHERE denied_at <= ?1",
                    params![unix(&now) - super::operations::DENIAL_THROTTLE_SECS],
                )?;
                tx.execute("DELETE FROM nonces WHERE expires_at <= ?1", params![unix(&now)])?;
                tx.execute(
                    "DELETE FROM relay_seen WHERE seen_at <= ?1",
                    params![unix(&now) - aipass_types::relay::MESSAGE_TTL_SECS - 3600],
                )?;
                let purged = tx.execute(
                    "UPDATE operations SET result = NULL WHERE result IS NOT NULL AND updated_at <= ?1",
                    params![unix(&now).saturating_sub(retention)],
                )?;
                tx.commit()?;
                Ok((conns.len() as u64, purged as u64))
            })
            .await?;
        Ok(SweepReport {
            approvals_expired,
            grants_expired: expired.len() as u64,
            pairings_expired,
            results_purged,
        })
    }
}

/// Startup recovery: executor memory (credentials, running work) did not survive the
/// restart, so the database is brought in line conservatively.
pub(crate) fn recover_after_restart(c: &mut rusqlite::Connection, now: &Timestamp) -> SResult<()> {
    let tx = c.transaction()?;
    let unknown = StoredError::from_api(&ApiError::new(ErrorCode::UpstreamOutcomeUnknown).with_message(
        "代理服务在操作运行中重启，外部服务可能已执行",
        "The broker restarted while this operation was running; the external service may have executed it.",
    ));
    let restarted = StoredError::from_api(&ApiError::new(ErrorCode::Internal).with_message(
        "代理服务重启，操作未执行",
        "The broker restarted before this operation ran.",
    ));
    let running = tx.execute(
        "UPDATE operations SET status = 'unknown', side_effects = 'possible', error = ?2, normalized = NULL, updated_at = ?1 WHERE status = 'running'",
        params![unix(now), enc(&unknown)?],
    )?;
    let queued = tx.execute(
        "UPDATE operations SET status = 'failed', error = ?2, normalized = NULL, updated_at = ?1 WHERE status IN ('authorized', 'received', 'policy_checked')",
        params![unix(now), enc(&restarted)?],
    )?;
    // Reserved rows of interrupted runs count as used (conservative); credentials are gone.
    tx.execute(
        "UPDATE grants SET used_rows = used_rows + reserved_rows, reserved_rows = 0 WHERE reserved_rows > 0",
        [],
    )?;
    let creds = tx.execute(
        "UPDATE grants SET credential_state = 'none' WHERE credential_state = 'installed'",
        [],
    )?;
    if running + queued + creds > 0 {
        audit::append(
            &tx,
            *now,
            Audit::new("system", "broker.recovered").detail(json!({
                "running_marked_unknown": running,
                "queued_marked_failed": queued,
                "credentials_reset": creds,
            })),
        )?;
    }
    tx.commit()?;
    Ok(())
}
