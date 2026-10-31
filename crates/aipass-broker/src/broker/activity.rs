// SPDX-License-Identifier: Apache-2.0
//! Read models for trusted clients: activity summary, state snapshot, executors, health,
//! audit log. Nothing here returns operation result bodies.

use aipass_types::Timestamp;
use aipass_types::error::{ApiError, Lang, Localized};
use aipass_types::ids::{ConnectionId, ResourceId};
use aipass_types::models::{
    ActivitySummary, Anomaly, AuditResponse, AuditVerifyResponse, ExecutorInfo, ExecutorsResponse,
    GrantStatus, HealthResponse, ProtectionLevel,
};
use aipass_types::relay::StateSnapshot;
use rusqlite::params;

use super::Broker;
use super::operations::operation_metadata;
use crate::audit;
use crate::db::{u, unix};
use crate::store;

impl Broker {
    /// `GET /v1/executors` — registered executors with live state, plus known-but-absent
    /// ones (reported offline).
    pub async fn list_executors(&self) -> Result<ExecutorsResponse, ApiError> {
        let mut known = self.db.call(|c| store::list_executor_infos(c)).await?;
        let mut out: Vec<ExecutorInfo> = Vec::new();
        for slot in self.executor_slots() {
            let mut info = slot.backend.info();
            info.online = slot.is_online();
            known.retain(|k| k.executor_id != info.executor_id);
            out.push(info);
        }
        for mut k in known {
            k.online = false;
            out.push(k);
        }
        out.sort_by(|a, b| a.executor_id.cmp(&b.executor_id));
        Ok(ExecutorsResponse { executors: out })
    }

    /// `GET /v1/health`. `protection_level` is the weakest among registered executors
    /// (`compatible` when there are none) — never overstated.
    pub fn health(&self) -> HealthResponse {
        let slots = self.executor_slots();
        let executor_online = slots.iter().any(|s| s.is_online());
        let protection_level = if !slots.is_empty()
            && slots
                .iter()
                .all(|s| s.backend.info().protection_level == ProtectionLevel::Isolated)
        {
            ProtectionLevel::Isolated
        } else {
            ProtectionLevel::Compatible
        };
        HealthResponse {
            status: "ok".into(),
            version: self.cfg.version.clone(),
            executor_online,
            protection_level,
        }
    }

    /// `GET /v1/audit?after_seq=&limit=`.
    pub async fn audit_events(&self, after_seq: u64, limit: u64) -> Result<AuditResponse, ApiError> {
        self.db.call(move |c| audit::list(c, after_seq, limit)).await
    }

    /// `GET /v1/audit/verify` — recompute the hash chain.
    pub async fn verify_audit(&self) -> Result<AuditVerifyResponse, ApiError> {
        self.db.call(|c| audit::verify(c)).await
    }

    /// `GET /v1/activity/summary?since=` (default: last 24 h).
    pub async fn activity_summary(&self, since: Option<Timestamp>) -> Result<ActivitySummary, ApiError> {
        let now = self.now();
        let since = since.unwrap_or_else(|| aipass_types::time::add_secs(&now, -86_400));
        let offline: Vec<ExecutorInfo> = self
            .list_executors()
            .await?
            .executors
            .into_iter()
            .filter(|e| !e.online)
            .collect();
        let mut summary = self
            .db
            .call(move |c| {
                let count = |sql: &str, args: &[&dyn rusqlite::ToSql]| -> crate::error::SResult<u64> {
                    let n: i64 = c.query_row(sql, args, |r| r.get(0))?;
                    Ok(u(n))
                };
                let s = unix(&since);
                let n = unix(&now);
                let pending_approvals = count("SELECT COUNT(*) FROM approvals WHERE status = 'pending' AND expires_at > ?1", &[&n])?;
                let active_grants = count("SELECT COUNT(*) FROM grants WHERE status = 'active' AND expires_at > ?1", &[&n])?;
                let recent_operations = count("SELECT COUNT(*) FROM operations WHERE created_at >= ?1", &[&s])?;
                let auto_approved_count = audit::count_since(c, "rule.auto_approved", since)?;
                let mut anomalies = Vec::new();

                // Repeated denials / throttling per connection.
                let mut stmt = c.prepare(
                    "SELECT body FROM audit WHERE ts >= ?1 AND action IN ('approval.denied', 'operation.rejected', 'access.rejected') ORDER BY seq DESC LIMIT 2000",
                )?;
                let rows = stmt.query_map(params![s], |r| r.get::<_, String>(0))?;
                let mut per_conn: std::collections::BTreeMap<String, (u64, u64, Timestamp)> = Default::default();
                for body in rows {
                    let ev: aipass_types::models::AuditEvent = crate::db::dec(&body?)?;
                    let conn_id = if ev.action == "approval.denied" {
                        None
                    } else {
                        Some(ev.actor.clone())
                    };
                    if let Some(cid) = conn_id {
                        let e = per_conn.entry(cid).or_insert((0, 0, ev.ts));
                        if ev.outcome == "throttled" {
                            e.1 += 1;
                        } else {
                            e.0 += 1;
                        }
                    }
                }
                for (cid, (denied, throttled, at)) in per_conn {
                    if throttled > 0 {
                        anomalies.push(Anomaly {
                            kind: "repeated_requests_throttled".into(),
                            summary: Localized::new(
                                format!("该 AI 连接的请求被限流 {throttled} 次（拒绝后仍持续请求）"),
                                format!("Requests from this AI connection were throttled {throttled} time(s) (kept asking after a denial)"),
                            ),
                            at,
                            connection_id: ConnectionId::parse(&cid).ok(),
                            resource_id: None,
                        });
                    } else if denied >= 5 {
                        anomalies.push(Anomaly {
                            kind: "repeated_rejections".into(),
                            summary: Localized::new(
                                format!("该 AI 连接有 {denied} 次请求被拒绝"),
                                format!("{denied} requests from this AI connection were rejected"),
                            ),
                            at,
                            connection_id: ConnectionId::parse(&cid).ok(),
                            resource_id: None,
                        });
                    }
                }
                // Budget exhaustion, unknown outcomes, partial revocations.
                let mut stmt = c.prepare(
                    "SELECT body FROM audit WHERE ts >= ?1 AND (action IN ('grant.exhausted', 'operation.unknown') OR (action = 'grant.revoked' AND json_extract(body, '$.outcome') = 'partial')) ORDER BY seq DESC LIMIT 200",
                )?;
                let rows = stmt.query_map(params![s], |r| r.get::<_, String>(0))?;
                for body in rows {
                    let ev: aipass_types::models::AuditEvent = crate::db::dec(&body?)?;
                    let (kind, zh, en) = match ev.action.as_str() {
                        "grant.exhausted" => ("budget_exhausted", "一项授权的额度已用完", "A grant used up its budget"),
                        "operation.unknown" => ("outcome_unknown", "一个操作结果未知，外部服务可能已执行", "An operation's outcome is unknown; the external service may have executed it"),
                        _ => ("revocation_incomplete", "撤销部分失败或待处理，请查看详情", "A revocation is partially failed or pending; see details"),
                    };
                    anomalies.push(Anomaly {
                        kind: kind.into(),
                        summary: Localized::new(zh, en),
                        at: ev.ts,
                        connection_id: None,
                        resource_id: ev.resource_id.clone(),
                    });
                }
                Ok(ActivitySummary {
                    pending_approvals,
                    active_grants,
                    recent_operations,
                    auto_approved_count,
                    anomalies,
                })
            })
            .await?;
        for e in offline {
            summary.anomalies.push(Anomaly {
                kind: "executor_offline".into(),
                summary: Localized::new(format!("执行设备离线：{}", e.name), format!("Executor offline: {}", e.name)),
                at: e.last_heartbeat_at.unwrap_or(now),
                connection_id: None,
                resource_id: None::<ResourceId>,
            });
        }
        Ok(summary)
    }

    /// `state.snapshot` for trusted devices: connections, usable/recent grants,
    /// executors, pending approvals, the 50 most recent operations (metadata only) and the
    /// activity summary.
    pub async fn state_snapshot(&self) -> Result<StateSnapshot, ApiError> {
        let connections = self.list_connections().await?.connections;
        let mut grants = self.list_grants(None).await?.grants;
        grants.retain(|g| matches!(g.status, GrantStatus::Active | GrantStatus::Exhausted) || g.revoked_at.is_some());
        grants.truncate(200);
        let executors = self.list_executors().await?.executors;
        let pending_approvals = self
            .list_approvals(Some(aipass_types::models::ApprovalStatus::Pending))
            .await?
            .approvals;
        let ops = self
            .db
            .call(|c| store::query_ops(c, "1 = 1 ORDER BY created_at DESC, operation_id DESC LIMIT 50", &[]))
            .await?;
        let recent_operations = ops.into_iter().map(|r| operation_metadata(r, Lang::ZhCn)).collect();
        let activity_summary = self.activity_summary(None).await?;
        Ok(StateSnapshot {
            connections,
            grants,
            executors,
            pending_approvals,
            recent_operations,
            activity_summary,
        })
    }
}
