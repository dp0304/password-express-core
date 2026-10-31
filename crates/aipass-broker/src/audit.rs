// SPDX-License-Identifier: Apache-2.0
//! Hash-chained audit log (CONTRACTS §6.1):
//! `hash = b64u(SHA-256(prev_hash_bytes ‖ JCS(event minus hash)))`.
//!
//! Events are appended inside the same database transaction as the state change they
//! describe, so the log and the state never disagree. `detail` holds IDs, digests, counts,
//! error codes and redacted parameter summaries — never credentials, never result bodies.
//!
//! Limitation (documented in the README): a chain proves that no *stored* event was
//! altered, removed from the middle or reordered; truncating the newest events is only
//! detectable against a previously recorded `head_hash` (e.g. kept by a trusted device).

use aipass_types::Timestamp;
use aipass_types::error::ErrorCode;
use aipass_types::ids::{EventId, GrantId, OperationId, ResourceId};
use aipass_types::models::{AuditEvent, AuditResponse, AuditVerifyResponse};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::db::{dec, enc, i, unix};
use crate::error::SResult;

/// Maximum page size of `GET /v1/audit`.
pub const MAX_AUDIT_PAGE: u64 = 1000;

/// A pending audit record.
#[derive(Debug, Clone)]
pub(crate) struct Audit {
    pub actor: String,
    pub action: &'static str,
    pub resource_id: Option<ResourceId>,
    pub operation_id: Option<OperationId>,
    pub grant_id: Option<GrantId>,
    pub outcome: &'static str,
    pub error_code: Option<ErrorCode>,
    pub detail: Value,
}

impl Audit {
    pub(crate) fn new(actor: impl Into<String>, action: &'static str) -> Self {
        Self {
            actor: actor.into(),
            action,
            resource_id: None,
            operation_id: None,
            grant_id: None,
            outcome: "ok",
            error_code: None,
            detail: json!({}),
        }
    }
    pub(crate) fn resource(mut self, r: &ResourceId) -> Self {
        self.resource_id = Some(r.clone());
        self
    }
    pub(crate) fn operation(mut self, o: &OperationId) -> Self {
        self.operation_id = Some(o.clone());
        self
    }
    pub(crate) fn grant(mut self, g: &GrantId) -> Self {
        self.grant_id = Some(g.clone());
        self
    }
    pub(crate) fn outcome(mut self, o: &'static str) -> Self {
        self.outcome = o;
        self
    }
    pub(crate) fn error(mut self, c: ErrorCode) -> Self {
        self.error_code = Some(c);
        if self.outcome == "ok" {
            self.outcome = "error";
        }
        self
    }
    pub(crate) fn detail(mut self, d: Value) -> Self {
        self.detail = d;
        self
    }
}

/// Append one event (call inside the transaction of the state change).
pub(crate) fn append(c: &Connection, now: Timestamp, a: Audit) -> SResult<AuditEvent> {
    let last: Option<(i64, String)> = c
        .query_row(
            "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (seq, prev_hash) = match last {
        Some((s, h)) => (s + 1, h),
        None => (1, String::new()),
    };
    let detail = match a.detail {
        Value::Object(_) => a.detail,
        other => json!({ "value": other }),
    };
    let mut ev = AuditEvent {
        seq: crate::db::u(seq),
        event_id: EventId::generate(),
        ts: now,
        actor: a.actor,
        action: a.action.to_owned(),
        resource_id: a.resource_id,
        operation_id: a.operation_id,
        grant_id: a.grant_id,
        outcome: a.outcome.to_owned(),
        error_code: a.error_code,
        detail,
        prev_hash,
        hash: String::new(),
    };
    ev.seal()?;
    c.execute(
        "INSERT INTO audit (seq, event_id, ts, action, body, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            seq,
            ev.event_id.as_str(),
            unix(&ev.ts),
            ev.action,
            enc(&ev)?,
            ev.hash
        ],
    )?;
    Ok(ev)
}

/// Head hash (`""` when empty).
pub(crate) fn head_hash(c: &Connection) -> SResult<String> {
    Ok(c.query_row(
        "SELECT hash FROM audit ORDER BY seq DESC LIMIT 1",
        [],
        |r| r.get(0),
    )
    .optional()?
    .unwrap_or_default())
}

/// Page of events after `after_seq`.
pub(crate) fn list(c: &Connection, after_seq: u64, limit: u64) -> SResult<AuditResponse> {
    let limit = limit.clamp(1, MAX_AUDIT_PAGE);
    let mut stmt = c.prepare("SELECT body FROM audit WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2")?;
    let rows = stmt.query_map(params![i(after_seq), i(limit)], |r| r.get::<_, String>(0))?;
    let mut events = Vec::new();
    for body in rows {
        events.push(dec::<AuditEvent>(&body?)?);
    }
    Ok(AuditResponse {
        events,
        head_hash: head_hash(c)?,
    })
}

/// Recompute the whole chain.
pub(crate) fn verify(c: &Connection) -> SResult<AuditVerifyResponse> {
    let mut stmt = c.prepare("SELECT seq, ts, action, body, hash FROM audit ORDER BY seq ASC")?;
    let mut rows = stmt.query([])?;
    let mut expected_prev = String::new();
    let mut expected_seq: i64 = 1;
    let mut checked: u64 = 0;
    let mut valid = true;
    let mut head = String::new();
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let row_ts: i64 = row.get(1)?;
        let action: String = row.get(2)?;
        let body: String = row.get(3)?;
        let hash: String = row.get(4)?;
        head = hash.clone();
        checked += 1;
        if !valid {
            continue;
        }
        let ok = match serde_json::from_str::<AuditEvent>(&body) {
            Ok(ev) => {
                seq == expected_seq
                    && i(ev.seq) == seq
                    && ev.hash == hash
                    && ev.action == action
                    && unix(&ev.ts) == row_ts
                    && ev.verify(&expected_prev)
            }
            Err(_) => false,
        };
        if !ok {
            tracing::warn!(seq, "audit chain verification failed");
            valid = false;
        }
        expected_prev = hash;
        expected_seq = seq + 1;
    }
    Ok(AuditVerifyResponse {
        valid,
        events_checked: checked,
        head_hash: head,
    })
}

/// Count events of `action` since `since`.
pub(crate) fn count_since(c: &Connection, action: &str, since: Timestamp) -> SResult<u64> {
    let n: i64 = c.query_row(
        "SELECT COUNT(*) FROM audit WHERE action = ?1 AND ts >= ?2",
        params![action, unix(&since)],
        |r| r.get(0),
    )?;
    Ok(crate::db::u(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn chain_and_tamper() {
        let db = Db::open(None).unwrap();
        db.call_sync(|c| {
            let now = aipass_types::time::now();
            for n in 0..5 {
                append(
                    c,
                    now,
                    Audit::new("system", "test.event").detail(json!({ "n": n })),
                )?;
            }
            let v = verify(c)?;
            assert!(v.valid);
            assert_eq!(v.events_checked, 5);
            assert_eq!(v.head_hash, head_hash(c)?);
            let page = list(c, 2, 2)?;
            assert_eq!(page.events.len(), 2);
            assert_eq!(page.events[0].seq, 3);

            // tamper with a stored detail
            let body: String =
                c.query_row("SELECT body FROM audit WHERE seq = 3", [], |r| r.get(0))?;
            let tampered = body.replace("\"n\":2", "\"n\":7");
            c.execute(
                "UPDATE audit SET body = ?1 WHERE seq = 3",
                params![tampered],
            )?;
            assert!(!verify(c)?.valid);
            c.execute("UPDATE audit SET body = ?1 WHERE seq = 3", params![body])?;
            assert!(verify(c)?.valid);
            // delete from the middle
            c.execute("DELETE FROM audit WHERE seq = 2", [])?;
            assert!(!verify(c)?.valid);
            Ok(())
        })
        .unwrap();
    }
}
