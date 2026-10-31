// SPDX-License-Identifier: Apache-2.0
//! Row mapping and simple queries. All functions are synchronous and run inside
//! [`crate::db::Db::call`] closures (often inside one transaction).

use std::collections::BTreeSet;

use aipass_types::Timestamp;
use aipass_types::error::{ApiError, ErrorCode, ErrorObject, Lang, Localized};
use aipass_types::exec::NormalizedRequest;
use aipass_types::ids::{
    ApprovalRequestId, ConnectionId, DeviceId, EntryId, ExecutorId, GrantId, OperationId,
    PairingId, PolicyId, ProjectId, ResourceId,
};
use aipass_types::models::{
    AllowedProjects, AppConnection, ApprovalMode, ApprovalRequest, ApprovalStatus,
    ConnectionStatus, Grant, GrantScope, GrantStatus, GrantUsage, Limits, Operation,
    OperationResult, OperationStatus, PairStatus, Policy, PolicyStatus, Project, Resource,
    RevocationReport, SideEffects,
};
use aipass_types::vault::{DevicePublic, MemberStatus};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::db::{dec, enc, enum_parse, enum_str, i, ts, ts_opt, u, unix};
use crate::error::{SResult, StoreError};
use crate::types::TrustedDevice;

// ------------------------------------------------------------------------------------
// Errors as stored on operations (both languages kept; rendered per request)
// ------------------------------------------------------------------------------------

/// An [`ApiError`] as persisted on an operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StoredError {
    pub code: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Localized>,
    #[serde(default)]
    pub details: Map<String, Value>,
}

impl StoredError {
    pub(crate) fn from_api(e: &ApiError) -> Self {
        Self {
            code: e.code,
            message: e.message.clone(),
            details: e.details.clone(),
        }
    }
    pub(crate) fn to_api(&self) -> ApiError {
        ApiError {
            code: self.code,
            message: self.message.clone(),
            details: self.details.clone(),
            request_id: None,
        }
    }
    pub(crate) fn to_object(&self, lang: Lang) -> ErrorObject {
        self.to_api().to_object(lang)
    }
}

// ------------------------------------------------------------------------------------
// Connections, tokens, pairings
// ------------------------------------------------------------------------------------

pub(crate) struct ConnRow {
    pub conn: AppConnection,
    pub last_control_at: Option<i64>,
}

const CONN_COLS: &str = "connection_id, host_type, display_name, transport, status, public_key, allowed_projects, created_at, approved_at, approved_by, last_seen_at, last_control_at";

struct RawConn {
    id: String,
    host_type: String,
    display_name: String,
    transport: String,
    status: String,
    public_key: Option<String>,
    allowed: String,
    created_at: i64,
    approved_at: Option<i64>,
    approved_by: Option<String>,
    last_seen_at: Option<i64>,
    last_control_at: Option<i64>,
}

fn raw_conn(r: &Row<'_>) -> rusqlite::Result<RawConn> {
    Ok(RawConn {
        id: r.get(0)?,
        host_type: r.get(1)?,
        display_name: r.get(2)?,
        transport: r.get(3)?,
        status: r.get(4)?,
        public_key: r.get(5)?,
        allowed: r.get(6)?,
        created_at: r.get(7)?,
        approved_at: r.get(8)?,
        approved_by: r.get(9)?,
        last_seen_at: r.get(10)?,
        last_control_at: r.get(11)?,
    })
}

impl RawConn {
    fn into_row(self) -> SResult<ConnRow> {
        Ok(ConnRow {
            conn: AppConnection {
                connection_id: ConnectionId::parse(&self.id)?,
                host_type: enum_parse(&self.host_type)?,
                display_name: self.display_name,
                transport: enum_parse(&self.transport)?,
                status: enum_parse(&self.status)?,
                public_key: self.public_key,
                allowed_projects: dec(&self.allowed)?,
                created_at: ts(self.created_at),
                approved_at: ts_opt(self.approved_at),
                approved_by: self
                    .approved_by
                    .map(|d| DeviceId::parse(&d))
                    .transpose()?,
                last_seen_at: ts_opt(self.last_seen_at),
            },
            last_control_at: self.last_control_at,
        })
    }
}

pub(crate) fn get_connection(c: &Connection, id: &ConnectionId) -> SResult<Option<ConnRow>> {
    c.query_row(
        &format!("SELECT {CONN_COLS} FROM connections WHERE connection_id = ?1"),
        params![id.as_str()],
        raw_conn,
    )
    .optional()?
    .map(RawConn::into_row)
    .transpose()
}

pub(crate) fn list_connections(c: &Connection) -> SResult<Vec<AppConnection>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {CONN_COLS} FROM connections WHERE status != 'removed' ORDER BY created_at DESC, connection_id"
    ))?;
    let rows = stmt.query_map([], raw_conn)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?.into_row()?.conn);
    }
    Ok(out)
}

pub(crate) fn insert_connection(c: &Connection, conn: &AppConnection) -> SResult<()> {
    c.execute(
        &format!("INSERT INTO connections ({CONN_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)"),
        params![
            conn.connection_id.as_str(),
            enum_str(&conn.host_type),
            conn.display_name,
            enum_str(&conn.transport),
            enum_str(&conn.status),
            conn.public_key,
            enc(&conn.allowed_projects)?,
            unix(&conn.created_at),
            conn.approved_at.as_ref().map(unix),
            conn.approved_by.as_ref().map(|d| d.as_str().to_owned()),
            conn.last_seen_at.as_ref().map(unix),
        ],
    )?;
    Ok(())
}

pub(crate) fn save_connection(c: &Connection, conn: &AppConnection) -> SResult<()> {
    c.execute(
        "UPDATE connections SET status = ?2, allowed_projects = ?3, approved_at = ?4, approved_by = ?5, display_name = ?6 WHERE connection_id = ?1",
        params![
            conn.connection_id.as_str(),
            enum_str(&conn.status),
            enc(&conn.allowed_projects)?,
            conn.approved_at.as_ref().map(unix),
            conn.approved_by.as_ref().map(|d| d.as_str().to_owned()),
            conn.display_name,
        ],
    )?;
    Ok(())
}

pub(crate) fn connection_for_token(c: &Connection, hash: &str) -> SResult<Option<ConnectionId>> {
    let id: Option<String> = c
        .query_row(
            "SELECT connection_id FROM connection_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
            params![hash],
            |r| r.get(0),
        )
        .optional()?;
    Ok(id.map(|s| ConnectionId::parse(&s)).transpose()?)
}

pub(crate) struct PairingRow {
    pub pairing_id: PairingId,
    pub connection_id: ConnectionId,
    pub pairing_code: String,
    pub status: PairStatus,
    pub expires_at: Timestamp,
}

pub(crate) fn get_pairing(c: &Connection, id: &PairingId) -> SResult<Option<PairingRow>> {
    let raw: Option<(String, String, String, String, i64)> = c
        .query_row(
            "SELECT pairing_id, connection_id, pairing_code, status, expires_at FROM pairings WHERE pairing_id = ?1",
            params![id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    raw.map(|(p, cid, code, st, exp)| {
        Ok(PairingRow {
            pairing_id: PairingId::parse(&p)?,
            connection_id: ConnectionId::parse(&cid)?,
            pairing_code: code,
            status: enum_parse(&st)?,
            expires_at: ts(exp),
        })
    })
    .transpose()
}

pub(crate) fn pairing_for_connection(c: &Connection, id: &ConnectionId) -> SResult<Option<PairingRow>> {
    let pid: Option<String> = c
        .query_row(
            "SELECT pairing_id FROM pairings WHERE connection_id = ?1",
            params![id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    match pid {
        Some(p) => get_pairing(c, &PairingId::parse(&p)?),
        None => Ok(None),
    }
}

pub(crate) fn set_pairing_status(c: &Connection, conn: &ConnectionId, st: PairStatus) -> SResult<()> {
    c.execute(
        "UPDATE pairings SET status = ?2 WHERE connection_id = ?1 AND status = 'pending'",
        params![conn.as_str(), enum_str(&st)],
    )?;
    Ok(())
}

// ------------------------------------------------------------------------------------
// Projects & resources
// ------------------------------------------------------------------------------------

pub(crate) fn list_projects(c: &Connection) -> SResult<Vec<Project>> {
    let mut stmt = c.prepare("SELECT project_id, name FROM projects ORDER BY created_at, project_id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (id, name) = r?;
        out.push(Project {
            project_id: ProjectId::parse(&id)?,
            name,
        });
    }
    Ok(out)
}

pub(crate) fn project_exists(c: &Connection, id: &ProjectId) -> SResult<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM projects WHERE project_id = ?1",
        params![id.as_str()],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

pub(crate) struct ResourceRow {
    pub resource: Resource,
    pub entry_conflict: bool,
}

pub(crate) fn get_resource(c: &Connection, id: &ResourceId) -> SResult<Option<ResourceRow>> {
    let raw: Option<(String, i64)> = c
        .query_row(
            "SELECT body, entry_conflict FROM resources WHERE resource_id = ?1 AND deleted_at IS NULL",
            params![id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    raw.map(|(b, conflict)| {
        Ok(ResourceRow {
            resource: dec(&b)?,
            entry_conflict: conflict != 0,
        })
    })
    .transpose()
}

pub(crate) fn list_resources(c: &Connection) -> SResult<Vec<ResourceRow>> {
    let mut stmt = c.prepare(
        "SELECT body, entry_conflict FROM resources WHERE deleted_at IS NULL ORDER BY created_at, resource_id",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (b, conflict) = r?;
        out.push(ResourceRow {
            resource: dec(&b)?,
            entry_conflict: conflict != 0,
        });
    }
    Ok(out)
}

pub(crate) fn upsert_resource(c: &Connection, r: &Resource) -> SResult<()> {
    c.execute(
        "INSERT INTO resources (resource_id, project_id, executor_id, credential_entry_id, body, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(resource_id) DO UPDATE SET project_id = excluded.project_id,
            executor_id = excluded.executor_id, credential_entry_id = excluded.credential_entry_id,
            body = excluded.body, deleted_at = NULL",
        params![
            r.resource_id.as_str(),
            r.project_id.as_str(),
            r.executor_id.as_str(),
            r.credential_entry_id.as_str(),
            enc(r)?,
            unix(&r.created_at),
        ],
    )?;
    Ok(())
}

pub(crate) fn set_entry_conflict(c: &Connection, entry: &EntryId, conflict: bool) -> SResult<u64> {
    let n = c.execute(
        "UPDATE resources SET entry_conflict = ?2 WHERE credential_entry_id = ?1 AND deleted_at IS NULL",
        params![entry.as_str(), i64::from(conflict)],
    )?;
    Ok(n as u64)
}

// ------------------------------------------------------------------------------------
// Devices & executors
// ------------------------------------------------------------------------------------

pub(crate) fn get_device(c: &Connection, id: &DeviceId) -> SResult<Option<TrustedDevice>> {
    let raw: Option<(String, String, i64, String, Option<i64>)> = c
        .query_row(
            "SELECT body, status, added_at, added_by, revoked_at FROM devices WHERE device_id = ?1",
            params![id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    raw.map(device_from_raw).transpose()
}

fn device_from_raw(
    (body, status, added_at, added_by, revoked_at): (String, String, i64, String, Option<i64>),
) -> SResult<TrustedDevice> {
    Ok(TrustedDevice {
        device: dec::<DevicePublic>(&body)?,
        status: enum_parse::<MemberStatus>(&status)?,
        added_at: ts(added_at),
        added_by,
        revoked_at: ts_opt(revoked_at),
    })
}

pub(crate) fn list_devices(c: &Connection) -> SResult<Vec<TrustedDevice>> {
    let mut stmt = c.prepare(
        "SELECT body, status, added_at, added_by, revoked_at FROM devices ORDER BY added_at, device_id",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(device_from_raw(r?)?);
    }
    Ok(out)
}

pub(crate) fn active_approvers(c: &Connection) -> SResult<Vec<TrustedDevice>> {
    Ok(list_devices(c)?
        .into_iter()
        .filter(TrustedDevice::is_active_approver)
        .collect())
}

pub(crate) fn upsert_device(c: &Connection, d: &TrustedDevice) -> SResult<()> {
    c.execute(
        "INSERT INTO devices (device_id, body, role, status, added_at, added_by, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(device_id) DO UPDATE SET body = excluded.body, role = excluded.role,
            status = excluded.status, revoked_at = excluded.revoked_at",
        params![
            d.device.device_id.as_str(),
            enc(&d.device)?,
            enum_str(&d.device.role),
            enum_str(&d.status),
            unix(&d.added_at),
            d.added_by,
            d.revoked_at.as_ref().map(unix),
        ],
    )?;
    Ok(())
}

pub(crate) fn save_executor_info(
    c: &Connection,
    info: &aipass_types::models::ExecutorInfo,
    now: &Timestamp,
) -> SResult<()> {
    c.execute(
        "INSERT INTO executors (executor_id, body, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(executor_id) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at",
        params![info.executor_id.as_str(), enc(info)?, unix(now)],
    )?;
    Ok(())
}

pub(crate) fn list_executor_infos(c: &Connection) -> SResult<Vec<aipass_types::models::ExecutorInfo>> {
    let mut stmt = c.prepare("SELECT body FROM executors ORDER BY executor_id")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(dec(&r?)?);
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------
// Policies
// ------------------------------------------------------------------------------------

pub(crate) struct PolicyRow {
    /// Exactly as signed (status as submitted).
    pub signed: Policy,
    pub disabled: bool,
}

impl PolicyRow {
    /// The policy as shown in listings (status reflects broker-side disabling, which needs
    /// no signature because it only removes permissions).
    pub(crate) fn view(&self) -> Policy {
        let mut p = self.signed.clone();
        if self.disabled {
            p.status = PolicyStatus::Disabled;
        }
        p
    }
    pub(crate) fn is_active(&self) -> bool {
        !self.disabled && self.signed.status == PolicyStatus::Active
    }
}

pub(crate) fn get_policy(c: &Connection, id: &PolicyId) -> SResult<Option<PolicyRow>> {
    let raw: Option<(String, Option<i64>)> = c
        .query_row(
            "SELECT body, disabled_at FROM policies WHERE policy_id = ?1",
            params![id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    raw.map(|(b, d)| {
        Ok(PolicyRow {
            signed: dec(&b)?,
            disabled: d.is_some(),
        })
    })
    .transpose()
}

pub(crate) fn list_policies(c: &Connection) -> SResult<Vec<PolicyRow>> {
    let mut stmt = c.prepare("SELECT body, disabled_at FROM policies ORDER BY created_at, policy_id")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (b, d) = r?;
        out.push(PolicyRow {
            signed: dec(&b)?,
            disabled: d.is_some(),
        });
    }
    Ok(out)
}

/// Disable every active policy whose `column` (`resource_id` or
/// `subject_connection_id`) equals `value`. Returns how many were disabled.
pub(crate) fn disable_policies(c: &Connection, column: &str, value: &str, now: &Timestamp) -> SResult<usize> {
    let column = match column {
        "resource_id" => "resource_id",
        "subject_connection_id" => "subject_connection_id",
        _ => return Err(StoreError::Api(ApiError::internal())),
    };
    Ok(c.execute(
        &format!("UPDATE policies SET disabled_at = ?2 WHERE {column} = ?1 AND disabled_at IS NULL"),
        params![value, unix(now)],
    )?)
}

pub(crate) fn policies_for(
    c: &Connection,
    conn: &ConnectionId,
    res: &ResourceId,
) -> SResult<Vec<PolicyRow>> {
    let mut stmt = c.prepare(
        "SELECT body, disabled_at FROM policies WHERE subject_connection_id = ?1 AND resource_id = ?2 AND disabled_at IS NULL",
    )?;
    let rows = stmt.query_map(params![conn.as_str(), res.as_str()], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (b, d) = r?;
        out.push(PolicyRow {
            signed: dec(&b)?,
            disabled: d.is_some(),
        });
    }
    Ok(out)
}

pub(crate) fn upsert_policy(c: &Connection, p: &Policy, now: &Timestamp) -> SResult<()> {
    c.execute(
        "INSERT INTO policies (policy_id, version, subject_connection_id, resource_id, body, created_at, disabled_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
         ON CONFLICT(policy_id) DO UPDATE SET version = excluded.version,
            subject_connection_id = excluded.subject_connection_id, resource_id = excluded.resource_id,
            body = excluded.body, disabled_at = NULL",
        params![
            p.policy_id.as_str(),
            i(p.version),
            p.subject_connection_id.as_str(),
            p.resource_id.as_str(),
            enc(p)?,
            unix(now),
        ],
    )?;
    Ok(())
}

// ------------------------------------------------------------------------------------
// Approvals
// ------------------------------------------------------------------------------------

pub(crate) struct ApprovalRow {
    pub req: ApprovalRequest,
    pub grant_id: Option<GrantId>,
}

pub(crate) fn get_approval(c: &Connection, id: &ApprovalRequestId) -> SResult<Option<ApprovalRow>> {
    let raw: Option<(String, String, Option<String>)> = c
        .query_row(
            "SELECT body, status, grant_id FROM approvals WHERE approval_request_id = ?1",
            params![id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    raw.map(approval_from_raw).transpose()
}

fn approval_from_raw((body, status, grant): (String, String, Option<String>)) -> SResult<ApprovalRow> {
    let mut req: ApprovalRequest = dec(&body)?;
    req.status = enum_parse(&status)?;
    Ok(ApprovalRow {
        req,
        grant_id: grant.map(|g| GrantId::parse(&g)).transpose()?,
    })
}

pub(crate) fn list_approvals(c: &Connection, status: Option<ApprovalStatus>) -> SResult<Vec<ApprovalRow>> {
    let (sql, st) = match status {
        Some(s) => (
            "SELECT body, status, grant_id FROM approvals WHERE status = ?1 ORDER BY created_at DESC LIMIT 500",
            enum_str(&s),
        ),
        None => (
            "SELECT body, status, grant_id FROM approvals WHERE ?1 = ?1 ORDER BY created_at DESC LIMIT 500",
            String::new(),
        ),
    };
    let mut stmt = c.prepare(sql)?;
    let rows = stmt.query_map(params![st], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(approval_from_raw(r?)?);
    }
    Ok(out)
}

pub(crate) fn insert_approval(c: &Connection, req: &ApprovalRequest) -> SResult<()> {
    c.execute(
        "INSERT INTO approvals (approval_request_id, kind, connection_id, resource_id, operation_id, status, body, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            req.approval_request_id.as_str(),
            enum_str(&req.kind),
            req.connection.connection_id.as_str(),
            req.resource.resource_id.as_str(),
            req.operation_id.as_ref().map(|o| o.as_str().to_owned()),
            enum_str(&req.status),
            enc(req)?,
            unix(&req.created_at),
            unix(&req.expires_at),
        ],
    )?;
    Ok(())
}

/// Move a *pending* approval to `to`. Returns false when it was no longer pending.
pub(crate) fn resolve_approval(
    c: &Connection,
    id: &ApprovalRequestId,
    to: ApprovalStatus,
    now: &Timestamp,
    decided_by: Option<&str>,
    grant: Option<&GrantId>,
) -> SResult<bool> {
    let n = c.execute(
        "UPDATE approvals SET status = ?2, decided_at = ?3, decided_by = ?4, grant_id = ?5
         WHERE approval_request_id = ?1 AND status = 'pending'",
        params![
            id.as_str(),
            enum_str(&to),
            unix(now),
            decided_by,
            grant.map(|g| g.as_str().to_owned()),
        ],
    )?;
    Ok(n == 1)
}

pub(crate) fn pending_approvals_for_connection(c: &Connection, conn: &ConnectionId, now: &Timestamp) -> SResult<u64> {
    let n: i64 = c.query_row(
        "SELECT COUNT(*) FROM approvals WHERE connection_id = ?1 AND status = 'pending' AND expires_at > ?2",
        params![conn.as_str(), unix(now)],
        |r| r.get(0),
    )?;
    Ok(u(n))
}

pub(crate) fn pending_approval_ids(
    c: &Connection,
    filter_col: &str,
    value: &str,
) -> SResult<Vec<ApprovalRequestId>> {
    debug_assert!(matches!(filter_col, "connection_id" | "resource_id"));
    let mut stmt = c.prepare(&format!(
        "SELECT approval_request_id FROM approvals WHERE {filter_col} = ?1 AND status = 'pending'"
    ))?;
    let rows = stmt.query_map(params![value], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(ApprovalRequestId::parse(&r?)?);
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------
// Grants
// ------------------------------------------------------------------------------------

/// Credential delivery state of a grant at its executor (in-memory there; tracked here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredState {
    None,
    Installed,
    Failed,
    Dropped,
}

#[derive(Debug, Clone)]
pub(crate) struct GrantRow {
    pub grant: Grant,
    pub reserved_rows: u64,
    pub cred: CredState,
    pub approved_by: Option<String>,
    /// Set for a `once` grant created by an operation approval: only that operation may
    /// use it (the user approved those exact parameters, not "anything in this scope").
    pub bound_operation: Option<OperationId>,
}

impl GrantRow {
    /// Remaining budget as limits handed to the executor (per-operation row cap already
    /// reduced to what the grant can still return, after in-flight reservations).
    pub(crate) fn remaining(&self) -> Limits {
        let l = &self.grant.limits;
        let used = &self.grant.usage;
        let rows_left = l
            .max_rows_per_grant
            .saturating_sub(used.rows)
            .saturating_sub(self.reserved_rows);
        let reqs_left = if self.grant.mode == ApprovalMode::Once {
            u64::from(used.requests == 0)
        } else {
            l.max_requests_per_grant.saturating_sub(used.requests)
        };
        Limits {
            max_rows_per_operation: l.max_rows_per_operation.min(rows_left),
            max_rows_per_grant: rows_left,
            max_requests_per_grant: reqs_left,
            max_result_bytes: l.max_result_bytes,
        }
    }

    pub(crate) fn has_budget(&self) -> bool {
        let r = self.remaining();
        r.max_requests_per_grant > 0 && r.max_rows_per_operation > 0
    }

    /// Budget fully consumed (nothing in flight could free it up).
    pub(crate) fn is_exhausted(&self) -> bool {
        let l = &self.grant.limits;
        let used = &self.grant.usage;
        (self.grant.mode == ApprovalMode::Once && used.requests > 0)
            || used.requests >= l.max_requests_per_grant
            || used.rows >= l.max_rows_per_grant
    }
}

const GRANT_COLS: &str = "grant_id, approval_request_id, policy_id, policy_version, connection_id, resource_id, executor_id, scope, mode, digest, status, max_rows_per_operation, max_rows_per_grant, max_requests_per_grant, max_result_bytes, used_requests, used_rows, used_bytes, reserved_rows, credential_state, approved_by, created_at, expires_at, revoked_at, revocation, bound_operation_id";

struct RawGrant {
    s: [Option<String>; 11],
    n: [i64; 8],
    cred: String,
    approved_by: Option<String>,
    created_at: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
    revocation: Option<String>,
    policy_version: Option<i64>,
    bound_operation: Option<String>,
}

fn raw_grant(r: &Row<'_>) -> rusqlite::Result<RawGrant> {
    Ok(RawGrant {
        s: [
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            None,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            r.get(8)?,
            r.get(9)?,
            r.get(10)?,
        ],
        policy_version: r.get(3)?,
        n: [
            r.get(11)?,
            r.get(12)?,
            r.get(13)?,
            r.get(14)?,
            r.get(15)?,
            r.get(16)?,
            r.get(17)?,
            r.get(18)?,
        ],
        cred: r.get(19)?,
        approved_by: r.get(20)?,
        created_at: r.get(21)?,
        expires_at: r.get(22)?,
        revoked_at: r.get(23)?,
        revocation: r.get(24)?,
        bound_operation: r.get(25)?,
    })
}

fn req_str(s: &Option<String>) -> SResult<&str> {
    s.as_deref()
        .ok_or_else(|| StoreError::Api(ApiError::internal()))
}

impl RawGrant {
    fn into_row(self) -> SResult<GrantRow> {
        let s = &self.s;
        let grant = Grant {
            grant_id: GrantId::parse(req_str(&s[0])?)?,
            approval_request_id: s[1].as_deref().map(ApprovalRequestId::parse).transpose()?,
            policy_id: s[2].as_deref().map(PolicyId::parse).transpose()?,
            policy_version: self.policy_version.map(u),
            connection_id: ConnectionId::parse(req_str(&s[4])?)?,
            resource_id: ResourceId::parse(req_str(&s[5])?)?,
            executor_id: ExecutorId::parse(req_str(&s[6])?)?,
            scope: dec::<GrantScope>(req_str(&s[7])?)?,
            mode: enum_parse(req_str(&s[8])?)?,
            digest: req_str(&s[9])?.to_owned(),
            status: enum_parse(req_str(&s[10])?)?,
            limits: Limits {
                max_rows_per_operation: u(self.n[0]),
                max_rows_per_grant: u(self.n[1]),
                max_requests_per_grant: u(self.n[2]),
                max_result_bytes: u(self.n[3]),
            },
            usage: GrantUsage {
                requests: u(self.n[4]),
                rows: u(self.n[5]),
                bytes: u(self.n[6]),
            },
            created_at: ts(self.created_at),
            expires_at: ts(self.expires_at),
            revoked_at: ts_opt(self.revoked_at),
            revocation: self
                .revocation
                .as_deref()
                .map(dec::<RevocationReport>)
                .transpose()?,
        };
        Ok(GrantRow {
            grant,
            reserved_rows: u(self.n[7]),
            cred: enum_parse(&self.cred)?,
            approved_by: self.approved_by,
            bound_operation: self.bound_operation.as_deref().map(OperationId::parse).transpose()?,
        })
    }
}

pub(crate) fn get_grant(c: &Connection, id: &GrantId) -> SResult<Option<GrantRow>> {
    c.query_row(
        &format!("SELECT {GRANT_COLS} FROM grants WHERE grant_id = ?1"),
        params![id.as_str()],
        raw_grant,
    )
    .optional()?
    .map(RawGrant::into_row)
    .transpose()
}

pub(crate) fn query_grants(c: &Connection, where_sql: &str, args: &[&dyn rusqlite::ToSql]) -> SResult<Vec<GrantRow>> {
    let mut stmt = c.prepare(&format!("SELECT {GRANT_COLS} FROM grants WHERE {where_sql}"))?;
    let rows = stmt.query_map(args, raw_grant)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?.into_row()?);
    }
    Ok(out)
}

pub(crate) fn insert_grant(c: &Connection, g: &GrantRow) -> SResult<()> {
    let gr = &g.grant;
    c.execute(
        &format!("INSERT INTO grants ({GRANT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)"),
        params![
            gr.grant_id.as_str(),
            gr.approval_request_id.as_ref().map(|a| a.as_str().to_owned()),
            gr.policy_id.as_ref().map(|p| p.as_str().to_owned()),
            gr.policy_version.map(i),
            gr.connection_id.as_str(),
            gr.resource_id.as_str(),
            gr.executor_id.as_str(),
            enc(&gr.scope)?,
            enum_str(&gr.mode),
            gr.digest,
            enum_str(&gr.status),
            i(gr.limits.max_rows_per_operation),
            i(gr.limits.max_rows_per_grant),
            i(gr.limits.max_requests_per_grant),
            i(gr.limits.max_result_bytes),
            i(gr.usage.requests),
            i(gr.usage.rows),
            i(gr.usage.bytes),
            i(g.reserved_rows),
            enum_str(&g.cred),
            g.approved_by,
            unix(&gr.created_at),
            unix(&gr.expires_at),
            gr.revoked_at.as_ref().map(unix),
            gr.revocation.as_ref().map(enc).transpose()?,
            g.bound_operation.as_ref().map(|o| o.as_str().to_owned()),
        ],
    )?;
    Ok(())
}

/// Conditional status change (`from` set → `to`). Returns whether it changed.
pub(crate) fn set_grant_status(
    c: &Connection,
    id: &GrantId,
    from: &[GrantStatus],
    to: GrantStatus,
) -> SResult<bool> {
    let from: Vec<String> = from.iter().map(enum_str).collect();
    let placeholders = (0..from.len()).map(|k| format!("?{}", k + 3)).collect::<Vec<_>>().join(", ");
    let sql = format!("UPDATE grants SET status = ?2 WHERE grant_id = ?1 AND status IN ({placeholders})");
    let mut args: Vec<&dyn rusqlite::ToSql> = Vec::new();
    let id_s = id.as_str().to_owned();
    let to_s = enum_str(&to);
    args.push(&id_s);
    args.push(&to_s);
    for f in &from {
        args.push(f);
    }
    Ok(c.execute(&sql, args.as_slice())? == 1)
}

pub(crate) fn set_cred_state(c: &Connection, id: &GrantId, st: CredState) -> SResult<()> {
    c.execute(
        "UPDATE grants SET credential_state = ?2 WHERE grant_id = ?1",
        params![id.as_str(), enum_str(&st)],
    )?;
    Ok(())
}

// ------------------------------------------------------------------------------------
// Operations
// ------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct OpRow {
    pub op: Operation,
    pub error: Option<StoredError>,
    pub request_digest: String,
    pub normalized: Option<NormalizedRequest>,
}

const OP_COLS: &str = "operation_id, connection_id, resource_id, operation, parameters_digest, request_digest, idempotency_key, status, grant_id, approval_request_id, result, error, side_effects, normalized, task_id, created_at, updated_at";

struct RawOp {
    s: [Option<String>; 15],
    created_at: i64,
    updated_at: i64,
}

fn raw_op(r: &Row<'_>) -> rusqlite::Result<RawOp> {
    let mut s: [Option<String>; 15] = Default::default();
    for (k, slot) in s.iter_mut().enumerate() {
        *slot = r.get(k)?;
    }
    Ok(RawOp {
        s,
        created_at: r.get(15)?,
        updated_at: r.get(16)?,
    })
}

impl RawOp {
    fn into_row(self) -> SResult<OpRow> {
        let s = &self.s;
        let status = OperationStatus::parse(req_str(&s[7])?)
            .ok_or_else(|| StoreError::Api(ApiError::internal()))?;
        Ok(OpRow {
            op: Operation {
                operation_id: OperationId::parse(req_str(&s[0])?)?,
                connection_id: ConnectionId::parse(req_str(&s[1])?)?,
                resource_id: ResourceId::parse(req_str(&s[2])?)?,
                operation: req_str(&s[3])?.to_owned(),
                parameters_digest: req_str(&s[4])?.to_owned(),
                idempotency_key: req_str(&s[6])?.to_owned(),
                status,
                grant_id: s[8].as_deref().map(GrantId::parse).transpose()?,
                approval_request_id: s[9].as_deref().map(ApprovalRequestId::parse).transpose()?,
                result: s[10].as_deref().map(dec::<OperationResult>).transpose()?,
                error: None,
                side_effects: enum_parse::<SideEffects>(req_str(&s[12])?)?,
                created_at: ts(self.created_at),
                updated_at: ts(self.updated_at),
            },
            error: s[11].as_deref().map(dec::<StoredError>).transpose()?,
            request_digest: req_str(&s[5])?.to_owned(),
            normalized: s[13].as_deref().map(dec::<NormalizedRequest>).transpose()?,
        })
    }
}

pub(crate) fn get_op(c: &Connection, id: &OperationId) -> SResult<Option<OpRow>> {
    c.query_row(
        &format!("SELECT {OP_COLS} FROM operations WHERE operation_id = ?1"),
        params![id.as_str()],
        raw_op,
    )
    .optional()?
    .map(RawOp::into_row)
    .transpose()
}

pub(crate) fn get_op_by_key(c: &Connection, conn: &ConnectionId, key: &str) -> SResult<Option<OpRow>> {
    c.query_row(
        &format!("SELECT {OP_COLS} FROM operations WHERE connection_id = ?1 AND idempotency_key = ?2"),
        params![conn.as_str(), key],
        raw_op,
    )
    .optional()?
    .map(RawOp::into_row)
    .transpose()
}

pub(crate) fn query_ops(c: &Connection, where_sql: &str, args: &[&dyn rusqlite::ToSql]) -> SResult<Vec<OpRow>> {
    let mut stmt = c.prepare(&format!("SELECT {OP_COLS} FROM operations WHERE {where_sql}"))?;
    let rows = stmt.query_map(args, raw_op)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?.into_row()?);
    }
    Ok(out)
}

/// Insert a new operation in state `received`. Returns false on an idempotency-key race
/// (the caller re-reads the existing operation).
pub(crate) fn insert_op(c: &Connection, row: &OpRow, task_id: Option<&str>) -> SResult<bool> {
    let op = &row.op;
    debug_assert_eq!(op.status, OperationStatus::Received);
    let r = c.execute(
        &format!("INSERT INTO operations ({OP_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, ?11, ?12, ?13, ?14, ?15)"),
        params![
            op.operation_id.as_str(),
            op.connection_id.as_str(),
            op.resource_id.as_str(),
            op.operation,
            op.parameters_digest,
            row.request_digest,
            op.idempotency_key,
            op.status.state_name(),
            op.grant_id.as_ref().map(|g| g.as_str().to_owned()),
            op.approval_request_id.as_ref().map(|a| a.as_str().to_owned()),
            enum_str(&op.side_effects),
            row.normalized.as_ref().map(enc).transpose()?,
            task_id,
            unix(&op.created_at),
            unix(&op.updated_at),
        ],
    );
    match r {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

/// Fields set together with a state transition.
#[derive(Default)]
pub(crate) struct OpUpdate<'a> {
    pub grant_id: Option<&'a GrantId>,
    pub approval_request_id: Option<&'a ApprovalRequestId>,
    pub result: Option<&'a OperationResult>,
    pub error: Option<&'a StoredError>,
    pub side_effects: Option<SideEffects>,
    /// Drop the stored normalized parameters (always done on terminal states).
    pub clear_normalized: bool,
}

/// State-machine-checked transition: only applied when the current status is one of
/// `from` and every `from → to` is legal (CONTRACTS §6.2). Returns whether it applied.
pub(crate) fn transition(
    c: &Connection,
    id: &OperationId,
    from: &[OperationStatus],
    to: OperationStatus,
    now: &Timestamp,
    upd: OpUpdate<'_>,
) -> SResult<bool> {
    for f in from {
        if !f.can_transition(to) {
            tracing::error!(from = f.state_name(), to = to.state_name(), "illegal operation transition requested");
            return Err(StoreError::Api(ApiError::internal()));
        }
    }
    let from_names: BTreeSet<&str> = from.iter().map(|s| s.state_name()).collect();
    let current: Option<String> = c
        .query_row(
            "SELECT status FROM operations WHERE operation_id = ?1",
            params![id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(current) = current else {
        return Ok(false);
    };
    if !from_names.contains(current.as_str()) {
        return Ok(false);
    }
    let clear = upd.clear_normalized || to.is_terminal();
    c.execute(
        "UPDATE operations SET status = ?2, updated_at = ?3,
            grant_id = COALESCE(?4, grant_id),
            approval_request_id = COALESCE(?5, approval_request_id),
            result = COALESCE(?6, result),
            error = COALESCE(?7, error),
            side_effects = COALESCE(?8, side_effects),
            normalized = CASE WHEN ?9 THEN NULL ELSE normalized END
         WHERE operation_id = ?1",
        params![
            id.as_str(),
            to.state_name(),
            unix(now),
            upd.grant_id.map(|g| g.as_str().to_owned()),
            upd.approval_request_id.map(|a| a.as_str().to_owned()),
            upd.result.map(enc).transpose()?,
            upd.error.map(enc).transpose()?,
            upd.side_effects.map(|s| enum_str(&s)),
            clear,
        ],
    )?;
    Ok(true)
}

// ------------------------------------------------------------------------------------
// Throttling, nonces, relay replay protection
// ------------------------------------------------------------------------------------

pub(crate) fn recently_denied(
    c: &Connection,
    conn: &ConnectionId,
    res: &ResourceId,
    operation: &str,
    since: &Timestamp,
) -> SResult<bool> {
    Ok(c.query_row(
        "SELECT 1 FROM denials WHERE connection_id = ?1 AND resource_id = ?2 AND operation = ?3 AND denied_at > ?4 LIMIT 1",
        params![conn.as_str(), res.as_str(), operation, unix(since)],
        |_| Ok(()),
    )
    .optional()?
    .is_some())
}

pub(crate) fn record_denial(c: &Connection, conn: &ConnectionId, res: &ResourceId, operation: &str, now: &Timestamp) -> SResult<()> {
    c.execute(
        "INSERT INTO denials (connection_id, resource_id, operation, denied_at) VALUES (?1, ?2, ?3, ?4)",
        params![conn.as_str(), res.as_str(), operation, unix(now)],
    )?;
    Ok(())
}

/// Persisted replay cache: `Ok(true)` = fresh, `Ok(false)` = replay.
pub(crate) fn check_nonce(c: &Connection, kid: &str, nonce: &str, now: i64, ttl: i64, max: u64, max_per_kid: u64) -> SResult<NonceCheck> {
    let seen: Option<i64> = c
        .query_row(
            "SELECT expires_at FROM nonces WHERE kid = ?1 AND nonce = ?2",
            params![kid, nonce],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(exp) = seen {
        if exp > now {
            return Ok(NonceCheck::Replay);
        }
        c.execute("DELETE FROM nonces WHERE kid = ?1 AND nonce = ?2", params![kid, nonce])?;
    }
    // Per-key quota first (bounded, indexed): a flooding key is turned away before it
    // costs a global count, and never fills the cache for everyone else.
    let mine: i64 = c.query_row(
        "SELECT COUNT(*) FROM nonces WHERE kid = ?1 AND expires_at > ?2",
        params![kid, now],
        |r| r.get(0),
    )?;
    if u(mine) >= max_per_kid {
        return Ok(NonceCheck::Full);
    }
    let count: i64 = c.query_row("SELECT COUNT(*) FROM nonces WHERE expires_at > ?1", params![now], |r| r.get(0))?;
    if u(count) >= max {
        c.execute("DELETE FROM nonces WHERE expires_at <= ?1", params![now])?;
        let count: i64 = c.query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get(0))?;
        if u(count) >= max {
            return Ok(NonceCheck::Full);
        }
    }
    c.execute(
        "INSERT INTO nonces (kid, nonce, expires_at) VALUES (?1, ?2, ?3)",
        params![kid, nonce, now + ttl],
    )?;
    Ok(NonceCheck::Fresh)
}

pub(crate) enum NonceCheck {
    Fresh,
    Replay,
    Full,
}

/// Envelope replay protection: true when this signature hash was not seen before.
pub(crate) fn relay_first_seen(c: &Connection, sig_hash: &str, now: &Timestamp) -> SResult<bool> {
    let n = c.execute(
        "INSERT OR IGNORE INTO relay_seen (sig_hash, seen_at) VALUES (?1, ?2)",
        params![sig_hash, unix(now)],
    )?;
    Ok(n == 1)
}

/// Helper: connection-visible check.
pub(crate) fn visible(conn: &AppConnection, project: &ProjectId) -> bool {
    match &conn.allowed_projects {
        AllowedProjects::All => true,
        AllowedProjects::Only(s) => s.contains(project),
    }
}

/// Helper: is the connection usable for C endpoints?
pub(crate) fn connection_status_error(status: ConnectionStatus) -> Option<ApiError> {
    match status {
        ConnectionStatus::Active => None,
        ConnectionStatus::Paused => Some(ApiError::new(ErrorCode::ConnectionPaused)),
        ConnectionStatus::Pending => Some(
            ApiError::identity_unverified()
                .with_message("此 AI 连接尚未在可信设备上获批", "This AI connection has not been approved on a trusted device yet."),
        ),
        ConnectionStatus::Removed => Some(ApiError::identity_unverified()),
    }
}
