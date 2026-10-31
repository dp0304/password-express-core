// SPDX-License-Identifier: Apache-2.0
//! AppConnections: pairing, approval by a trusted device or admin, pause / resume /
//! remove / revoke_all, request authentication (`AIPass-Sig`, `Bearer aipc_…`).
//!
//! `display_name` and `host_type` are self-declared labels (§7.3); identity is the
//! connection key or token hash only.

use std::collections::BTreeSet;
use std::sync::Arc;

use aipass_crypto::b64u;
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::ids::{ConnectionId, PairingId, PrincipalId};
use aipass_types::models::{
    AllowedProjects, AppConnection, ConnectionStatus, ConnectionView, ConnectionViewsResponse,
    ConnectionsResponse, PairConnectionResponse, PairStatus, PairStatusResponse, RevocationLevel,
};
use aipass_types::relay::{ConnectionPairRequest, ControlAction, RelayMessage};
use aipass_types::signing::{self, NONCE_TTL_SECS, SigError, SigHeader, token_prefix};
use rusqlite::params;
use serde_json::json;

use super::Broker;
use crate::audit::{self, Audit};
use crate::db::{enum_str, unix};
use crate::error::{SResult, err};
use crate::notify::BrokerEvent;
use crate::principal::{Actor, AuthVia, ConnectionPrincipal, VerifiedPrincipal};
use crate::store::{self, NonceCheck};
use crate::types::{CreatedConnection, NewConnection, PairingInput, RevokeAllResponse, TokenResponse};

const MAX_DISPLAY_NAME: usize = 64;

fn validate_display_name(name: &str) -> Result<String, ApiError> {
    let t = name.trim();
    if t.is_empty() || t.chars().count() > MAX_DISPLAY_NAME || t.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            "display_name 必须为 1 到 64 个可打印字符",
            "display_name must be 1 to 64 printable characters",
        )
        .with_detail("field", "display_name"));
    }
    Ok(t.to_owned())
}

fn validate_public_key(pk: &str) -> Result<(), ApiError> {
    let bytes = b64u::decode_array::<32>(pk).map_err(|_| {
        ApiError::invalid_request("public_key 必须是 32 字节 Ed25519 公钥（b64u）", "public_key must be a 32-byte Ed25519 key (b64u)")
            .with_detail("field", "public_key")
    })?;
    aipass_crypto::identity::validate_ed25519_public_key(&bytes).map_err(|_| {
        ApiError::invalid_request("public_key 不是有效的 Ed25519 公钥", "public_key is not a valid Ed25519 key")
            .with_detail("field", "public_key")
    })
}

/// `GET /v1/connections/pair/{id}` — the only request a `pending` connection may sign.
fn is_pairing_poll(method: &str, path_and_query: &str) -> bool {
    let path = path_and_query.split(['?', '#']).next().unwrap_or_default();
    method.eq_ignore_ascii_case("GET")
        && path
            .strip_prefix("/v1/connections/pair/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

fn pairing_code() -> Result<String, ApiError> {
    let n = aipass_crypto::rng::random_below(1_000_000).map_err(|_| ApiError::internal())?;
    Ok(format!("{n:06}"))
}

fn validate_projects(c: &rusqlite::Connection, allowed: &AllowedProjects) -> SResult<()> {
    if let AllowedProjects::Only(set) = allowed {
        for p in set {
            if !store::project_exists(c, p)? {
                return Err(ApiError::invalid_request("项目不存在", "unknown project")
                    .with_detail("project_id", p.as_str())
                    .into());
            }
        }
    }
    Ok(())
}

impl Broker {
    // ------------------------------------------------------------- authentication

    /// Verify an `AIPass-Sig` request signature (skew, Ed25519, per-kid nonce persisted for
    /// 600 s, per-kid nonce quota) and resolve the principal: `conn_…` → its pairing key
    /// when `active` / `paused` (endpoints check the status), or — for a `pending`
    /// connection — only on `GET /v1/connections/pair/{id}` (CONTRACTS §1.6: the kid
    /// must resolve to an active principal); `dev_…` → an active owner/member device. The
    /// status is checked before a nonce is recorded.
    pub async fn verify_request_signature(
        &self,
        header: &SigHeader,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<VerifiedPrincipal, ApiError> {
        let principal = header.principal().map_err(ApiError::from)?;
        let (pk, verified) = match principal {
            PrincipalId::Connection(id) => {
                let lookup = id.clone();
                let row = self
                    .db
                    .call(move |c| store::get_connection(c, &lookup))
                    .await?
                    .ok_or_else(ApiError::identity_unverified)?;
                let allowed = match row.conn.status {
                    ConnectionStatus::Active | ConnectionStatus::Paused => true,
                    ConnectionStatus::Pending => is_pairing_poll(method, path_and_query),
                    ConnectionStatus::Removed => false,
                };
                if !allowed {
                    return Err(ApiError::identity_unverified());
                }
                let pk_text = row.conn.public_key.ok_or_else(ApiError::identity_unverified)?;
                let pk = b64u::decode_array::<32>(&pk_text).map_err(|_| ApiError::identity_unverified())?;
                (pk, VerifiedPrincipal::Connection(ConnectionPrincipal::verified(id, AuthVia::Signature)))
            }
            PrincipalId::Device(id) => {
                let lookup = id.clone();
                let dev = self
                    .db
                    .call(move |c| store::get_device(c, &lookup))
                    .await?
                    .filter(|d| d.is_active_approver())
                    .ok_or_else(ApiError::identity_unverified)?;
                (dev.device.sign_pk, VerifiedPrincipal::Device(id))
            }
            PrincipalId::Executor(_) => return Err(ApiError::identity_unverified()),
        };
        let now = self.clock.unix();
        signing::verify_request(header, &pk, method, path_and_query, body, now).map_err(ApiError::from)?;
        let kid = header.kid.clone();
        let nonce = header.nonce.clone();
        let (max, per_kid) = (self.cfg.max_nonces, self.cfg.max_nonces_per_kid);
        match self
            .db
            .call(move |c| store::check_nonce(c, &kid, &nonce, now, NONCE_TTL_SECS, max, per_kid))
            .await?
        {
            NonceCheck::Fresh => Ok(verified),
            NonceCheck::Replay => Err(ApiError::from(SigError::Replay)),
            NonceCheck::Full => Err(ApiError::from(SigError::CacheFull)),
        }
    }

    /// Authenticate a `Bearer aipc_…` connection token (compared by SHA-256 hash only).
    pub async fn authenticate_connection_token(&self, token: &str) -> Result<ConnectionPrincipal, ApiError> {
        if !token.starts_with(token_prefix::CONNECTION) || token.len() > 256 {
            return Err(ApiError::identity_unverified());
        }
        let hash = signing::token_hash(token);
        let row = self
            .db
            .call(move |c| {
                let Some(id) = store::connection_for_token(c, &hash)? else {
                    return Ok(None);
                };
                store::get_connection(c, &id)
            })
            .await?
            .ok_or_else(ApiError::identity_unverified)?;
        if row.conn.status == ConnectionStatus::Removed {
            return Err(ApiError::identity_unverified());
        }
        Ok(ConnectionPrincipal::verified(row.conn.connection_id, AuthVia::ConnectionToken))
    }

    /// Load the connection of `p` and require `active` (rule 1 of §6.2); records `last_seen_at`.
    pub(crate) async fn active_connection(&self, p: &ConnectionPrincipal) -> Result<AppConnection, ApiError> {
        let id = p.connection_id().clone();
        let now = self.now();
        let row = self
            .db
            .call(move |c| {
                let row = store::get_connection(c, &id)?;
                if let Some(r) = &row {
                    let stale = r
                        .conn
                        .last_seen_at
                        .is_none_or(|t| unix(&now) - unix(&t) >= 30);
                    if r.conn.status == ConnectionStatus::Active && stale {
                        c.execute(
                            "UPDATE connections SET last_seen_at = ?2 WHERE connection_id = ?1",
                            params![id.as_str(), unix(&now)],
                        )?;
                    }
                }
                Ok(row)
            })
            .await?
            .ok_or_else(ApiError::identity_unverified)?;
        if let Some(e) = store::connection_status_error(row.conn.status) {
            return Err(e);
        }
        Ok(row.conn)
    }

    // ------------------------------------------------------------- pairing

    /// Start pairing an AI host (`POST /v1/connections/pair`). Creates a `pending`
    /// connection that can do nothing until a trusted device (or the local admin)
    /// approves it with an explicit project list.
    pub async fn begin_pairing(&self, input: PairingInput) -> Result<PairConnectionResponse, ApiError> {
        self.begin_pairing_from(input, None).await
    }

    /// [`Self::begin_pairing`] from a network peer (`POST /v1/connections/pair`): at most
    /// `max_pending_pairings_per_peer` pending pairings per peer, below the global cap.
    pub async fn begin_pairing_from(&self, input: PairingInput, peer: Option<&str>) -> Result<PairConnectionResponse, ApiError> {
        let display_name = validate_display_name(&input.display_name)?;
        if let Some(pk) = &input.public_key {
            validate_public_key(pk)?;
        }
        let now = self.now();
        let ttl = i64::try_from(self.cfg.pairing_ttl.as_secs()).unwrap_or(600);
        let expires_at = aipass_types::time::add_secs(&now, ttl);
        let code = pairing_code()?;
        let conn = AppConnection {
            connection_id: ConnectionId::generate(),
            host_type: input.host_type,
            display_name,
            transport: input.transport,
            status: ConnectionStatus::Pending,
            public_key: input.public_key,
            allowed_projects: AllowedProjects::Only(BTreeSet::new()),
            created_at: now,
            approved_at: None,
            approved_by: None,
            last_seen_at: None,
        };
        let pairing_id = PairingId::generate();
        let max = i64::from(self.cfg.max_pending_pairings);
        let max_peer = i64::from(self.cfg.max_pending_pairings_per_peer);
        let peer: Option<String> = peer.map(|p| p.chars().take(64).collect());
        let (c2, p2, code2) = (conn.clone(), pairing_id.clone(), code.clone());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                let pending: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pairings WHERE status = 'pending' AND expires_at > ?1",
                    params![unix(&now)],
                    |r| r.get(0),
                )?;
                let mine: i64 = match &peer {
                    Some(p) => tx.query_row(
                        "SELECT COUNT(*) FROM pairings WHERE peer = ?1 AND status = 'pending' AND expires_at > ?2",
                        params![p, unix(&now)],
                        |r| r.get(0),
                    )?,
                    None => 0,
                };
                if pending >= max || mine >= max_peer {
                    return Err(err(
                        ErrorCode::RateLimited,
                        "待确认的连接请求过多，请先在可信设备上处理",
                        "Too many pending connection requests; handle them on a trusted device first.",
                    )
                    .into());
                }
                store::insert_connection(&tx, &c2)?;
                tx.execute(
                    "INSERT INTO pairings (pairing_id, connection_id, pairing_code, status, created_at, expires_at, peer) VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6)",
                    params![p2.as_str(), c2.connection_id.as_str(), code2, unix(&now), unix(&expires_at), peer],
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(c2.connection_id.as_str(), "connection.pair_requested").detail(json!({
                        "pairing_request_id": p2.as_str(),
                        "host_type": enum_str(&c2.host_type),
                        "transport": enum_str(&c2.transport),
                        "has_key": c2.public_key.is_some(),
                    })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        self.emit(BrokerEvent::ConnectionPairingRequested {
            connection: Box::new(conn.clone()),
            pairing_code: code.clone(),
        });
        self.notify_devices(
            RelayMessage::ConnectionPairRequest(Box::new(ConnectionPairRequest {
                connection: conn.clone(),
                pairing_code: code.clone(),
            })),
            None,
        )
        .await;
        Ok(PairConnectionResponse {
            pairing_request_id: pairing_id,
            connection_id: conn.connection_id,
            pairing_code: code,
            expires_at,
        })
    }

    /// Pairing status for the pending connection itself (`caller` must be the
    /// connection the pairing belongs to — otherwise `NOT_FOUND`).
    pub async fn pair_status(&self, pairing_id: &PairingId, caller: &ConnectionId) -> Result<PairStatusResponse, ApiError> {
        let now = self.now();
        let (pid, caller) = (pairing_id.clone(), caller.clone());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                let p = store::get_pairing(&tx, &pid)?
                    .filter(|p| p.connection_id == caller)
                    .ok_or_else(ApiError::not_found)?;
                let mut status = p.status;
                if status == PairStatus::Pending && now >= p.expires_at {
                    expire_pairing(&tx, &p.connection_id, &now)?;
                    status = PairStatus::Expired;
                }
                tx.commit()?;
                Ok(PairStatusResponse {
                    status,
                    connection_id: p.connection_id,
                })
            })
            .await
    }

    /// Pairing code + status of a connection's pairing (for trusted UIs).
    pub async fn connection_pairing(&self, id: &ConnectionId) -> Result<Option<(PairingId, String, PairStatus)>, ApiError> {
        let id = id.clone();
        self.db
            .call(move |c| Ok(store::pairing_for_connection(c, &id)?.map(|p| (p.pairing_id, p.pairing_code, p.status))))
            .await
    }

    /// `GET /v1/connections`.
    pub async fn list_connections(&self) -> Result<ConnectionsResponse, ApiError> {
        let connections = self.db.call(|c| store::list_connections(c)).await?;
        Ok(ConnectionsResponse { connections })
    }

    /// One connection.
    pub async fn get_connection(&self, id: &ConnectionId) -> Result<AppConnection, ApiError> {
        let id = id.clone();
        self.db
            .call(move |c| Ok(store::get_connection(c, &id)?.map(|r| r.conn)))
            .await?
            .ok_or_else(ApiError::not_found)
    }

    /// `GET /v1/connections/{id}` for trusted devices / admins (callers must have checked
    /// the D/A principal): the connection plus, while it is `pending` and its pairing is
    /// open, the pairing code the AI host displayed.
    pub async fn get_connection_view(&self, id: &ConnectionId) -> Result<ConnectionView, ApiError> {
        let (id, now) = (id.clone(), self.now());
        self.db
            .call(move |c| {
                let row = store::get_connection(c, &id)?.ok_or_else(ApiError::not_found)?;
                connection_view(c, row.conn, &now)
            })
            .await
    }

    /// `GET /v1/connections` for trusted devices / admins: pending rows carry their open
    /// pairing code (see [`Self::get_connection_view`]).
    pub async fn list_connection_views(&self) -> Result<ConnectionViewsResponse, ApiError> {
        let now = self.now();
        self.db
            .call(move |c| {
                let mut connections = Vec::new();
                for conn in store::list_connections(c)? {
                    connections.push(connection_view(c, conn, &now)?);
                }
                Ok(ConnectionViewsResponse { connections })
            })
            .await
    }

    /// Approve a pending connection (or edit the projects of an existing one).
    pub async fn approve_connection(
        &self,
        actor: &Actor,
        id: &ConnectionId,
        allowed_projects: AllowedProjects,
    ) -> Result<AppConnection, ApiError> {
        let now = self.now();
        let (id, actor) = (id.clone(), actor.clone());
        let conn = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut row = store::get_connection(&tx, &id)?.ok_or_else(ApiError::not_found)?;
                validate_projects(&tx, &allowed_projects)?;
                match row.conn.status {
                    ConnectionStatus::Removed => return Err(ApiError::not_found().into()),
                    ConnectionStatus::Pending => {
                        if let Some(p) = store::pairing_for_connection(&tx, &id)? {
                            if p.status == PairStatus::Pending && now >= p.expires_at {
                                expire_pairing(&tx, &id, &now)?;
                                tx.commit()?;
                                return Err(err(
                                    ErrorCode::ApprovalExpired,
                                    "连接请求已过期，请在 AI 应用中重新发起",
                                    "The connection request expired; start pairing again from the AI app.",
                                )
                                .into());
                            }
                            if p.status != PairStatus::Pending {
                                return Err(ApiError::invalid_request("该连接请求已处理", "This connection request was already handled.").into());
                            }
                        }
                        row.conn.status = ConnectionStatus::Active;
                        row.conn.approved_at = Some(now);
                        row.conn.approved_by = actor.device().cloned();
                    }
                    ConnectionStatus::Active | ConnectionStatus::Paused => {}
                }
                row.conn.allowed_projects = allowed_projects;
                store::save_connection(&tx, &row.conn)?;
                store::set_pairing_status(&tx, &id, PairStatus::Approved)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(actor.audit_name(), "connection.approved").detail(json!({
                        "connection_id": id.as_str(),
                        "allowed_projects": serde_json::to_value(&row.conn.allowed_projects)?,
                    })),
                )?;
                tx.commit()?;
                Ok(row.conn)
            })
            .await?;
        self.emit(BrokerEvent::ConnectionUpdated {
            connection: Box::new(conn.clone()),
        });
        Ok(conn)
    }

    /// Deny a pending connection.
    pub async fn deny_connection(&self, actor: &Actor, id: &ConnectionId) -> Result<AppConnection, ApiError> {
        let now = self.now();
        let (id, actor) = (id.clone(), actor.clone());
        let conn = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut row = store::get_connection(&tx, &id)?.ok_or_else(ApiError::not_found)?;
                if row.conn.status != ConnectionStatus::Pending {
                    return Err(ApiError::invalid_request("只能拒绝待确认的连接", "Only pending connections can be denied.").into());
                }
                row.conn.status = ConnectionStatus::Removed;
                store::save_connection(&tx, &row.conn)?;
                store::set_pairing_status(&tx, &id, PairStatus::Denied)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(actor.audit_name(), "connection.denied")
                        .outcome("denied")
                        .detail(json!({ "connection_id": id.as_str() })),
                )?;
                tx.commit()?;
                Ok(row.conn)
            })
            .await?;
        self.emit(BrokerEvent::ConnectionUpdated {
            connection: Box::new(conn.clone()),
        });
        Ok(conn)
    }

    /// `pause` / `resume` / `remove` / `revoke_all`.
    ///
    /// * pause — new requests get `CONNECTION_PAUSED`; pending approvals and queued
    ///   operations are cancelled; running operations finish.
    /// * resume — back to active.
    /// * remove — status `removed`, tokens revoked, every grant revoked
    ///   (`revoke_upstream` level), pending approvals cancelled.
    /// * revoke_all — every grant revoked (`revoke_upstream`), approvals cancelled; the
    ///   connection itself stays.
    pub async fn control_connection(
        self: &Arc<Self>,
        actor: &Actor,
        id: &ConnectionId,
        action: ControlAction,
    ) -> Result<RevokeAllResponse, ApiError> {
        let now = self.now();
        let (cid, act) = (id.clone(), actor.clone());
        let conn = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut row = store::get_connection(&tx, &cid)?.ok_or_else(ApiError::not_found)?;
                let (action_name, new_status) = match action {
                    ControlAction::Pause => match row.conn.status {
                        ConnectionStatus::Active | ConnectionStatus::Paused => ("connection.paused", ConnectionStatus::Paused),
                        _ => return Err(ApiError::invalid_request("只能暂停已启用的连接", "Only active connections can be paused.").into()),
                    },
                    ControlAction::Resume => match row.conn.status {
                        ConnectionStatus::Paused | ConnectionStatus::Active => ("connection.resumed", ConnectionStatus::Active),
                        _ => return Err(ApiError::invalid_request("只能恢复已暂停的连接", "Only paused connections can be resumed.").into()),
                    },
                    ControlAction::Remove => {
                        if row.conn.status == ConnectionStatus::Removed {
                            return Err(ApiError::not_found().into());
                        }
                        tx.execute(
                            "UPDATE connection_tokens SET revoked_at = ?2 WHERE connection_id = ?1 AND revoked_at IS NULL",
                            params![cid.as_str(), unix(&now)],
                        )?;
                        store::set_pairing_status(&tx, &cid, PairStatus::Denied)?;
                        disable_rules(&tx, &cid, &act, now, "connection_removed")?;
                        ("connection.removed", ConnectionStatus::Removed)
                    }
                    ControlAction::RevokeAll => {
                        if row.conn.status == ConnectionStatus::Removed {
                            return Err(ApiError::not_found().into());
                        }
                        // "全部已收回" includes standing rules: otherwise a rule would
                        // silently re-create access after its TTL window (A09, §8.3).
                        disable_rules(&tx, &cid, &act, now, "connection_revoke_all")?;
                        ("connection.revoke_all", row.conn.status)
                    }
                };
                row.conn.status = new_status;
                store::save_connection(&tx, &row.conn)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act.audit_name(), action_name).detail(json!({ "connection_id": cid.as_str() })),
                )?;
                tx.commit()?;
                Ok(row.conn)
            })
            .await?;

        let mut reports = Vec::new();
        match action {
            ControlAction::Pause => {
                self.cancel_pending_approvals_for_connection(id, "connection_paused").await;
                for (_, f) in self.inflight_for_connection(id) {
                    if !f.started.load(std::sync::atomic::Ordering::SeqCst) {
                        f.cancel_with(Some(ErrorCode::ConnectionPaused));
                    }
                }
            }
            ControlAction::Resume => {}
            ControlAction::Remove | ControlAction::RevokeAll => {
                self.cancel_pending_approvals_for_connection(id, "connection_revoked").await;
                let cid = id.clone();
                let grants = self
                    .db
                    .call(move |c| {
                        store::query_grants(
                            c,
                            "connection_id = ?1 AND status IN ('active', 'exhausted')",
                            &[&cid.as_str()],
                        )
                    })
                    .await?;
                reports = self
                    .revoke_grants(actor, grants.into_iter().map(|g| g.grant.grant_id).collect(), RevocationLevel::RevokeUpstream)
                    .await?;
            }
        }
        self.emit(BrokerEvent::ConnectionUpdated {
            connection: Box::new(conn.clone()),
        });
        Ok(RevokeAllResponse {
            connection: conn,
            reports,
        })
    }

    /// Issue a new `aipc_…` bearer token for a connection (remote MCP / SDK clients that
    /// cannot sign). Returned once; stored only as a SHA-256 hash.
    pub async fn issue_connection_token(&self, actor: &Actor, id: &ConnectionId) -> Result<TokenResponse, ApiError> {
        let token = aipass_crypto::rng::random_token(token_prefix::CONNECTION, 32).map_err(|_| ApiError::internal())?;
        let hash = signing::token_hash(token.expose());
        let now = self.now();
        let (cid, act) = (id.clone(), actor.clone());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                let row = store::get_connection(&tx, &cid)?.ok_or_else(ApiError::not_found)?;
                if row.conn.status == ConnectionStatus::Removed {
                    return Err(ApiError::not_found().into());
                }
                tx.execute(
                    "INSERT INTO connection_tokens (token_hash, connection_id, created_at) VALUES (?1, ?2, ?3)",
                    params![hash, cid.as_str(), unix(&now)],
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act.audit_name(), "connection.token_issued").detail(json!({ "connection_id": cid.as_str() })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(TokenResponse {
            connection_id: id.clone(),
            token: token.expose().to_owned(),
        })
    }

    /// Admin-provisioned active connection (e.g. a remote SDK agent). Issues a bearer
    /// token when no public key is supplied.
    pub async fn create_connection(&self, actor: &Actor, input: NewConnection) -> Result<CreatedConnection, ApiError> {
        let display_name = validate_display_name(&input.display_name)?;
        if let Some(pk) = &input.public_key {
            validate_public_key(pk)?;
        }
        let now = self.now();
        let conn = AppConnection {
            connection_id: ConnectionId::generate(),
            host_type: input.host_type,
            display_name,
            transport: input.transport,
            status: ConnectionStatus::Active,
            public_key: input.public_key.clone(),
            allowed_projects: input.allowed_projects,
            created_at: now,
            approved_at: Some(now),
            approved_by: actor.device().cloned(),
            last_seen_at: None,
        };
        let (c2, act) = (conn.clone(), actor.clone());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                validate_projects(&tx, &c2.allowed_projects)?;
                store::insert_connection(&tx, &c2)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act.audit_name(), "connection.created").detail(json!({
                        "connection_id": c2.connection_id.as_str(),
                        "host_type": enum_str(&c2.host_type),
                        "allowed_projects": serde_json::to_value(&c2.allowed_projects)?,
                    })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        let token = if input.public_key.is_none() {
            Some(self.issue_connection_token(actor, &conn.connection_id).await?.token)
        } else {
            None
        };
        self.emit(BrokerEvent::ConnectionUpdated {
            connection: Box::new(conn.clone()),
        });
        Ok(CreatedConnection { connection: conn, token })
    }

    /// Insert or replace a connection record verbatim (state import / restore, tests).
    pub async fn import_connection(&self, conn: AppConnection) -> Result<(), ApiError> {
        if let Some(pk) = &conn.public_key {
            validate_public_key(pk)?;
        }
        let now = self.now();
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                if store::get_connection(&tx, &conn.connection_id)?.is_some() {
                    store::save_connection(&tx, &conn)?;
                    tx.execute(
                        "UPDATE connections SET public_key = ?2, host_type = ?3, transport = ?4 WHERE connection_id = ?1",
                        params![conn.connection_id.as_str(), conn.public_key, enum_str(&conn.host_type), enum_str(&conn.transport)],
                    )?;
                } else {
                    store::insert_connection(&tx, &conn)?;
                }
                audit::append(
                    &tx,
                    now,
                    Audit::new("admin", "connection.imported").detail(json!({ "connection_id": conn.connection_id.as_str() })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }
}

/// Mark a pending pairing expired and its never-approved connection removed.
pub(crate) fn expire_pairing(c: &rusqlite::Connection, conn: &ConnectionId, now: &aipass_types::Timestamp) -> SResult<()> {
    store::set_pairing_status(c, conn, PairStatus::Expired)?;
    c.execute(
        "UPDATE connections SET status = 'removed' WHERE connection_id = ?1 AND status = 'pending'",
        params![conn.as_str()],
    )?;
    audit::append(
        c,
        *now,
        Audit::new("system", "connection.pairing_expired")
            .outcome("expired")
            .detail(json!({ "connection_id": conn.as_str() })),
    )?;
    Ok(())
}

/// Disable a connection's standing rules (revoke-all / remove), audited.
fn disable_rules(
    tx: &rusqlite::Connection,
    cid: &ConnectionId,
    actor: &Actor,
    now: aipass_types::Timestamp,
    reason: &str,
) -> crate::error::SResult<()> {
    let n = store::disable_policies(tx, "subject_connection_id", cid.as_str(), &now)?;
    if n > 0 {
        audit::append(
            tx,
            now,
            Audit::new(actor.audit_name(), "policy.disabled")
                .detail(json!({ "reason": reason, "connection_id": cid.as_str(), "count": n })),
        )?;
    }
    Ok(())
}

/// Attach the pairing code of a pending connection whose pairing is still open.
fn connection_view(c: &rusqlite::Connection, conn: AppConnection, now: &aipass_types::Timestamp) -> SResult<ConnectionView> {
    let pairing = if conn.status == ConnectionStatus::Pending {
        store::pairing_for_connection(c, &conn.connection_id)?.filter(|p| p.status == PairStatus::Pending && *now < p.expires_at)
    } else {
        None
    };
    Ok(ConnectionView {
        connection: conn,
        pairing_code: pairing.as_ref().map(|p| p.pairing_code.clone()),
        pairing_expires_at: pairing.map(|p| p.expires_at),
    })
}
