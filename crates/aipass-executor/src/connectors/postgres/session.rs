// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL sessions: TLS per `sslmode`, connection, privilege check, per-grant pool,
//! cancellation and error mapping.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_types::{ApiError, GrantId};
use rustls::pki_types::CertificateDer;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{CancelToken, Client, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

use super::config::{PgConfig, SslModeCfg};
use crate::connectors::SessionsClosed;
use crate::errors;

/// Max concurrent sessions per grant.
pub const MAX_SESSIONS_PER_GRANT: usize = 4;
/// Idle sessions are closed after this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// TLS connector for a session (kept for sending cancel requests over the same TLS mode).
#[derive(Clone)]
pub(crate) enum PgTls {
    Plain,
    Tls(MakeRustlsConnect),
}

/// Where to connect.
#[derive(Clone)]
pub(crate) struct PgTarget {
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub sslmode: SslModeCfg,
    pub roots: Vec<CertificateDer<'static>>,
    pub connect_timeout: Duration,
}

impl PgTarget {
    pub fn from_config(cfg: &PgConfig) -> Result<Self, ApiError> {
        let roots = match &cfg.ssl_root_cert {
            Some(pem) => {
                crate::tls::parse_pem_certs(pem).map_err(|_| errors::bad_config("ssl_root_cert"))?
            }
            None => Vec::new(),
        };
        Ok(Self {
            host: cfg.host.clone(),
            port: cfg.port,
            dbname: cfg.dbname.clone(),
            sslmode: cfg.sslmode,
            roots,
            connect_timeout: cfg.connect_timeout(),
        })
    }

    fn tls(&self) -> Result<(SslMode, PgTls), ApiError> {
        let setup = |r: Result<rustls::ClientConfig, crate::tls::TlsSetupError>| {
            r.map(MakeRustlsConnect::new)
                .map_err(|_| errors::bad_config("ssl_root_cert"))
        };
        Ok(match self.sslmode {
            SslModeCfg::Disable => (SslMode::Disable, PgTls::Plain),
            SslModeCfg::Prefer => (
                SslMode::Prefer,
                PgTls::Tls(setup(crate::tls::encrypt_only_config())?),
            ),
            SslModeCfg::Require if self.roots.is_empty() => (
                SslMode::Require,
                PgTls::Tls(setup(crate::tls::encrypt_only_config())?),
            ),
            SslModeCfg::Require => (
                SslMode::Require,
                PgTls::Tls(setup(crate::tls::verify_ca_config(&self.roots))?),
            ),
            SslModeCfg::VerifyFull => (
                SslMode::Require,
                PgTls::Tls(setup(crate::tls::webpki_config(true, &self.roots, false))?),
            ),
        })
    }
}

/// What kind of session: query sessions default every transaction to read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionKind {
    /// `postgres.query_view` (read-only by default, plus `BEGIN READ ONLY`).
    Query,
    /// Fixed administrative statements (rotation, temporary roles).
    #[cfg_attr(not(feature = "experimental"), allow(dead_code))]
    Control,
}

/// An open session.
pub(crate) struct Session {
    pub client: Client,
    task: JoinHandle<()>,
    pub cancel_token: CancelToken,
    pub tls: PgTls,
    /// Identifies the credential the session authenticated with.
    pub cred_key: u64,
    pub last_used: Instant,
}

impl Session {
    /// Ask the server to cancel the running statement.
    pub async fn send_cancel(token: &CancelToken, tls: &PgTls) -> bool {
        let fut = async {
            match tls {
                PgTls::Plain => token.cancel_query(NoTls).await,
                PgTls::Tls(m) => token.cancel_query(m.clone()).await,
            }
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(5), fut).await,
            Ok(Ok(()))
        )
    }

    /// Close the session (drops the client, stops the connection task).
    pub fn close(self) {
        drop(self.client);
        self.task.abort();
    }
}

/// Map a driver error to an API error without copying the server message (which can
/// contain data values).
pub(crate) fn map_pg_error(e: &tokio_postgres::Error) -> ApiError {
    let Some(code) = e.code() else {
        if e.is_closed() {
            return errors::upstream(
                "connection_closed",
                "数据库连接已关闭",
                "The database connection was closed.",
            );
        }
        return errors::upstream(
            "connect",
            "无法连接数据库（网络、TLS 或证书校验失败）",
            "Could not connect to the database (network, TLS or certificate verification failed).",
        );
    };
    let sqlstate = code.code().to_owned();
    let with = |e: ApiError| e.with_detail("sqlstate", sqlstate.clone());
    if *code == SqlState::INSUFFICIENT_PRIVILEGE {
        return with(errors::scope_denied(
            "数据库拒绝了对该对象的访问",
            "The database denied access to this object.",
        ));
    }
    if *code == SqlState::READ_ONLY_SQL_TRANSACTION {
        return with(errors::scope_denied(
            "只读查询中出现写操作，已被数据库拒绝",
            "A write was attempted inside the read-only query and was refused.",
        ));
    }
    if *code == SqlState::INVALID_PASSWORD || *code == SqlState::INVALID_AUTHORIZATION_SPECIFICATION
    {
        return with(errors::interactive_auth("PostgreSQL"));
    }
    if *code == SqlState::QUERY_CANCELED {
        return with(errors::upstream(
            "statement_timeout",
            "查询超时，已由数据库取消",
            "The query exceeded the statement timeout and was cancelled.",
        ));
    }
    if *code == SqlState::UNDEFINED_TABLE
        || *code == SqlState::UNDEFINED_COLUMN
        || *code == SqlState::UNDEFINED_OBJECT
    {
        return with(errors::upstream(
            "undefined_object",
            "配置的视图或字段在数据库中不存在",
            "A configured view or field does not exist in the database.",
        ));
    }
    if sqlstate.starts_with("22") {
        return with(errors::invalid(
            "过滤条件的取值与字段类型不匹配",
            "A filter value does not match the column type.",
        ));
    }
    if sqlstate.starts_with("08") || sqlstate.starts_with("53") || sqlstate.starts_with("57") {
        return with(errors::upstream(
            "unavailable",
            "数据库暂时不可用",
            "The database is temporarily unavailable.",
        ));
    }
    with(errors::upstream(
        "database_error",
        "数据库返回错误",
        "The database returned an error.",
    ))
}

/// Open a session. Query sessions get `default_transaction_read_only=on`.
pub(crate) async fn connect(
    target: &PgTarget,
    user: &str,
    password: &str,
    kind: SessionKind,
    cred_key: u64,
) -> Result<Session, ApiError> {
    let (ssl_mode, tls) = target.tls()?;
    let mut cfg = tokio_postgres::Config::new();
    if target.host.starts_with('/') {
        #[cfg(unix)]
        {
            cfg.host_path(&target.host);
        }
        #[cfg(not(unix))]
        {
            return Err(errors::bad_config("host"));
        }
    } else {
        cfg.host(&target.host);
    }
    cfg.port(target.port)
        .dbname(&target.dbname)
        .user(user)
        .password(password.as_bytes())
        .ssl_mode(ssl_mode)
        .application_name("aipass-executor")
        .connect_timeout(target.connect_timeout)
        .keepalives(true);
    let opts = match kind {
        SessionKind::Query => {
            "-c default_transaction_read_only=on -c idle_in_transaction_session_timeout=30000"
        }
        SessionKind::Control => "-c idle_in_transaction_session_timeout=30000",
    };
    cfg.options(opts);
    let overall = target.connect_timeout + Duration::from_secs(5);
    let connected = match &tls {
        PgTls::Plain => {
            let r = tokio::time::timeout(overall, cfg.connect(NoTls)).await;
            match r {
                Ok(Ok((client, conn))) => {
                    let task = tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    Ok((client, task))
                }
                Ok(Err(e)) => Err(map_pg_error(&e)),
                Err(_) => Err(errors::upstream(
                    "connect_timeout",
                    "连接数据库超时",
                    "Connecting to the database timed out.",
                )),
            }
        }
        PgTls::Tls(maker) => {
            let r = tokio::time::timeout(overall, cfg.connect(maker.clone())).await;
            match r {
                Ok(Ok((client, conn))) => {
                    let task = tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    Ok((client, task))
                }
                Ok(Err(e)) => Err(map_pg_error(&e)),
                Err(_) => Err(errors::upstream(
                    "connect_timeout",
                    "连接数据库超时",
                    "Connecting to the database timed out.",
                )),
            }
        }
    };
    let (client, task) = connected?;
    let cancel_token = client.cancel_token();
    Ok(Session {
        client,
        task,
        cancel_token,
        tls,
        cred_key,
        last_used: Instant::now(),
    })
}

/// Privileges of the session role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RolePrivileges {
    pub superuser: bool,
    pub bypass_rls: bool,
    /// Memberships in server-file / program roles.
    pub file_roles: Vec<String>,
}

impl RolePrivileges {
    pub fn is_privileged(&self) -> bool {
        self.superuser || self.bypass_rls || !self.file_roles.is_empty()
    }
}

/// Inspect the current role.
pub(crate) async fn role_privileges(client: &Client) -> Result<RolePrivileges, ApiError> {
    let row = client
        .query_one(
            "SELECT r.rolsuper, r.rolbypassrls, \
               (SELECT pg_catalog.string_agg(b.rolname::text, ',') FROM pg_catalog.pg_roles b \
                 WHERE b.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program') \
                   AND pg_catalog.pg_has_role(current_user, b.oid, 'MEMBER')) \
             FROM pg_catalog.pg_roles r WHERE r.rolname = current_user",
            &[],
        )
        .await
        .map_err(|e| map_pg_error(&e))?;
    let file_roles: Option<String> = row.get(2);
    Ok(RolePrivileges {
        superuser: row.get(0),
        bypass_rls: row.get(1),
        file_roles: file_roles
            .map(|s| s.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
    })
}

/// The refusal for privileged roles.
pub(crate) fn privileged_role_error() -> ApiError {
    errors::scope_denied(
        "数据库账号权限过高（超级用户、BYPASSRLS 或服务器文件访问角色），已拒绝使用；请为 AI 配置只读角色",
        "The database role is too privileged (superuser, BYPASSRLS or server-file roles) and was refused; configure a read-only role for AI use.",
    )
    .with_detail("reason", "privileged_role")
}

// ======================================================================================
// Pool
// ======================================================================================

struct ActiveQuery {
    token: CancelToken,
    tls: PgTls,
}

struct GrantPool {
    idle: Vec<Session>,
    active: HashMap<u64, ActiveQuery>,
    permits: Arc<Semaphore>,
}

impl GrantPool {
    fn new() -> Self {
        Self {
            idle: Vec::new(),
            active: HashMap::new(),
            permits: Arc::new(Semaphore::new(MAX_SESSIONS_PER_GRANT)),
        }
    }
}

/// Per-grant session pool. A grant's sessions are closed by [`SessionPool::close_grant`]
/// (end_sessions / revocation); a session opened with an older credential installation is
/// never reused.
#[derive(Default)]
pub(crate) struct SessionPool {
    grants: Mutex<HashMap<GrantId, GrantPool>>,
    next_active: std::sync::atomic::AtomicU64,
}

/// A checked-out session slot.
pub(crate) struct Lease {
    pub grant_id: GrantId,
    pub active_id: u64,
    _permit: OwnedSemaphorePermit,
}

impl SessionPool {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<GrantId, GrantPool>> {
        self.grants.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Wait for a session slot of `grant_id`. Fails (as cancelled) when the grant's sessions
    /// are being closed concurrently.
    pub async fn acquire(&self, grant_id: &GrantId) -> Result<Lease, ApiError> {
        let permits = {
            let mut g = self.lock();
            g.entry(grant_id.clone())
                .or_insert_with(GrantPool::new)
                .permits
                .clone()
        };
        let permit = permits
            .acquire_owned()
            .await
            .map_err(|_| errors::cancelled())?;
        Ok(Lease {
            grant_id: grant_id.clone(),
            active_id: self
                .next_active
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            _permit: permit,
        })
    }

    /// Take an idle session authenticated with `cred_key`, closing stale ones.
    pub fn take_idle(&self, grant_id: &GrantId, cred_key: u64) -> Option<Session> {
        let mut g = self.lock();
        let pool = g.get_mut(grant_id)?;
        let mut found = None;
        let mut stale = Vec::new();
        while let Some(s) = pool.idle.pop() {
            if s.cred_key == cred_key
                && !s.client.is_closed()
                && s.last_used.elapsed() < IDLE_TIMEOUT
            {
                found = Some(s);
                break;
            }
            stale.push(s);
        }
        drop(g);
        for s in stale {
            s.close();
        }
        found
    }

    /// Register a running statement so `close_grant` can cancel it.
    pub fn mark_active(&self, lease: &Lease, session: &Session) {
        let mut g = self.lock();
        let pool = g
            .entry(lease.grant_id.clone())
            .or_insert_with(GrantPool::new);
        pool.active.insert(
            lease.active_id,
            ActiveQuery {
                token: session.cancel_token.clone(),
                tls: session.tls.clone(),
            },
        );
    }

    /// Return a session after use. If the grant was closed meanwhile (`active` entry gone),
    /// or `reuse` is false, the session is closed instead.
    pub fn release(&self, lease: Lease, mut session: Session, reuse: bool) {
        let mut g = self.lock();
        let still_open = g
            .get_mut(&lease.grant_id)
            .map(|p| p.active.remove(&lease.active_id).is_some())
            .unwrap_or(false);
        if reuse && still_open && !session.client.is_closed() {
            session.last_used = Instant::now();
            if let Some(p) = g.get_mut(&lease.grant_id) {
                p.idle.push(session);
                return;
            }
        }
        drop(g);
        session.close();
    }

    /// Close every session of `grant_id` and cancel its running statements.
    pub async fn close_grant(&self, grant_id: &GrantId) -> SessionsClosed {
        let pool = self.lock().remove(grant_id);
        let Some(pool) = pool else {
            return SessionsClosed::default();
        };
        let mut report = SessionsClosed {
            closed: pool.idle.len() + pool.active.len(),
            ..Default::default()
        };
        for s in pool.idle {
            s.close();
        }
        for (_, a) in pool.active {
            report.cancelled += 1;
            if !Session::send_cancel(&a.token, &a.tls).await {
                report.cancel_failures += 1;
            }
        }
        pool.permits.close();
        report
    }

    /// Close idle sessions older than [`IDLE_TIMEOUT`].
    pub fn sweep_idle(&self) {
        let mut stale = Vec::new();
        {
            let mut g = self.lock();
            for pool in g.values_mut() {
                let (keep, old): (Vec<Session>, Vec<Session>) = pool
                    .idle
                    .drain(..)
                    .partition(|s| s.last_used.elapsed() < IDLE_TIMEOUT && !s.client.is_closed());
                pool.idle = keep;
                stale.extend(old);
            }
            g.retain(|_, p| !p.idle.is_empty() || !p.active.is_empty());
        }
        for s in stale {
            s.close();
        }
    }

    /// Number of open sessions of a grant (idle + active).
    pub fn open_sessions(&self, grant_id: &GrantId) -> usize {
        self.lock()
            .get(grant_id)
            .map(|p| p.idle.len() + p.active.len())
            .unwrap_or(0)
    }
}
