// SPDX-License-Identifier: Apache-2.0
//! Desktop side of native messaging (CONTRACTS §11): the IPC server that
//! `aipass-nm-host` connects to, and the request handler.
//!
//! Security rules enforced here (the extension enforces its own as well):
//! * every IPC connection must present the per-install token (constant-time compare),
//!   come from the same OS user (peer uid check on Unix) and name an allowed extension
//!   origin — otherwise `NOT_PAIRED`;
//! * `match` never returns secrets; `same_site` candidates only over https;
//! * `fill` re-checks the entry against the *frame* origin, refuses cross-origin frames
//!   unless the saved origin matches exactly, never fills an https entry on http, refuses
//!   entries with sync conflicts, and is rate-limited;
//! * nothing about request bodies is logged.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_crypto::SecretString;
use aipass_nm::frame::{read_frame, write_json};
use aipass_nm::proto::{self, codes};
use aipass_sync::SaveStatus;
use aipass_types::ids::EntryId;
use aipass_vault::matching::MatchKind;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::core::AppCore;
use crate::error::UiError;

/// Sliding-window limits per request type (requests per minute).
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<&'static str, VecDeque<Instant>>>,
}

impl RateLimiter {
    fn limit_for(kind: &str) -> (&'static str, usize) {
        match kind {
            "fill" => ("fill", 20),
            "generate" => ("generate", 30),
            "save" => ("save", 20),
            "match" => ("match", 240),
            _ => ("other", 240),
        }
    }

    /// Record a request; false when over the limit.
    pub fn allow(&self, kind: &str) -> bool {
        let (key, max) = Self::limit_for(kind);
        let mut g = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let q = g.entry(key).or_default();
        let now = Instant::now();
        while q.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60)) {
            q.pop_front();
        }
        if q.len() >= max {
            return false;
        }
        q.push_back(now);
        true
    }
}

/// Parse a web origin (`scheme://host[:port]`), http or https only.
pub fn parse_origin(s: &str) -> Option<url::Url> {
    if s.len() > 2048 {
        return None;
    }
    let u = url::Url::parse(s).ok()?;
    if !(u.scheme() == "https" || u.scheme() == "http") || u.host_str().is_none() {
        return None;
    }
    if !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    Some(u)
}

fn origin_string(u: &url::Url) -> String {
    u.origin().ascii_serialization()
}

fn ui_err(id: &str, e: &UiError) -> Value {
    let code = match e.code.as_str() {
        c @ (codes::LOCKED | codes::NOT_FOUND | codes::SYNC_CONFLICT | codes::RATE_LIMITED | codes::ORIGIN_MISMATCH) => c,
        "NO_VAULT" => codes::LOCKED,
        other => other,
    };
    proto::err(id, code, &format!("{} / {}", e.message.zh, e.message.en))
}

fn str_field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

impl AppCore {
    /// Handle one §11 request (already authenticated at the IPC layer).
    pub async fn handle_nm(&self, req: &Value) -> Value {
        let Some(id) = proto::request_id(req) else {
            return json!({"ok": false, "error": {"code": "INVALID_REQUEST", "message": "missing id"}});
        };
        let kind = str_field(req, "type").unwrap_or("");
        if !self.nm_limiter.allow(kind) {
            return proto::err(id, codes::RATE_LIMITED, "请求过于频繁，请稍后再试 / Too many requests, try again shortly");
        }
        match kind {
            "hello" => proto::ok(id, json!({"app_version": self.app_version, "locked": !self.is_unlocked(), "ai_mode_available": false})),
            "status" => proto::ok(id, json!({"locked": !self.is_unlocked()})),
            "match" => self.nm_match(id, req),
            "fill" => self.nm_fill(id, req),
            "generate" => self.nm_generate(id, req),
            "save" => self.nm_save(id, req).await,
            "open_app" => {
                self.sink.emit("open-app", json!({}));
                proto::ok(id, json!({}))
            }
            "lock" => {
                self.lock_app().await;
                proto::ok(id, json!({}))
            }
            _ => proto::err(id, "INVALID_REQUEST", "未知请求类型 / Unknown request type"),
        }
    }

    fn nm_candidates(&self, origin: &url::Url) -> Result<Vec<aipass_sync::AutofillCandidate>, UiError> {
        self.require_unlocked()?;
        let mut c = self.vault.autofill_candidates(&origin_string(origin))?;
        if origin.scheme() != "https" {
            // Related-site matches only between https origins (§11.3).
            c.retain(|x| x.match_kind == MatchKind::ExactOrigin);
        }
        Ok(c)
    }

    fn nm_match(&self, id: &str, req: &Value) -> Value {
        let Some(origin) = str_field(req, "origin").and_then(parse_origin) else {
            return proto::err(id, "INVALID_REQUEST", "无效来源 / Invalid origin");
        };
        match self.nm_candidates(&origin) {
            Ok(list) => {
                let candidates: Vec<Value> = list
                    .into_iter()
                    .map(|c| {
                        json!({
                            "entry_id": c.entry_id,
                            "title": c.title,
                            // §11: no username → null (never an empty string the
                            // content script could write into a field).
                            "username": c.username.filter(|u| !u.is_empty()),
                            "match": match c.match_kind { MatchKind::ExactOrigin => "exact_origin", _ => "same_site" },
                        })
                    })
                    .collect();
                proto::ok(id, json!({"candidates": candidates}))
            }
            Err(e) => ui_err(id, &e),
        }
    }

    fn nm_fill(&self, id: &str, req: &Value) -> Value {
        if req.get("user_gesture").and_then(Value::as_bool) != Some(true) {
            return proto::err(id, "INVALID_REQUEST", "需要用户点击 / A user gesture is required");
        }
        let (Some(top), Some(frame)) = (
            str_field(req, "origin").and_then(parse_origin),
            str_field(req, "frame_origin").and_then(parse_origin),
        ) else {
            return proto::err(id, "INVALID_REQUEST", "无效来源 / Invalid origin");
        };
        let Some(entry) = str_field(req, "entry_id").and_then(|s| EntryId::parse(s).ok()) else {
            return proto::err(id, codes::NOT_FOUND, "未找到账号 / Entry not found");
        };
        if top.scheme() == "https" && frame.scheme() != "https" {
            return proto::err(id, codes::ORIGIN_MISMATCH, "不在 https 页面内的 http 框架中填充 / No filling into http frames on https pages");
        }
        let candidates = match self.nm_candidates(&frame) {
            Ok(c) => c,
            Err(e) => return ui_err(id, &e),
        };
        let Some(m) = candidates.iter().find(|c| c.entry_id == entry) else {
            // Unknown (or deleted) entry → NOT_FOUND; an existing entry saved for another
            // site → ORIGIN_MISMATCH. Nothing about the entry itself is revealed.
            if self.vault.get_item(&entry).is_err() {
                return proto::err(id, codes::NOT_FOUND, "未找到账号 / Entry not found");
            }
            return proto::err(id, codes::ORIGIN_MISMATCH, "该账号不属于此网站 / This entry does not belong to this site");
        };
        let cross_origin_frame = origin_string(&top) != origin_string(&frame);
        if cross_origin_frame && m.match_kind != MatchKind::ExactOrigin {
            return proto::err(id, codes::ORIGIN_MISMATCH, "跨站框架仅在来源完全一致时填充 / Cross-origin frames need an exact origin match");
        }
        match self.vault.autofill_credential(&entry) {
            Ok(c) => {
                let mut body = json!({"username": c.username.clone().filter(|u| !u.is_empty()), "password": c.password.expose()});
                if let Some(t) = &c.totp {
                    body["totp"] = Value::String(t.expose().to_owned());
                }
                proto::ok(id, body)
            }
            Err(e) => ui_err(id, &e.into()),
        }
    }

    fn nm_generate(&self, id: &str, req: &Value) -> Value {
        if let Err(e) = self.require_unlocked() {
            return ui_err(id, &e);
        }
        if str_field(req, "origin").and_then(parse_origin).is_none() {
            return proto::err(id, "INVALID_REQUEST", "无效来源 / Invalid origin");
        }
        let rules = str_field(req, "passwordrules");
        if rules.is_some_and(|r| r.len() > 1024) {
            return proto::err(id, "INVALID_REQUEST", "passwordrules 过长 / passwordrules too long");
        }
        let length = match req.get("length") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_u64() {
                Some(n) if (8..=128).contains(&n) => Some(n as u32),
                _ => return proto::err(id, "INVALID_REQUEST", "长度应为 8–128 / Length must be 8–128"),
            },
        };
        match aipass_vault::generator::generate_for_site(None, rules, length) {
            Ok(p) => proto::ok(id, json!({"password": p.expose()})),
            Err(e) => ui_err(id, &e.into()),
        }
    }

    async fn nm_save(&self, id: &str, req: &Value) -> Value {
        let Some(origin) = str_field(req, "origin").and_then(parse_origin) else {
            return proto::err(id, "INVALID_REQUEST", "无效来源 / Invalid origin");
        };
        let form_kind = str_field(req, "form_kind").unwrap_or("");
        if !matches!(form_kind, "login" | "signup" | "change_password") {
            return proto::err(id, "INVALID_REQUEST", "未知表单类型 / Unknown form kind");
        }
        let Some(password) = str_field(req, "password").filter(|p| !p.is_empty() && p.len() <= 4096) else {
            return proto::err(id, "INVALID_REQUEST", "缺少密码 / Missing password");
        };
        let username = str_field(req, "username").filter(|u| !u.is_empty() && u.len() <= 512);
        if let Err(e) = self.require_unlocked() {
            return ui_err(id, &e);
        }
        let res = self
            .vault
            .save_from_browser(&origin_string(&origin), username, SecretString::new(password.to_owned()), form_kind)
            .await;
        match res {
            Ok((status, entry)) => {
                let s = match status {
                    SaveStatus::Saved => "saved",
                    SaveStatus::Updated => "updated",
                    SaveStatus::NeedsConfirmation => "needs_confirmation",
                };
                if status != SaveStatus::NeedsConfirmation {
                    self.sink.emit("items-changed", json!({}));
                }
                proto::ok(id, json!({"status": s, "entry_id": entry}))
            }
            Err(e) => ui_err(id, &e.into()),
        }
    }
}

// --------------------------------------------------------------------------------------
// IPC server
// --------------------------------------------------------------------------------------

/// Read the per-install token, creating it (CSPRNG, 0600) when missing or malformed.
pub fn ensure_token(core: &AppCore) -> std::io::Result<String> {
    let home = core.paths().home();
    if let Ok(t) = aipass_nm::ipc::read_token(home) {
        return Ok(t);
    }
    crate::paths::ensure_private_dir(&core.paths().run_dir())?;
    let t = hex::encode(aipass_crypto::rng::try_random_array::<{ aipass_nm::ipc::TOKEN_BYTES }>().map_err(|_| std::io::Error::other("rng"))?);
    crate::paths::write_private(&core.paths().desktop_token(), t.as_bytes())?;
    Ok(t)
}

/// Check the auth frame. Returns the refusal code on failure.
pub fn check_auth(core: &AppCore, token: &str, frame: &Value) -> Result<(), &'static str> {
    if frame.get("type").and_then(Value::as_str) != Some("auth") {
        return Err(codes::NOT_PAIRED);
    }
    let got = frame.get("token").and_then(Value::as_str).unwrap_or("");
    if !aipass_nm::ipc::token_matches(token, got) {
        return Err(codes::NOT_PAIRED);
    }
    let origin = frame.get("origin").and_then(Value::as_str).unwrap_or("");
    if !aipass_nm::ipc::is_extension_origin(origin) {
        return Err(codes::NOT_PAIRED);
    }
    let allowed = core.settings().allowed_extension_origins;
    if !allowed.is_empty() && !allowed.iter().any(|a| a == origin) {
        return Err(codes::NOT_PAIRED);
    }
    Ok(())
}

/// Serve one authenticated IPC connection.
pub async fn serve_connection<S>(core: Arc<AppCore>, token: String, mut stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let first = match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream)).await {
        Ok(Ok(Some(f))) => f,
        _ => return,
    };
    let auth: Value = serde_json::from_slice(&first).unwrap_or(Value::Null);
    if let Err(code) = check_auth(&core, &token, &auth) {
        let _ = write_json(&mut stream, &json!({"type": "auth", "ok": false, "code": code})).await;
        return;
    }
    if write_json(&mut stream, &json!({"type": "auth", "ok": true})).await.is_err() {
        return;
    }
    loop {
        let frame = match read_frame(&mut stream).await {
            Ok(Some(f)) => f,
            _ => return,
        };
        let reply = match serde_json::from_slice::<Value>(&frame) {
            Ok(req) => core.handle_nm(&req).await,
            Err(_) => json!({"ok": false, "error": {"code": "INVALID_REQUEST", "message": "not JSON"}}),
        };
        if write_json(&mut stream, &reply).await.is_err() {
            return;
        }
    }
}

/// Run the IPC server until `shutdown`.
#[cfg(unix)]
pub async fn serve_ipc(core: Arc<AppCore>, shutdown: CancellationToken) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let token = ensure_token(&core)?;
    let path = core.paths().desktop_socket();
    crate::paths::ensure_private_dir(&core.paths().run_dir())?;
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_socket() {
            std::fs::remove_file(&path)?;
        } else {
            return Err(std::io::Error::other("desktop.sock exists and is not a socket"));
        }
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    // SAFETY-free uid lookup: compare against the owner of our own private run dir.
    let my_uid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(core.paths().run_dir())?.uid()
    };
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            acc = listener.accept() => {
                let Ok((stream, _)) = acc else { continue };
                match stream.peer_cred() {
                    Ok(c) if c.uid() == my_uid => {}
                    _ => continue,
                }
                let core = core.clone();
                let token = token.clone();
                tokio::spawn(serve_connection(core, token, stream));
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Run the IPC server until `shutdown` (Windows named pipe; not tested in this build).
#[cfg(windows)]
pub async fn serve_ipc(core: Arc<AppCore>, shutdown: CancellationToken) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let token = ensure_token(&core)?;
    let name = aipass_nm::ipc::pipe_name(core.paths().home());
    // reject_remote_clients is the default; first_pipe_instance prevents squatting.
    let mut server = ServerOptions::new().first_pipe_instance(true).create(&name)?;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            r = server.connect() => {
                r?;
                let connected = server;
                server = ServerOptions::new().create(&name)?;
                tokio::spawn(serve_connection(core.clone(), token.clone(), connected));
            }
        }
    }
    Ok(())
}
