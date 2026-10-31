// SPDX-License-Identifier: Apache-2.0
//! A tiny demo web site for the experimental `demo` SiteAdapter (accounts.create /
//! browser.start_task). Plain HTTP forms, in-memory accounts. Used by the tests and by
//! `cargo run -p aipass-executor --example demo_site`.
//!
//! Behaviour switches (for exercising every outcome):
//! * e-mail ending in `@verify.example` → `202` "verify your e-mail";
//! * username starting with `slow` → the account is created, then the response is delayed
//!   (`slow_ms`, default 3000 ms) so the client times out → outcome `unknown`;
//! * existing username → `409`; password shorter than 12 → `400`;
//! * `Idempotency-Key` → a repeated key replays the first response without creating again.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone)]
struct Account {
    email: String,
    password: String,
    created_at: String,
}

/// Site state.
#[derive(Default)]
pub struct SiteState {
    accounts: Mutex<HashMap<String, Account>>,
    idem: Mutex<HashMap<String, (u16, Value)>>,
    sessions: Mutex<HashMap<String, String>>,
    seen_keys: Mutex<std::collections::HashSet<String>>,
    /// Accounts actually created.
    pub signups: AtomicUsize,
    /// Signup requests received (including replays and rejections).
    pub signup_requests: AtomicUsize,
    /// Delay for `slow*` usernames.
    pub slow_ms: AtomicU64,
}

impl SiteState {
    /// Whether `username` exists.
    pub fn has_account(&self, username: &str) -> bool {
        self.accounts.lock().unwrap().contains_key(username)
    }

    /// Whether a sign-up request with this idempotency key was received.
    pub fn saw_key(&self, key: &str) -> bool {
        self.seen_keys.lock().unwrap().contains(key)
    }
}

#[derive(Deserialize)]
struct SignupForm {
    username: String,
    email: String,
    #[serde(default)]
    display_name: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ExistsQuery {
    username: String,
}

async fn index() -> Html<&'static str> {
    Html(
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>AI Pass demo site</title>\
         <h1>演示网站 / Demo site</h1><p>仅用于测试实验性的账号创建流程。/ For testing the experimental account-creation flow only.</p>\
         <form method=\"post\" action=\"/api/signup\"><input name=\"username\" placeholder=\"username\">\
         <input name=\"email\" placeholder=\"email\"><input name=\"password\" type=\"password\" placeholder=\"password\">\
         <button>注册 / Sign up</button></form></html>",
    )
}

async fn signup(
    State(st): State<Arc<SiteState>>,
    headers: HeaderMap,
    Form(f): Form<SignupForm>,
) -> Response {
    st.signup_requests.fetch_add(1, Ordering::SeqCst);
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if let Some(k) = &key {
        st.seen_keys.lock().unwrap().insert(k.clone());
    }
    if let Some(k) = &key
        && let Some((code, body)) = st.idem.lock().unwrap().get(k).cloned()
    {
        return (
            StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
            Json(body),
        )
            .into_response();
    }
    let _ = f.display_name;
    if f.username.len() < 3 || !f.email.contains('@') || f.password.chars().count() < 12 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid"}))).into_response();
    }
    {
        let mut accounts = st.accounts.lock().unwrap();
        if accounts.contains_key(&f.username) {
            return (StatusCode::CONFLICT, Json(json!({"error": "taken"}))).into_response();
        }
        accounts.insert(
            f.username.clone(),
            Account {
                email: f.email.clone(),
                password: f.password.clone(),
                created_at: "2026-10-30T12:00:00Z".into(),
            },
        );
    }
    st.signups.fetch_add(1, Ordering::SeqCst);
    let (code, body) = if f.email.ends_with("@verify.example") {
        (202u16, json!({"status": "verify_email"}))
    } else {
        (201u16, json!({"status": "created"}))
    };
    if let Some(k) = key {
        st.idem.lock().unwrap().insert(k, (code, body.clone()));
    }
    if f.username.starts_with("slow") {
        let ms = match st.slow_ms.load(Ordering::SeqCst) {
            0 => 3000,
            n => n,
        };
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    (
        StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
        Json(body),
    )
        .into_response()
}

async fn exists(State(st): State<Arc<SiteState>>, Query(q): Query<ExistsQuery>) -> Json<Value> {
    Json(json!({"exists": st.has_account(&q.username)}))
}

async fn login(State(st): State<Arc<SiteState>>, Form(f): Form<LoginForm>) -> Response {
    let ok = st
        .accounts
        .lock()
        .unwrap()
        .get(&f.username)
        .is_some_and(|a| a.password == f.password);
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "bad credentials"})),
        )
            .into_response();
    }
    let token = aipass_crypto::b64u::encode(aipass_crypto::rng::random_array::<18>());
    st.sessions
        .lock()
        .unwrap()
        .insert(token.clone(), f.username);
    Json(json!({"session": token})).into_response()
}

async fn profile(State(st): State<Arc<SiteState>>, headers: HeaderMap) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Session "))
        .unwrap_or("")
        .to_owned();
    let Some(user) = st.sessions.lock().unwrap().get(&token).cloned() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(acc) = st.accounts.lock().unwrap().get(&user).cloned() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Deliberately over-shares (password, session) so the adapter's output filter is tested.
    Json(
        json!({"username": user, "email": acc.email, "plan": "free", "created_at": acc.created_at,
                "password_hint": acc.password, "session": token}),
    )
    .into_response()
}

/// The router.
pub fn router(state: Arc<SiteState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/signup", post(signup))
        .route("/api/exists", get(exists))
        .route("/api/login", post(login))
        .route("/api/profile", get(profile))
        .with_state(state)
}

/// A running demo site.
pub struct DemoSite {
    /// Address.
    pub addr: SocketAddr,
    /// State.
    pub state: Arc<SiteState>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DemoSite {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DemoSite {
    /// Start on `addr` (`127.0.0.1:0` for an ephemeral port).
    pub async fn start_on(addr: &str) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(SiteState::default());
        let app = router(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { addr, state, task })
    }

    /// Base URL.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}
