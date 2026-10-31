// SPDX-License-Identifier: Apache-2.0
//! `demo` site adapter: plain HTTP-form sign-up / login against the bundled demo site
//! (`examples/demo_site.rs`). It exists to exercise the account-creation protocol end to end;
//! it is not a browser driver.
//!
//! Endpoints of the demo site (form-encoded requests, JSON responses):
//! `POST /api/signup` (`Idempotency-Key` header) → 201 created · 202 verify e-mail ·
//! 409 username taken · 400 invalid; `GET /api/exists?username=` → `{"exists":bool}`;
//! `POST /api/login` → 200 + `{"session":…}` / 401; `GET /api/profile` with
//! `Authorization: Session <token>` → profile JSON.

use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_types::error::Localized;
use aipass_types::{ApiError, ErrorCode};
use async_trait::async_trait;
use serde_json::Value;
use url::{Host, Url};

use super::accounts::{
    SignupOutcome, SignupProfile, SiteAction, SiteAdapter, SiteAdapterInfo, SiteLogin,
};
use crate::errors;

/// Adapter for the bundled demo site.
pub struct DemoSiteAdapter {
    base: Url,
    client: reqwest::Client,
}

impl std::fmt::Debug for DemoSiteAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DemoSiteAdapter")
            .field("origin", &self.base.origin().ascii_serialization())
            .finish()
    }
}

impl DemoSiteAdapter {
    /// Adapter for a demo site at `base` — `https://…`, or `http://` on a loopback address
    /// only (the bundled site runs locally). `timeout` bounds every request.
    pub fn new(base: &str, timeout: Duration) -> Result<Self, ApiError> {
        let base = Url::parse(base).map_err(|_| errors::bad_config("base_url"))?;
        let loopback = match base.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(d)) => d == "localhost",
            None => false,
        };
        let ok = match base.scheme() {
            "https" => true,
            "http" => loopback,
            _ => false,
        };
        if !ok || !base.username().is_empty() || base.password().is_some() {
            return Err(errors::bad_config("base_url"));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|_| ApiError::internal())?;
        Ok(Self { base, client })
    }

    fn url(&self, path: &str) -> Result<Url, ApiError> {
        let u = self.base.join(path).map_err(|_| ApiError::internal())?;
        if u.origin() != self.base.origin() {
            return Err(ApiError::internal());
        }
        Ok(u)
    }

    fn unreachable() -> ApiError {
        errors::upstream(
            "connect",
            "无法连接演示网站",
            "Could not reach the demo site.",
        )
    }
}

#[async_trait]
impl SiteAdapter for DemoSiteAdapter {
    fn info(&self) -> SiteAdapterInfo {
        SiteAdapterInfo {
            id: "demo".into(),
            origin: self.base.origin().ascii_serialization(),
            display_name: Localized::new("演示网站（实验性）", "Demo site (experimental)"),
            may_require_email_verification: true,
            fees: None,
            actions: vec![SiteAction {
                name: "account.profile".into(),
                read_only: true,
                allowed_fields: vec!["username".into(), "plan".into(), "created_at".into()],
                description: Localized::new(
                    "读取账号资料（用户名、套餐、创建时间）",
                    "Read the account profile (username, plan, created_at)",
                ),
            }],
        }
    }

    async fn account_exists(&self, username: &str) -> Result<Option<bool>, ApiError> {
        let mut u = self.url("/api/exists")?;
        u.query_pairs_mut().append_pair("username", username);
        let resp = match self.client.get(u).send().await {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        if !resp.status().is_success() {
            return Ok(None);
        }
        let v: Value = resp.json().await.map_err(|_| Self::unreachable())?;
        Ok(v.get("exists").and_then(Value::as_bool))
    }

    async fn submit_signup(
        &self,
        profile: &SignupProfile,
        password: &SecretString,
        idempotency_key: &str,
    ) -> Result<SignupOutcome, ApiError> {
        let form = [
            ("username", profile.username.as_str()),
            ("email", profile.email.as_str()),
            (
                "display_name",
                profile.display_name.as_deref().unwrap_or(""),
            ),
            ("password", password.expose()),
        ];
        let resp = self
            .client
            .post(self.url("/api/signup")?)
            .header("Idempotency-Key", idempotency_key)
            .form(&form)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            // Connect failure: nothing reached the site.
            Err(e) if e.is_connect() => return Err(Self::unreachable()),
            // Timeout / broken connection after sending: the site may have created it.
            Err(_) => return Ok(SignupOutcome::Unknown),
        };
        match resp.status().as_u16() {
            200 | 201 => Ok(SignupOutcome::Created),
            202 => Ok(SignupOutcome::NeedsVerification),
            409 => Err(ApiError::new(ErrorCode::InvalidRequest)
                .with_message("该用户名已被占用", "That username is already taken.")
                .with_detail("reason", "username_taken")),
            400 | 422 => Err(errors::invalid(
                "网站拒绝了注册资料",
                "The site rejected the sign-up data.",
            )),
            _ => Ok(SignupOutcome::Unknown),
        }
    }

    async fn verify_login(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<bool, ApiError> {
        let resp = self
            .client
            .post(self.url("/api/login")?)
            .form(&[("username", username), ("password", password.expose())])
            .send()
            .await
            .map_err(|_| Self::unreachable())?;
        Ok(resp.status().is_success())
    }

    async fn run_action(
        &self,
        action: &str,
        login: &SiteLogin,
        _params: &Value,
    ) -> Result<Value, ApiError> {
        if action != "account.profile" {
            return Err(errors::scope_denied("未适配的动作", "Action not adapted."));
        }
        let resp = self
            .client
            .post(self.url("/api/login")?)
            .form(&[
                ("username", login.username.as_str()),
                ("password", login.password.expose()),
            ])
            .send()
            .await
            .map_err(|_| Self::unreachable())?;
        if resp.status().as_u16() == 401 {
            return Err(errors::interactive_auth("demo"));
        }
        let v: Value = resp.json().await.map_err(|_| Self::unreachable())?;
        let token = v
            .get("session")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let token = SecretString::new(token);
        let resp = self
            .client
            .get(self.url("/api/profile")?)
            .header("Authorization", format!("Session {}", token.expose()))
            .send()
            .await
            .map_err(|_| Self::unreachable())?;
        if !resp.status().is_success() {
            return Err(errors::upstream(
                "upstream_status",
                "演示网站返回错误",
                "The demo site returned an error.",
            ));
        }
        resp.json().await.map_err(|_| Self::unreachable())
    }
}
