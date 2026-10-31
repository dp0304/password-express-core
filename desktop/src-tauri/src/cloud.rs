// SPDX-License-Identifier: Apache-2.0
//! Optional AI 通行证 cloud account (CONTRACTS §13): sign-in, subscription status and
//! licence activation. The subscription account is separate from the vault: its password
//! never unlocks or decrypts anything, and a licence failure only disables premium
//! features — it never blocks unlock, export, recovery or revocation (§5.5, §16.2).
//! Licences are verified offline (Ed25519 over JCS(payload)) against a pinned key.

use std::time::Duration;

use aipass_crypto::{SecretString, b64u};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::AppCore;
use crate::error::{UiError, UiResult};

/// HTTP client for the cloud API.
pub struct CloudClient {
    http: reqwest::Client,
    base: url::Url,
}

/// Offline licence check result (§12 `LicenseStatusFfi`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseStatus {
    /// Signature, device and expiry all check out.
    pub valid: bool,
    /// Plan.
    pub plan_id: Option<String>,
    /// Premium features.
    pub features: Vec<String>,
    /// Expiry (unix seconds).
    pub expires_at: Option<i64>,
    /// Grace end (unix seconds).
    pub grace_until: Option<i64>,
    /// Why it is not valid.
    pub reason: Option<String>,
}

impl LicenseStatus {
    fn invalid(reason: &str) -> Self {
        Self { valid: false, plan_id: None, features: vec![], expires_at: None, grace_until: None, reason: Some(reason.into()) }
    }
}

/// Verify `token` = `b64u(JCS(payload)).b64u(sig)` for `device_id` at `now`.
pub fn verify_license(token: &str, public_key_b64u: &str, device_id: &str, now: i64) -> LicenseStatus {
    let Some((p, s)) = token.split_once('.') else {
        return LicenseStatus::invalid("malformed");
    };
    let (Ok(bytes), Ok(sig), Ok(pk)) = (b64u::decode(p), b64u::decode_array::<64>(s), b64u::decode_array::<32>(public_key_b64u)) else {
        return LicenseStatus::invalid("malformed");
    };
    if aipass_crypto::identity::verify(&pk, &bytes, &sig).is_err() {
        return LicenseStatus::invalid("bad_signature");
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
        return LicenseStatus::invalid("malformed");
    };
    // The signed bytes must be the canonical form (no alternative encodings accepted).
    if aipass_types::canonical::value_to_jcs(&payload).ok().as_deref() != Some(&bytes[..]) {
        return LicenseStatus::invalid("not_canonical");
    }
    let features = payload["features"]
        .as_array()
        .map(|a| a.iter().filter_map(|f| f.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let exp = payload["exp"].as_i64();
    let grace = payload["grace_until"].as_i64();
    let mut st = LicenseStatus {
        valid: true,
        plan_id: payload["plan_id"].as_str().map(str::to_owned),
        features,
        expires_at: exp,
        grace_until: grace,
        reason: None,
    };
    if payload["v"].as_i64() != Some(1) {
        st.valid = false;
        st.reason = Some("unsupported_version".into());
    } else if payload["device_id"].as_str() != Some(device_id) {
        st.valid = false;
        st.reason = Some("other_device".into());
    } else if exp.is_none_or(|e| now > e.max(grace.unwrap_or(e))) {
        st.valid = false;
        st.reason = Some("expired".into());
    }
    st
}

impl CloudClient {
    /// Client for `base` (https, or http on loopback for development).
    pub fn new(base: &str) -> UiResult<Self> {
        let base = url::Url::parse(base).map_err(|_| UiError::invalid("云端地址无效", "Invalid cloud URL"))?;
        let loopback = matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
            return Err(UiError::invalid("云端地址必须使用 https", "The cloud URL must use https"));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("aipass-desktop/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| UiError::internal("http client"))?;
        Ok(Self { http, base })
    }

    async fn call(&self, method: reqwest::Method, path: &str, token: Option<&SecretString>, body: Option<Value>) -> UiResult<Value> {
        let url = self.base.join(path).map_err(|_| UiError::internal("url"))?;
        let mut rb = self.http.request(method, url).header("Accept-Language", "zh-CN");
        if let Some(t) = token {
            rb = rb.bearer_auth(t.expose());
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.map_err(|_| {
            UiError::new("UPSTREAM_ERROR", "无法连接 AI 通行证云服务。", "Could not reach the AI Pass cloud service.")
        })?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|_| UiError::internal("cloud response"))?;
        if (200..300).contains(&status) {
            if bytes.is_empty() {
                return Ok(Value::Null);
            }
            return serde_json::from_slice(&bytes).map_err(|_| UiError::internal("cloud response"));
        }
        match serde_json::from_slice::<aipass_types::ErrorBody>(&bytes) {
            Ok(b) => Err(aipass_types::ApiError::from_body(&b).into()),
            Err(_) => Err(UiError::new("UPSTREAM_ERROR", &format!("云服务返回 {status}"), &format!("Cloud service returned {status}"))),
        }
    }

    /// `POST /v1/auth/login` → session token.
    pub async fn login(&self, email: &str, password: &SecretString) -> UiResult<(SecretString, Value)> {
        let v = self
            .call(reqwest::Method::POST, "/v1/auth/login", None, Some(json!({"email": email, "password": password.expose()})))
            .await?;
        let tok = v["session_token"].as_str().ok_or_else(|| UiError::internal("no session token"))?;
        Ok((SecretString::new(tok.to_owned()), v["user"].clone()))
    }

    /// `POST /v1/auth/logout`.
    pub async fn logout(&self, token: &SecretString) -> UiResult<()> {
        self.call(reqwest::Method::POST, "/v1/auth/logout", Some(token), None).await.map(|_| ())
    }

    /// `GET /v1/subscription`.
    pub async fn subscription(&self, token: &SecretString) -> UiResult<Value> {
        self.call(reqwest::Method::GET, "/v1/subscription", Some(token), None).await
    }

    /// `POST /v1/licenses/activate`.
    pub async fn activate(&self, token: &SecretString, device_id: &str, platform: &str, app_version: &str) -> UiResult<String> {
        let v = self
            .call(
                reqwest::Method::POST,
                "/v1/licenses/activate",
                Some(token),
                Some(json!({"device_id": device_id, "platform": platform, "app_version": app_version})),
            )
            .await?;
        v["license_token"].as_str().map(str::to_owned).ok_or_else(|| UiError::internal("no licence token"))
    }

    /// `GET /v1/licenses/public-key`.
    pub async fn public_key(&self) -> UiResult<String> {
        let v = self.call(reqwest::Method::GET, "/v1/licenses/public-key", None, None).await?;
        v["public_key"].as_str().map(str::to_owned).ok_or_else(|| UiError::internal("no public key"))
    }
}

impl AppCore {
    fn cloud(&self) -> UiResult<CloudClient> {
        CloudClient::new(&self.settings().cloud_url)
    }

    /// Sign in to the cloud account (the session token is kept in the encrypted store).
    pub async fn cloud_login(&self, email: &str, password: SecretString) -> UiResult<Value> {
        let email = email.trim();
        if email.is_empty() || email.len() > 254 || !email.contains('@') {
            return Err(UiError::invalid("请输入有效的邮箱", "Enter a valid e-mail address"));
        }
        let (tok, user) = self.cloud()?.login(email, &password).await?;
        self.set_cloud_session(Some(tok))?;
        let e = email.to_owned();
        self.mutate_settings(|s| s.cloud_email = Some(e))?;
        Ok(json!({"user": user}))
    }

    /// Sign out.
    pub async fn cloud_logout(&self) -> UiResult<()> {
        if let Some(t) = self.cloud_session() {
            let _ = self.cloud()?.logout(&t).await;
        }
        self.set_cloud_session(None)?;
        self.mutate_settings(|s| s.cloud_email = None)
    }

    /// Account, subscription and licence status. Network failures are reported, never fatal.
    pub async fn cloud_status(&self) -> UiResult<Value> {
        let s = self.settings();
        let license = self.license_status();
        let Some(tok) = self.cloud_session() else {
            return Ok(json!({"signed_in": false, "email": s.cloud_email, "license": license, "cloud_url": s.cloud_url}));
        };
        let sub = self.cloud()?.subscription(&tok).await;
        Ok(json!({
            "signed_in": true,
            "email": s.cloud_email,
            "cloud_url": s.cloud_url,
            "subscription": sub.as_ref().ok(),
            "subscription_error": sub.err(),
            "license": license,
        }))
    }

    /// Activate a licence for this device and pin the cloud's licence key.
    pub async fn activate_license(&self) -> UiResult<LicenseStatus> {
        self.require_unlocked()?;
        let tok = self.cloud_session().ok_or_else(|| UiError::new("UNAUTHENTICATED", "请先登录云账户。", "Sign in to the cloud account first."))?;
        let device = self.vault.device_id().ok_or_else(|| UiError::new("NO_VAULT", "没有账号库", "No vault"))?;
        let cloud = self.cloud()?;
        let pinned = self.settings().license_public_key;
        let pk = match pinned {
            Some(pk) => pk,
            None => cloud.public_key().await?,
        };
        let platform = if cfg!(target_os = "macos") { "macos" } else if cfg!(windows) { "windows" } else { "linux" };
        let token = cloud.activate(&tok, device.as_str(), platform, &self.app_version).await?;
        let st = verify_license(&token, &pk, device.as_str(), aipass_types::time::unix_now());
        if st.reason.as_deref() == Some("bad_signature") {
            return Err(UiError::new("INTEGRITY_FAILED", "许可证签名无效。", "The licence signature is invalid."));
        }
        self.mutate_settings(|s| {
            s.license_token = Some(token);
            s.license_public_key = Some(pk);
        })?;
        Ok(st)
    }

    /// Offline licence status (never blocks core features).
    pub fn license_status(&self) -> LicenseStatus {
        let s = self.settings();
        match (s.license_token, s.license_public_key, self.vault.device_id()) {
            (Some(t), Some(pk), Some(d)) => verify_license(&t, &pk, d.as_str(), aipass_types::time::unix_now()),
            _ => LicenseStatus::invalid("none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::Ed25519Keypair;

    fn token(k: &Ed25519Keypair, payload: &Value) -> String {
        let bytes = aipass_types::canonical::value_to_jcs(payload).unwrap();
        format!("{}.{}", b64u::encode(&bytes), b64u::encode(k.sign(&bytes)))
    }

    #[test]
    fn licence_checks() {
        let k = Ed25519Keypair::generate();
        let pk = k.public_key_b64u();
        let p = json!({"v":1,"sub":"usr_x","plan_id":"personal_yearly","features":["official_sync"],"device_id":"dev_a","iat":100,"exp":1000,"grace_until":2000});
        let t = token(&k, &p);
        let ok = verify_license(&t, &pk, "dev_a", 500);
        assert!(ok.valid, "{ok:?}");
        assert_eq!(ok.features, vec!["official_sync".to_string()]);
        assert!(verify_license(&t, &pk, "dev_a", 1500).valid, "grace period");
        assert_eq!(verify_license(&t, &pk, "dev_a", 2500).reason.as_deref(), Some("expired"));
        assert_eq!(verify_license(&t, &pk, "dev_b", 500).reason.as_deref(), Some("other_device"));
        let other = Ed25519Keypair::generate().public_key_b64u();
        assert_eq!(verify_license(&t, &other, "dev_a", 500).reason.as_deref(), Some("bad_signature"));
        let (_, sig) = t.split_once('.').unwrap();
        let forged = format!("{}.{sig}", b64u::encode(br#"{"features":["team"]}"#));
        assert!(!verify_license(&forged, &pk, "dev_a", 500).valid);
        assert!(!verify_license("garbage", &pk, "dev_a", 500).valid);
    }
}
