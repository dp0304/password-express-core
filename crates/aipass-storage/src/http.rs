// SPDX-License-Identifier: Apache-2.0
//! `HttpSyncStore` — client of the device-signed HTTP sync API (CONTRACTS §3.3) used for
//! the official ciphertext service and self-hosted nodes.
//!
//! Every request carries `Authorization: AIPass-Sig kid=<dev_…|exe_…>, ts, nonce, sig`
//! (CONTRACTS §1.6) over the exact path + query sent. The server checks that `kid` is an
//! active member of the vault (executors may only read). `PUT` maps
//! [`PutCondition::IfAbsent`] to `If-None-Match: *` and [`PutCondition::IfMatch`] to
//! `If-Match: "<etag>"`; `412` → [`PutOutcome::PreconditionFailed`]. Keys under
//! `entries/ manifests/ members/ recovery/ keyring/` are immutable server-side.
//!
//! The wire shapes of the API ([`VaultInfo`], [`ListObjectsResponse`],
//! [`PutObjectResponse`], [`create_vault_body`]) live here so the server crate
//! (`aipass-sync-server`) and every client share one definition.

use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::{Ed25519Signer, SecretString};
use aipass_types::error::ErrorBody;
use aipass_types::ids::{PrincipalId, VaultId};
use aipass_types::time::{Timestamp, rfc3339};
use aipass_types::{ApiError, ErrorCode};
use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::httputil::{self, quote_etag, response_etag, transport_error};
use crate::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    validate_key, validate_prefix,
};

/// Maximum object size accepted by the sync API (4 MiB).
pub const MAX_OBJECT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum `limit` of one listing request.
pub const MAX_LIST_LIMIT: usize = 1000;
/// Maximum size of a `POST /v1/vaults` body.
pub const MAX_CREATE_VAULT_BYTES: usize = 64 * 1024;

/// A device / executor signer shared across tasks.
pub type DeviceSigner = Arc<dyn Ed25519Signer + Send + Sync>;

/// `GET /v1/vaults/{vault_id}` and `POST /v1/vaults` (201) response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    /// Vault.
    pub vault_id: VaultId,
    /// From the signed `vault.json`.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Objects stored.
    pub object_count: u64,
    /// Bytes stored.
    pub bytes_used: u64,
    /// Quota in bytes (`null` = unlimited).
    pub quota_bytes: Option<u64>,
}

/// `GET /v1/vaults/{vault_id}/objects?prefix=&start_after=&limit=` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    /// Objects in lexicographic key order (keys relative to the vault root).
    pub objects: Vec<ObjectMeta>,
    /// More objects exist after the last one returned.
    pub truncated: bool,
}

/// `PUT /v1/vaults/{vault_id}/objects/{key}` response body (the ETag is also in the header).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutObjectResponse {
    /// New ETag.
    pub etag: String,
}

/// Build the `POST /v1/vaults` body `{"vault_header": …, "genesis_member": …}` from the
/// **exact bytes** of `vault.json` and `members/<genesis>/1.json`. The server stores those
/// bytes verbatim, so manifest hashes computed by the client over its own files stay valid.
pub fn create_vault_body(
    header_json: &[u8],
    genesis_member_json: &[u8],
) -> Result<Vec<u8>, StorageError> {
    for part in [header_json, genesis_member_json] {
        let v: serde_json::Value =
            serde_json::from_slice(part).map_err(|_| StorageError::Backend {
                status: None,
                message: "vault creation parts must be JSON objects".into(),
            })?;
        if !v.is_object() {
            return Err(StorageError::Backend {
                status: None,
                message: "vault creation parts must be JSON objects".into(),
            });
        }
    }
    let mut out = Vec::with_capacity(header_json.len() + genesis_member_json.len() + 40);
    out.extend_from_slice(b"{\"vault_header\":");
    out.extend_from_slice(header_json);
    out.extend_from_slice(b",\"genesis_member\":");
    out.extend_from_slice(genesis_member_json);
    out.push(b'}');
    if out.len() > MAX_CREATE_VAULT_BYTES {
        return Err(StorageError::TooLarge {
            limit: MAX_CREATE_VAULT_BYTES as u64,
        });
    }
    Ok(out)
}

const QUERY: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, QUERY).to_string()
}

/// Map a sync-API error response to a storage error (codes only; messages are not copied).
pub fn map_api_error(status: u16, body: &[u8]) -> StorageError {
    let parsed: Option<ErrorBody> = serde_json::from_slice(body).ok();
    let Some(b) = parsed else {
        return httputil::status_error(status, None);
    };
    let api = ApiError::from_body(&b);
    match api.code {
        ErrorCode::IdentityUnverified | ErrorCode::Unauthenticated | ErrorCode::Forbidden => {
            StorageError::Unauthorized
        }
        ErrorCode::NotFound => StorageError::LocationNotFound,
        ErrorCode::RateLimited => StorageError::RateLimited,
        ErrorCode::InvalidRequest
            if api.details.get("reason").and_then(|v| v.as_str()) == Some("too_large") =>
        {
            StorageError::TooLarge {
                limit: api
                    .details
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(MAX_OBJECT_BYTES as u64),
            }
        }
        ErrorCode::InvalidRequest
            if api.details.get("reason").and_then(|v| v.as_str()) == Some("invalid_key") =>
        {
            StorageError::InvalidKey
        }
        code => StorageError::Backend {
            status: Some(status),
            message: code.as_str().to_owned(),
        },
    }
}

/// Client of the HTTP sync API for one vault.
#[derive(Clone)]
pub struct HttpSyncStore {
    base: Url,
    vault_id: VaultId,
    kid: PrincipalId,
    signer: DeviceSigner,
    http: reqwest::Client,
}

impl core::fmt::Debug for HttpSyncStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpSyncStore")
            .field("base", &self.base.as_str())
            .field("vault_id", &self.vault_id)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

fn normalize_base(mut base: Url) -> Url {
    if !base.path().ends_with('/') {
        let p = format!("{}/", base.path());
        base.set_path(&p);
    }
    base.set_query(None);
    base.set_fragment(None);
    base
}

impl HttpSyncStore {
    /// New store with a default client (https required except loopback).
    pub fn new(
        base_url: Url,
        vault_id: VaultId,
        kid: PrincipalId,
        signer: DeviceSigner,
    ) -> Result<Self, StorageError> {
        let http = httputil::build_client(Duration::from_secs(60))?;
        Self::with_client(base_url, vault_id, kid, signer, http, false)
    }

    /// New store with a caller-supplied client. `allow_http` permits plain http to
    /// non-loopback hosts (development only).
    pub fn with_client(
        base_url: Url,
        vault_id: VaultId,
        kid: PrincipalId,
        signer: DeviceSigner,
        http: reqwest::Client,
        allow_http: bool,
    ) -> Result<Self, StorageError> {
        httputil::check_url(&base_url, allow_http)?;
        if matches!(kid, PrincipalId::Connection(_)) {
            return Err(StorageError::Unauthorized);
        }
        Ok(Self {
            base: normalize_base(base_url),
            vault_id,
            kid,
            signer,
            http,
        })
    }

    /// The vault.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    fn url(&self, rel: &str) -> Result<Url, StorageError> {
        self.base.join(rel).map_err(|_| StorageError::InvalidKey)
    }

    async fn send(
        &self,
        method: Method,
        rel: &str,
        extra: HeaderMap,
        body: Vec<u8>,
    ) -> Result<(u16, HeaderMap, Vec<u8>), StorageError> {
        let url = self.url(rel)?;
        let pq = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let sig = aipass_types::signing::sign_request(
            self.signer.as_ref(),
            self.kid.as_str(),
            method.as_str(),
            &pq,
            &body,
        );
        let mut auth = HeaderValue::from_str(&sig.to_header_value())
            .map_err(|_| StorageError::Unauthorized)?;
        auth.set_sensitive(true);
        let mut req = self
            .http
            .request(method, url)
            .headers(extra)
            .header(reqwest::header::AUTHORIZATION, auth);
        if !body.is_empty() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let bytes = resp.bytes().await.map_err(|e| transport_error(&e))?;
        Ok((status, headers, bytes.to_vec()))
    }

    fn object_path(&self, key: &str) -> Result<String, StorageError> {
        validate_key(key)?;
        Ok(format!("v1/vaults/{}/objects/{key}", self.vault_id))
    }

    /// `GET /v1/vaults/{vault_id}`.
    pub async fn vault_info(&self) -> Result<VaultInfo, StorageError> {
        let (status, _, body) = self
            .send(
                Method::GET,
                &format!("v1/vaults/{}", self.vault_id),
                HeaderMap::new(),
                Vec::new(),
            )
            .await?;
        if status != 200 {
            return Err(map_api_error(status, &body));
        }
        serde_json::from_slice(&body).map_err(|_| StorageError::Backend {
            status: Some(status),
            message: "invalid vault info".into(),
        })
    }

    /// `POST /v1/vaults` with an enroll token (self-host) or `aips_` session (cloud).
    /// `header_json` / `genesis_member_json` are the exact file bytes of `vault.json` and
    /// `members/<genesis>/1.json`.
    pub async fn create_vault(
        http: &reqwest::Client,
        base_url: &Url,
        bearer: &SecretString,
        header_json: &[u8],
        genesis_member_json: &[u8],
        allow_http: bool,
    ) -> Result<VaultInfo, StorageError> {
        httputil::check_url(base_url, allow_http)?;
        let body = create_vault_body(header_json, genesis_member_json)?;
        let url = normalize_base(base_url.clone())
            .join("v1/vaults")
            .map_err(|_| StorageError::InvalidKey)?;
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", bearer.expose()))
            .map_err(|_| StorageError::Unauthorized)?;
        auth.set_sensitive(true);
        let resp = http
            .post(url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|e| transport_error(&e))?;
        match status {
            200 | 201 => serde_json::from_slice(&bytes).map_err(|_| StorageError::Backend {
                status: Some(status),
                message: "invalid vault info".into(),
            }),
            _ => Err(map_api_error(status, &bytes)),
        }
    }
}

#[async_trait]
impl ObjectStore for HttpSyncStore {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        let path = self.object_path(key)?;
        let (status, headers, body) = self
            .send(Method::GET, &path, HeaderMap::new(), Vec::new())
            .await?;
        match status {
            200 => {
                let etag = response_etag(&headers).unwrap_or_else(|| crate::etag_for(&body));
                Ok(Some(Object { bytes: body, etag }))
            }
            404 => Ok(None),
            _ => Err(map_api_error(status, &body)),
        }
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        let path = self.object_path(key)?;
        if bytes.len() > MAX_OBJECT_BYTES {
            return Err(StorageError::TooLarge {
                limit: MAX_OBJECT_BYTES as u64,
            });
        }
        let mut h = HeaderMap::new();
        match &cond {
            PutCondition::None => {}
            PutCondition::IfAbsent => {
                h.insert(
                    reqwest::header::IF_NONE_MATCH,
                    HeaderValue::from_static("*"),
                );
            }
            PutCondition::IfMatch(e) => {
                h.insert(
                    reqwest::header::IF_MATCH,
                    HeaderValue::from_str(&quote_etag(e)).map_err(|_| StorageError::Backend {
                        status: None,
                        message: "invalid etag".into(),
                    })?,
                );
            }
        }
        let fallback = crate::etag_for(&bytes);
        let (status, headers, body) = self.send(Method::PUT, &path, h, bytes).await?;
        match status {
            200 | 201 => {
                let etag = response_etag(&headers)
                    .or_else(|| {
                        serde_json::from_slice::<PutObjectResponse>(&body)
                            .ok()
                            .map(|r| r.etag)
                    })
                    .unwrap_or(fallback);
                Ok(PutOutcome::Written { etag })
            }
            412 => Ok(PutOutcome::PreconditionFailed),
            _ => Err(map_api_error(status, &body)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.object_path(key)?;
        let (status, _, body) = self
            .send(Method::DELETE, &path, HeaderMap::new(), Vec::new())
            .await?;
        match status {
            200 | 204 | 404 => Ok(()),
            _ => Err(map_api_error(status, &body)),
        }
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_prefix(prefix)?;
        let mut out: Vec<ObjectMeta> = Vec::new();
        let mut after: Option<String> = start_after.map(str::to_owned);
        while out.len() < limit {
            let want = (limit - out.len()).min(MAX_LIST_LIMIT);
            let mut q = format!(
                "v1/vaults/{}/objects?prefix={}&limit={want}",
                self.vault_id,
                enc(prefix)
            );
            if let Some(a) = &after {
                q.push_str(&format!("&start_after={}", enc(a)));
            }
            let (status, _, body) = self
                .send(Method::GET, &q, HeaderMap::new(), Vec::new())
                .await?;
            if status != 200 {
                return Err(map_api_error(status, &body));
            }
            let page: ListObjectsResponse =
                serde_json::from_slice(&body).map_err(|_| StorageError::Backend {
                    status: Some(status),
                    message: "invalid listing".into(),
                })?;
            if let (Some(a), Some(first)) = (&after, page.objects.first())
                && first.key.as_str() <= a.as_str()
            {
                return Err(StorageError::Backend {
                    status: Some(status),
                    message: "listing did not advance".into(),
                });
            }
            let n = page.objects.len();
            after = page.objects.last().map(|m| m.key.clone());
            out.extend(page.objects);
            if !page.truncated || n == 0 {
                break;
            }
        }
        out.truncate(limit);
        Ok(out)
    }

    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "http".into(),
            endpoint: Some(self.base.as_str().trim_end_matches('/').to_owned()),
            detail: Some(format!("vault={}", self.vault_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_body_is_exact_concatenation() {
        let h = br#"{"format":1, "b":2}"#;
        let m = br#"{"x" : "y"}"#;
        let body = create_vault_body(h, m).unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            r#"{"vault_header":{"format":1, "b":2},"genesis_member":{"x" : "y"}}"#
        );
        assert!(create_vault_body(b"[1]", m).is_err());
        assert!(create_vault_body(b"{", m).is_err());
    }

    #[test]
    fn api_error_mapping() {
        let body = |code: &str, details: &str| {
            format!(r#"{{"error":{{"code":"{code}","message":"m","details":{details}}}}}"#)
        };
        assert_eq!(
            map_api_error(401, body("IDENTITY_UNVERIFIED", "{}").as_bytes()),
            StorageError::Unauthorized
        );
        assert_eq!(
            map_api_error(
                400,
                body("INVALID_REQUEST", r#"{"reason":"too_large","limit":5}"#).as_bytes()
            ),
            StorageError::TooLarge { limit: 5 }
        );
        assert_eq!(
            map_api_error(429, body("RATE_LIMITED", "{}").as_bytes()),
            StorageError::RateLimited
        );
        assert!(matches!(
            map_api_error(429, body("QUOTA_EXCEEDED", "{}").as_bytes()),
            StorageError::Backend {
                status: Some(429),
                ..
            }
        ));
        assert!(matches!(
            map_api_error(502, b"<html>"),
            StorageError::Backend {
                status: Some(502),
                ..
            }
        ));
    }
}
