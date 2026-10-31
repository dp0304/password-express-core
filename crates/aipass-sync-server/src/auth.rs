// SPDX-License-Identifier: Apache-2.0
//! Request authentication shared by the sync and relay routers: `AIPass-Sig` parsing,
//! skew pre-check, signature + nonce verification (CONTRACTS §1.6), raw path extraction
//! and client-address keys for pre-authentication rate limiting.

use std::net::SocketAddr;

use aipass_types::ids::PrincipalId;
use aipass_types::signing::{self, Authorization, MAX_SKEW_SECS, NonceCache, SigHeader};
use aipass_types::{ApiError, ErrorCode};
use axum::extract::{ConnectInfo, OriginalUri};
use axum::http::request::Parts;

use crate::error::unverified;

/// A parsed, not yet verified `AIPass-Sig` request.
#[derive(Debug, Clone)]
pub(crate) struct SignedRequest {
    pub header: SigHeader,
    pub principal: PrincipalId,
}

/// Parse `Authorization: AIPass-Sig …` with a `dev_` / `exe_` kid.
pub(crate) fn parse_sig(parts: &Parts) -> Result<SignedRequest, ApiError> {
    let v = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| unverified("missing_signature"))?
        .to_str()
        .map_err(|_| unverified("malformed_signature"))?;
    let header = match Authorization::parse(v) {
        Ok(Authorization::Sig(h)) => h,
        Ok(Authorization::Bearer(_)) => return Err(unverified("signature_required")),
        Err(e) => return Err(e.into()),
    };
    let principal = header.principal().map_err(ApiError::from)?;
    if matches!(principal, PrincipalId::Connection(_)) {
        return Err(unverified("principal_not_allowed"));
    }
    Ok(SignedRequest { header, principal })
}

/// Cheap skew check before any storage lookups.
pub(crate) fn check_skew(h: &SigHeader, now: i64) -> Result<(), ApiError> {
    if (now - h.ts).abs() > MAX_SKEW_SECS {
        Err(signing::SigError::ClockSkew.into())
    } else {
        Ok(())
    }
}

/// Reason used both for unknown principals and for bad signatures, so responses do not
/// reveal whether a kid is a member of the vault / relay.
pub(crate) const UNVERIFIED_PRINCIPAL: &str = "invalid_signature_or_principal";

/// Verify skew and signature, then record the nonce per verifying key (replays are only
/// reported for requests whose signature verified).
pub(crate) fn verify(
    req: &SignedRequest,
    sign_pk: &[u8; 32],
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
    nonces: &NonceCache,
) -> Result<(), ApiError> {
    match signing::verify_request(&req.header, sign_pk, method, path_and_query, body, now) {
        Ok(()) => {}
        Err(signing::SigError::ClockSkew) => return Err(signing::SigError::ClockSkew.into()),
        Err(_) => return Err(unverified(UNVERIFIED_PRINCIPAL)),
    }
    // keyed by the verifying key, not the unsigned `kid` string: aliases of one record
    // (`dev_U` / `exe_U`) or of one key in several directories share one replay window
    nonces
        .check_and_insert(&replay_key(sign_pk), &req.header.nonce, now)
        .map_err(ApiError::from)
}

/// Replay-cache namespace of a verifying key.
pub(crate) fn replay_key(sign_pk: &[u8; 32]) -> String {
    format!("pk:{}", hex::encode(sign_pk))
}

/// The raw path + query of the request as received (before any router nesting).
pub(crate) fn path_and_query(parts: &Parts) -> String {
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|o| o.0.clone())
        .unwrap_or_else(|| parts.uri.clone());
    uri.path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

/// Client address key, when the server was started with connect info.
pub(crate) fn client_key(parts: &Parts) -> Option<String> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
}

/// `RATE_LIMITED`.
pub(crate) fn rate_limited() -> ApiError {
    ApiError::new(ErrorCode::RateLimited)
}
