// SPDX-License-Identifier: Apache-2.0
//! `AIPass-Sig` request signing (CONTRACTS §1.6).
//!
//! ```text
//! Authorization: AIPass-Sig kid=<principal id>, ts=<unix seconds>, nonce=<b64u 16 bytes>, sig=<b64u 64 bytes>
//! ```
//! String to sign (UTF-8, `\n`-joined, no trailing newline):
//! `AIPASS-SIG-V1`, METHOD, path+query exactly as sent, ts, nonce, b64u(SHA-256(body)).
//!
//! Verifiers check `|now − ts| ≤ 300 s`, the Ed25519 signature, and that the nonce is unique
//! per kid for 600 s ([`NonceCache`]). Resolving `kid` to an *active* principal key is the
//! caller's job (connection key, active vault member device, node key).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use aipass_crypto::{Ed25519Signer, b64u};
use thiserror::Error;

use crate::error::{ApiError, ErrorCode};
use crate::ids::PrincipalId;

/// Authorization scheme name.
pub const SCHEME: &str = "AIPass-Sig";
/// First line of the string to sign.
pub const VERSION_LINE: &str = "AIPASS-SIG-V1";
/// Maximum allowed clock skew in seconds.
pub const MAX_SKEW_SECS: i64 = 300;
/// Nonce uniqueness window per kid in seconds.
pub const NONCE_TTL_SECS: i64 = 600;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 16;

/// Bearer token prefixes (stored server-side only as SHA-256 hashes).
pub mod token_prefix {
    /// Node-issued connection token (remote MCP / SDK).
    pub const CONNECTION: &str = "aipc_";
    /// Cloud OAuth access token.
    pub const OAUTH_ACCESS: &str = "aipa_";
    /// Cloud OAuth refresh token.
    pub const OAUTH_REFRESH: &str = "aipr_";
    /// Cloud session token.
    pub const SESSION: &str = "aips_";
}

/// Request-signature failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SigError {
    /// Header is not a well-formed `AIPass-Sig` header.
    #[error("malformed AIPass-Sig header")]
    Malformed,
    /// `kid` is not a `conn_`/`dev_`/`exe_` id.
    #[error("invalid key id")]
    InvalidKid,
    /// Timestamp outside the ±300 s window.
    #[error("request timestamp outside the allowed window")]
    ClockSkew,
    /// Ed25519 verification failed.
    #[error("bad request signature")]
    BadSignature,
    /// Nonce already used by this kid within the window.
    #[error("nonce replay")]
    Replay,
    /// Nonce cache at capacity (treat as rate limiting).
    #[error("too many signed requests in the replay window")]
    CacheFull,
}

impl From<SigError> for ApiError {
    fn from(e: SigError) -> Self {
        match e {
            SigError::CacheFull => ApiError::new(ErrorCode::RateLimited),
            other => ApiError::new(ErrorCode::IdentityUnverified)
                .with_detail("reason", other.to_string()),
        }
    }
}

/// Parsed `AIPass-Sig` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigHeader {
    /// Principal id (`conn_` / `dev_` / `exe_`).
    pub kid: String,
    /// Unix seconds.
    pub ts: i64,
    /// b64u of 16 random bytes.
    pub nonce: String,
    /// b64u of the 64-byte Ed25519 signature.
    pub sig: String,
}

impl SigHeader {
    /// Parse an `Authorization` header value. Parameters may appear in any order but each
    /// exactly once; unknown parameters are rejected.
    pub fn parse(value: &str) -> Result<Self, SigError> {
        let value = value.trim();
        let (scheme, rest) = value.split_once(' ').ok_or(SigError::Malformed)?;
        if !scheme.eq_ignore_ascii_case(SCHEME) {
            return Err(SigError::Malformed);
        }
        let (mut kid, mut ts, mut nonce, mut sig) = (None, None, None, None);
        for part in rest.split(',') {
            let (k, v) = part.trim().split_once('=').ok_or(SigError::Malformed)?;
            let v = v.trim().trim_matches('"');
            let slot = match k.trim() {
                "kid" => &mut kid,
                "ts" => &mut ts,
                "nonce" => &mut nonce,
                "sig" => &mut sig,
                _ => return Err(SigError::Malformed),
            };
            if slot.replace(v.to_owned()).is_some() {
                return Err(SigError::Malformed);
            }
        }
        let kid = kid.ok_or(SigError::Malformed)?;
        PrincipalId::parse(&kid).map_err(|_| SigError::InvalidKid)?;
        let ts_s = ts.ok_or(SigError::Malformed)?;
        if ts_s.is_empty() || !ts_s.bytes().all(|b| b.is_ascii_digit()) || ts_s.len() > 12 {
            return Err(SigError::Malformed);
        }
        let ts: i64 = ts_s.parse().map_err(|_| SigError::Malformed)?;
        let nonce = nonce.ok_or(SigError::Malformed)?;
        b64u::decode_array::<NONCE_LEN>(&nonce).map_err(|_| SigError::Malformed)?;
        let sig = sig.ok_or(SigError::Malformed)?;
        b64u::decode_array::<64>(&sig).map_err(|_| SigError::Malformed)?;
        Ok(Self {
            kid,
            ts,
            nonce,
            sig,
        })
    }

    /// Render as an `Authorization` header value.
    pub fn to_header_value(&self) -> String {
        format!(
            "{SCHEME} kid={}, ts={}, nonce={}, sig={}",
            self.kid, self.ts, self.nonce, self.sig
        )
    }

    /// The principal id.
    pub fn principal(&self) -> Result<PrincipalId, SigError> {
        PrincipalId::parse(&self.kid).map_err(|_| SigError::InvalidKid)
    }
}

/// b64u(SHA-256(body)); an empty body hashes the empty string.
pub fn body_hash_b64u(body: &[u8]) -> String {
    aipass_crypto::sha256_b64u(body)
}

/// Build the exact string to sign.
pub fn string_to_sign(
    method: &str,
    path_and_query: &str,
    ts: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "{VERSION_LINE}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        ts,
        nonce,
        body_hash_b64u(body)
    )
}

/// Sign with an explicit timestamp and nonce (deterministic; used by tests and vectors).
pub fn sign_request_with(
    signer: &dyn Ed25519Signer,
    kid: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    ts: i64,
    nonce: &str,
) -> SigHeader {
    let sts = string_to_sign(method, path_and_query, ts, nonce, body);
    let sig = b64u::encode(signer.sign(sts.as_bytes()));
    SigHeader {
        kid: kid.to_owned(),
        ts,
        nonce: nonce.to_owned(),
        sig,
    }
}

/// Sign a request now with a fresh CSPRNG nonce.
pub fn sign_request(
    signer: &dyn Ed25519Signer,
    kid: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> SigHeader {
    let nonce = b64u::encode(aipass_crypto::rng::random_array::<NONCE_LEN>());
    sign_request_with(
        signer,
        kid,
        method,
        path_and_query,
        body,
        crate::time::unix_now(),
        &nonce,
    )
}

/// Verify skew and signature (not the nonce — see [`verify_request_with_nonce`]).
pub fn verify_request(
    header: &SigHeader,
    public_key: &[u8; 32],
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
) -> Result<(), SigError> {
    if (now - header.ts).abs() > MAX_SKEW_SECS {
        return Err(SigError::ClockSkew);
    }
    let sig = b64u::decode_array::<64>(&header.sig).map_err(|_| SigError::Malformed)?;
    let sts = string_to_sign(method, path_and_query, header.ts, &header.nonce, body);
    aipass_crypto::identity::verify(public_key, sts.as_bytes(), &sig)
        .map_err(|_| SigError::BadSignature)
}

/// Full verification: skew, signature, then nonce uniqueness (recorded only after the
/// signature verified, so unauthenticated callers cannot fill the cache).
pub fn verify_request_with_nonce(
    header: &SigHeader,
    public_key: &[u8; 32],
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
    nonces: &NonceCache,
) -> Result<(), SigError> {
    verify_request(header, public_key, method, path_and_query, body, now)?;
    nonces.check_and_insert(&header.kid, &header.nonce, now)
}

/// Parsed `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// `AIPass-Sig …`.
    Sig(SigHeader),
    /// `Bearer <token>` — the token itself must be treated as a secret (hash before storing
    /// or comparing, never log).
    Bearer(String),
}

impl Authorization {
    /// Parse an `Authorization` header value.
    pub fn parse(value: &str) -> Result<Self, SigError> {
        let v = value.trim();
        if let Some((scheme, token)) = v.split_once(' ')
            && scheme.eq_ignore_ascii_case("Bearer")
        {
            let t = token.trim();
            if t.is_empty() || t.contains(char::is_whitespace) {
                return Err(SigError::Malformed);
            }
            return Ok(Self::Bearer(t.to_owned()));
        }
        SigHeader::parse(v).map(Self::Sig)
    }
}

/// SHA-256 hash (b64u) of a bearer token — the only form in which tokens are stored.
pub fn token_hash(token: &str) -> String {
    aipass_crypto::sha256_b64u(token.as_bytes())
}

/// Replay cache: remembers `(kid, nonce)` for [`NONCE_TTL_SECS`].
///
/// Entries are never evicted early; when the cache is full, new requests are refused with
/// [`SigError::CacheFull`] (fail closed) rather than forgetting nonces.
#[derive(Debug)]
pub struct NonceCache {
    inner: Mutex<NonceInner>,
    ttl: i64,
    max_entries: usize,
}

#[derive(Debug, Default)]
struct NonceInner {
    seen: HashMap<(String, String), i64>,
    order: VecDeque<(i64, String, String)>,
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new(NONCE_TTL_SECS, 1_000_000)
    }
}

impl NonceCache {
    /// Cache with a custom TTL and capacity.
    pub fn new(ttl_secs: i64, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(NonceInner::default()),
            ttl: ttl_secs,
            max_entries,
        }
    }

    /// Record `(kid, nonce)`; `Err(Replay)` if it was seen within the TTL.
    pub fn check_and_insert(&self, kid: &str, nonce: &str, now: i64) -> Result<(), SigError> {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // prune expired
        while let Some((exp, _, _)) = g.order.front() {
            if *exp > now {
                break;
            }
            if let Some((_, k, n)) = g.order.pop_front() {
                let key = (k, n);
                if g.seen.get(&key).is_some_and(|e| *e <= now) {
                    g.seen.remove(&key);
                }
            }
        }
        let key = (kid.to_owned(), nonce.to_owned());
        if g.seen.get(&key).is_some_and(|exp| *exp > now) {
            return Err(SigError::Replay);
        }
        if g.seen.len() >= self.max_entries {
            return Err(SigError::CacheFull);
        }
        let exp = now + self.ttl;
        g.seen.insert(key.clone(), exp);
        g.order.push_back((exp, key.0, key.1));
        Ok(())
    }

    /// Number of remembered nonces.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.seen.len()).unwrap_or(0)
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::Ed25519Keypair;

    fn vector_key() -> Ed25519Keypair {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        Ed25519Keypair::from_seed(&seed)
    }

    #[test]
    fn header_roundtrip_and_strict_parse() {
        let h = sign_request(
            &vector_key(),
            "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
            "post",
            "/v1/x",
            b"{}",
        );
        let text = h.to_header_value();
        assert_eq!(SigHeader::parse(&text).unwrap(), h);
        assert!(matches!(
            Authorization::parse(&text).unwrap(),
            Authorization::Sig(_)
        ));
        assert_eq!(
            Authorization::parse("Bearer aipc_abc").unwrap(),
            Authorization::Bearer("aipc_abc".into())
        );
        // duplicates, unknown params, wrong scheme, bad kid
        assert!(SigHeader::parse(&format!("{text}, ts=1")).is_err());
        assert!(SigHeader::parse(&format!("{text}, extra=1")).is_err());
        assert!(SigHeader::parse(&text.replace("AIPass-Sig", "Other")).is_err());
        assert_eq!(
            SigHeader::parse(&text.replace(
                "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
                "res_01jbz3k6w8a7m2q4t5v9x0y1z4"
            )),
            Err(SigError::InvalidKid)
        );
        assert!(SigHeader::parse(&text.replace(&format!("ts={}", h.ts), "ts=-5")).is_err());
    }

    #[test]
    fn verify_skew_tamper_replay() {
        let k = vector_key();
        let now = 1_793_318_400;
        let h = sign_request_with(
            &k,
            "dev_01jbz3k6w8a7m2q4t5v9x0y1z4",
            "GET",
            "/v1/a?b=1",
            b"",
            now,
            "qqqqqqqqqqqqqqqqqqqqqg",
        );
        let pk = k.public_key();
        verify_request(&h, &pk, "GET", "/v1/a?b=1", b"", now + 300).unwrap();
        assert_eq!(
            verify_request(&h, &pk, "GET", "/v1/a?b=1", b"", now + 301),
            Err(SigError::ClockSkew)
        );
        assert_eq!(
            verify_request(&h, &pk, "GET", "/v1/a?b=1", b"", now - 301),
            Err(SigError::ClockSkew)
        );
        assert_eq!(
            verify_request(&h, &pk, "GET", "/v1/a?b=2", b"", now),
            Err(SigError::BadSignature)
        );
        assert_eq!(
            verify_request(&h, &pk, "POST", "/v1/a?b=1", b"", now),
            Err(SigError::BadSignature)
        );
        assert_eq!(
            verify_request(&h, &pk, "GET", "/v1/a?b=1", b"x", now),
            Err(SigError::BadSignature)
        );
        let other = Ed25519Keypair::generate().public_key();
        assert_eq!(
            verify_request(&h, &other, "GET", "/v1/a?b=1", b"", now),
            Err(SigError::BadSignature)
        );

        let cache = NonceCache::default();
        verify_request_with_nonce(&h, &pk, "GET", "/v1/a?b=1", b"", now, &cache).unwrap();
        assert_eq!(
            verify_request_with_nonce(&h, &pk, "GET", "/v1/a?b=1", b"", now + 10, &cache),
            Err(SigError::Replay)
        );
        // a bad signature does not consume a cache slot
        let bad = SigHeader {
            nonce: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            ..h.clone()
        };
        assert!(
            verify_request_with_nonce(&bad, &pk, "GET", "/v1/a?b=1", b"", now, &cache).is_err()
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn nonce_cache_ttl_and_capacity() {
        let c = NonceCache::new(600, 2);
        c.check_and_insert("k", "n1", 1000).unwrap();
        assert_eq!(c.check_and_insert("k", "n1", 1599), Err(SigError::Replay));
        c.check_and_insert("k2", "n1", 1000).unwrap(); // per kid
        assert_eq!(
            c.check_and_insert("k", "n3", 1001),
            Err(SigError::CacheFull)
        );
        // after TTL the nonce is forgotten and capacity frees up
        c.check_and_insert("k", "n1", 1600).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn token_hash_is_b64u_sha256() {
        assert_eq!(
            token_hash(""),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }
}
