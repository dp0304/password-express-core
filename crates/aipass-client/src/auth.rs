// SPDX-License-Identifier: Apache-2.0
//! Request authentication (CONTRACTS §1.6, §6.3).
//!
//! * [`Auth::Signed`] — `AIPass-Sig` with a connection (`conn_`), trusted device (`dev_`) or
//!   node (`exe_`) key. A fresh CSPRNG nonce and the current time are used per request; the
//!   signature covers the method, the path+query exactly as sent and the body hash.
//! * [`Auth::Bearer`] — `Bearer aipc_…` connection tokens or the local admin token
//!   (`<data>/admin.token`). Tokens are kept in a zeroizing [`SecretString`] and never logged.
//! * [`Auth::None`] — public endpoints (`/health`, `POST /connections/pair`) and UDS peers.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use aipass_crypto::{Ed25519Signer, SecretString};
use aipass_types::signing;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// How requests are authenticated.
#[derive(Clone, Default)]
pub enum Auth {
    /// No `Authorization` header.
    #[default]
    None,
    /// `AIPass-Sig` with `kid`.
    Signed {
        /// Principal id (`conn_…`, `dev_…`, `exe_…`).
        kid: String,
        /// Signing key.
        signer: Arc<dyn Ed25519Signer + Send + Sync>,
    },
    /// `Bearer <token>`.
    Bearer(Arc<SecretString>),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Auth::None => f.write_str("Auth::None"),
            Auth::Signed { kid, .. } => write!(f, "Auth::Signed {{ kid: {kid} }}"),
            Auth::Bearer(_) => f.write_str("Auth::Bearer([REDACTED])"),
        }
    }
}

impl Auth {
    /// `AIPass-Sig` authentication.
    pub fn signed(kid: impl Into<String>, signer: Arc<dyn Ed25519Signer + Send + Sync>) -> Self {
        Auth::Signed {
            kid: kid.into(),
            signer,
        }
    }

    /// Bearer authentication.
    pub fn bearer(token: impl Into<String>) -> Self {
        Auth::Bearer(Arc::new(SecretString::new(token.into())))
    }

    /// The signing principal id, if any.
    pub fn kid(&self) -> Option<&str> {
        match self {
            Auth::Signed { kid, .. } => Some(kid),
            _ => None,
        }
    }

    /// `Authorization` header value for a request signed now with a fresh nonce.
    pub fn header_value(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Option<Zeroizing<String>> {
        match self {
            Auth::None => None,
            Auth::Signed { kid, signer } => Some(Zeroizing::new(
                signing::sign_request(signer.as_ref(), kid, method, path_and_query, body)
                    .to_header_value(),
            )),
            Auth::Bearer(t) => Some(Zeroizing::new(format!("Bearer {}", t.expose()))),
        }
    }

    /// Deterministic variant (explicit `ts` and `nonce`) for test vectors.
    pub fn header_value_with(
        &self,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        ts: i64,
        nonce: &str,
    ) -> Option<Zeroizing<String>> {
        match self {
            Auth::Signed { kid, signer } => Some(Zeroizing::new(
                signing::sign_request_with(
                    signer.as_ref(),
                    kid,
                    method,
                    path_and_query,
                    body,
                    ts,
                    nonce,
                )
                .to_header_value(),
            )),
            other => other.header_value(method, path_and_query, body),
        }
    }
}

/// Load the local admin token (`<data>/admin.token`, CONTRACTS §6.3 auth "A").
///
/// The file must contain a single token line and, on Unix, must not be accessible by
/// group/others.
pub fn load_admin_token(path: &Path) -> Result<Auth, ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ClientError::Key(format!(
                "{} is accessible by other users; run `chmod 600 {}`",
                path.display(),
                path.display()
            )));
        }
    }
    let raw = Zeroizing::new(std::fs::read_to_string(path)?);
    let token = raw.trim();
    if token.is_empty() || token.contains(char::is_whitespace) {
        return Err(ClientError::Key(format!(
            "{} does not contain a token",
            path.display()
        )));
    }
    Ok(Auth::bearer(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::Ed25519Keypair;

    #[test]
    fn debug_redacts_tokens() {
        let a = Auth::bearer("aipc_supersecret");
        assert!(!format!("{a:?}").contains("supersecret"));
        let s = Auth::signed(
            "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
            Arc::new(Ed25519Keypair::generate()),
        );
        assert_eq!(s.kid(), Some("conn_01jbz3k6w8a7m2q4t5v9x0y1z4"));
        assert!(Auth::None.header_value("GET", "/v1/health", b"").is_none());
        assert_eq!(
            a.header_value("GET", "/", b"").unwrap().as_str(),
            "Bearer aipc_supersecret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn admin_token_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("admin.token");
        std::fs::write(&p, "tok123\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_admin_token(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let a = load_admin_token(&p).unwrap();
        assert_eq!(a.header_value("GET", "/", b"").unwrap().as_str(), "Bearer tok123");
    }
}
