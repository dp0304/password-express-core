// SPDX-License-Identifier: Apache-2.0
//! Shared HTTP plumbing for the network backends: client construction (rustls, no
//! redirects), transport-security checks, ETag quoting and sanitized error mapping.
//!
//! Error messages produced here never contain URLs, headers, signatures or bodies.

use std::net::IpAddr;
use std::time::Duration;

use url::Url;

use crate::StorageError;

/// Default per-request timeout for storage backends.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Connect timeout.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// User agent.
pub(crate) const USER_AGENT: &str = concat!("aipass-storage/", env!("CARGO_PKG_VERSION"));

/// A reqwest client with rustls, redirects disabled (signed requests must never be
/// replayed against another origin) and bounded timeouts.
pub(crate) fn build_client(timeout: Duration) -> Result<reqwest::Client, StorageError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|_| StorageError::Network("could not initialise the HTTP client".into()))
}

/// Whether `url` points at a loopback host (`localhost`, `127.0.0.0/8`, `::1`).
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Require `https`, except for loopback hosts or when `allow_http` was explicitly set
/// (development / tests). URLs must not embed credentials.
pub(crate) fn check_url(url: &Url, allow_http: bool) -> Result<(), StorageError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(StorageError::Backend {
            status: None,
            message: "endpoint URL must not contain credentials".into(),
        });
    }
    if url.host().is_none() {
        return Err(StorageError::Backend {
            status: None,
            message: "endpoint URL has no host".into(),
        });
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_http || is_loopback(url) => Ok(()),
        "http" => Err(StorageError::Backend {
            status: None,
            message: "plain http is only allowed for loopback endpoints; use https".into(),
        }),
        _ => Err(StorageError::Backend {
            status: None,
            message: "unsupported URL scheme".into(),
        }),
    }
}

/// Map a transport error without leaking the URL.
pub(crate) fn transport_error(e: &reqwest::Error) -> StorageError {
    if e.is_timeout() {
        StorageError::Timeout
    } else if e.is_connect() {
        StorageError::Network("connection failed".into())
    } else if e.is_body() || e.is_decode() {
        StorageError::Network("response body could not be read".into())
    } else {
        StorageError::Network("request failed".into())
    }
}

/// Strip a weak prefix and surrounding quotes from an ETag header value.
pub(crate) fn unquote_etag(v: &str) -> String {
    let v = v.trim();
    let v = v.strip_prefix("W/").unwrap_or(v);
    v.trim_matches('"').to_owned()
}

/// Quote an ETag for `If-Match`.
pub(crate) fn quote_etag(v: &str) -> String {
    format!("\"{}\"", v.trim_matches('"'))
}

/// ETag of a response, if present and ASCII.
pub(crate) fn response_etag(h: &reqwest::header::HeaderMap) -> Option<String> {
    h.get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(unquote_etag)
        .filter(|s| !s.is_empty())
}

/// Generic status → error mapping (callers handle 404 / 412 themselves first).
pub(crate) fn status_error(status: u16, code: Option<&str>) -> StorageError {
    let detail = code.map(|c| format!(" ({c})")).unwrap_or_default();
    match status {
        401 | 403 => StorageError::Unauthorized,
        413 => StorageError::TooLarge { limit: 0 },
        429 => StorageError::RateLimited,
        503 if code == Some("SlowDown") => StorageError::RateLimited,
        _ => StorageError::Backend {
            status: Some(status),
            message: format!("unexpected response{detail}"),
        },
    }
}

/// Keep only a short, safe token from an untrusted error code (letters, digits, `_`).
pub(crate) fn safe_code(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect();
    (!t.is_empty()).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_checks() {
        assert!(check_url(&Url::parse("https://s3.example.com").unwrap(), false).is_ok());
        assert!(check_url(&Url::parse("http://127.0.0.1:9000").unwrap(), false).is_ok());
        assert!(check_url(&Url::parse("http://[::1]:9000").unwrap(), false).is_ok());
        assert!(check_url(&Url::parse("http://localhost:9000").unwrap(), false).is_ok());
        assert!(check_url(&Url::parse("http://minio.lan:9000").unwrap(), false).is_err());
        assert!(check_url(&Url::parse("http://minio.lan:9000").unwrap(), true).is_ok());
        assert!(check_url(&Url::parse("https://u:p@s3.example.com").unwrap(), false).is_err());
        assert!(check_url(&Url::parse("ftp://s3.example.com").unwrap(), true).is_err());
    }

    #[test]
    fn etags() {
        assert_eq!(unquote_etag("\"abc\""), "abc");
        assert_eq!(unquote_etag("W/\"abc\""), "abc");
        assert_eq!(quote_etag("abc"), "\"abc\"");
        assert_eq!(safe_code("No<Such>Key"), Some("NoSuchKey".into()));
    }
}
