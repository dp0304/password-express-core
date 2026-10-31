// SPDX-License-Identifier: Apache-2.0
//! Broker endpoints and broker URL resolution (CONTRACTS §1.7, §9).
//!
//! Accepted forms: `unix:///abs/path.sock` and `http(s)://host[:port][/prefix]`. URLs with
//! user-info, query or fragment are rejected so that an endpoint string can never smuggle a
//! credential into logs, host configs or error messages.
//!
//! Resolution order (contract): the `--broker` flag, then `AIPASS_BROKER_URL`, then
//! `<AIPASS_HOME>/broker.json`, then `unix://<AIPASS_HOME>/run/broker.sock`. Refinement (see
//! README "Contract deviations"): when a connection key records the broker it was explicitly
//! paired against, that URL is used after the flag and the environment but before
//! `broker.json`, because the connection only exists on that broker.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use url::Url;

use crate::error::ClientError;
use crate::home::AipassHome;

/// Default TCP address of a local broker (desktop / `aipass node`).
pub const DEFAULT_TCP_BROKER: &str = "http://127.0.0.1:7878";

/// Where the broker API lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrokerEndpoint {
    /// Unix domain socket (absolute path).
    Unix(PathBuf),
    /// HTTP(S) base URL (no trailing slash, no user-info/query/fragment).
    Http(Url),
}

impl BrokerEndpoint {
    /// Parse `unix:///abs/path.sock` or `http(s)://host[:port][/prefix]`.
    pub fn parse(s: &str) -> Result<Self, ClientError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ClientError::Config("empty broker URL".into()));
        }
        if let Some(rest) = s.strip_prefix("unix://") {
            let path = PathBuf::from(rest);
            if rest.is_empty() || !path.is_absolute() {
                return Err(ClientError::Config(
                    "unix broker URLs must name an absolute socket path, e.g. unix:///home/me/.aipass/run/broker.sock".into(),
                ));
            }
            if rest.contains('?') || rest.contains('#') {
                return Err(ClientError::Config(
                    "unix broker URLs must not contain '?' or '#'".into(),
                ));
            }
            return Ok(Self::Unix(path));
        }
        let url = Url::parse(s)
            .map_err(|e| ClientError::Config(format!("invalid broker URL: {e}")))?;
        match url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ClientError::Config(format!(
                    "unsupported broker URL scheme {other:?} (use unix://, http:// or https://)"
                )));
            }
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ClientError::Config(
                "broker URLs must not contain credentials (user:password@)".into(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ClientError::Config(
                "broker URLs must not contain a query or fragment".into(),
            ));
        }
        if url.host_str().is_none() {
            return Err(ClientError::Config("broker URL has no host".into()));
        }
        let mut url = url;
        let trimmed = url.path().trim_end_matches('/').to_owned();
        url.set_path(&trimmed);
        Ok(Self::Http(url))
    }

    /// True for `unix://`.
    pub fn is_unix(&self) -> bool {
        matches!(self, Self::Unix(_))
    }

    /// True for a loopback HTTP endpoint or a UDS.
    pub fn is_local(&self) -> bool {
        match self {
            Self::Unix(_) => true,
            Self::Http(u) => match u.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                None => false,
            },
        }
    }

    /// Socket path for `unix://`.
    pub fn socket_path(&self) -> Option<&Path> {
        match self {
            Self::Unix(p) => Some(p),
            Self::Http(_) => None,
        }
    }

    /// Path prefix of an HTTP base URL (`""` when none).
    pub fn path_prefix(&self) -> &str {
        match self {
            Self::Unix(_) => "",
            Self::Http(u) => {
                let p = u.path();
                if p == "/" { "" } else { p }
            }
        }
    }
}

impl fmt::Display for BrokerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(p) => write!(f, "unix://{}", p.display()),
            Self::Http(u) => {
                let s = u.as_str();
                f.write_str(s.strip_suffix('/').unwrap_or(s))
            }
        }
    }
}

impl std::str::FromStr for BrokerEndpoint {
    type Err = ClientError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Where a resolved broker URL came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerUrlSource {
    /// `--broker` flag.
    Flag,
    /// `AIPASS_BROKER_URL`.
    Env,
    /// The broker URL recorded in the connection key at pairing time.
    ConnectionKey,
    /// `<AIPASS_HOME>/broker.json`.
    BrokerJson,
    /// Built-in default (`unix://<AIPASS_HOME>/run/broker.sock`, or TCP on Windows).
    Default,
}

impl BrokerUrlSource {
    /// Short label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Flag => "--broker",
            Self::Env => "AIPASS_BROKER_URL",
            Self::ConnectionKey => "connection key",
            Self::BrokerJson => "broker.json",
            Self::Default => "default",
        }
    }
}

/// A resolved endpoint and its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBroker {
    /// Endpoint.
    pub endpoint: BrokerEndpoint,
    /// Source.
    pub source: BrokerUrlSource,
}

/// Inputs to [`resolve_broker`]. Values are passed explicitly (instead of reading the process
/// environment) so embedders and tests control them.
#[derive(Debug, Clone, Copy)]
pub struct ResolveInputs<'a> {
    /// `--broker` flag value.
    pub flag: Option<&'a str>,
    /// `AIPASS_BROKER_URL` value.
    pub env: Option<&'a str>,
    /// Broker URL recorded in the selected connection key (explicit pairing target).
    pub connection_key: Option<&'a str>,
    /// AI Pass home.
    pub home: &'a AipassHome,
}

/// `broker.json` contents.
#[derive(Debug, Clone, Deserialize)]
struct BrokerJson {
    #[serde(alias = "broker_url")]
    url: String,
}

/// Read `<home>/broker.json` if present.
pub fn read_broker_json(home: &AipassHome) -> Result<Option<BrokerEndpoint>, ClientError> {
    let path = home.broker_json();
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let parsed: BrokerJson = serde_json::from_slice(&bytes).map_err(|e| {
        ClientError::Config(format!(
            "{} is not valid ({{\"url\": \"…\"}} expected): {e}",
            path.display()
        ))
    })?;
    BrokerEndpoint::parse(&parsed.url).map(Some)
}

/// Write `<home>/broker.json` (used by the desktop app / `aipass node` to advertise a
/// non-default broker).
pub fn write_broker_json(home: &AipassHome, endpoint: &BrokerEndpoint) -> Result<(), ClientError> {
    crate::home::ensure_private_dir(home.root())?;
    let body = serde_json::to_vec_pretty(&serde_json::json!({ "url": endpoint.to_string() }))
        .map_err(|e| ClientError::Config(e.to_string()))?;
    crate::keys::atomic_write(&home.broker_json(), &body, 0o600)
}

/// The built-in default endpoint.
pub fn default_endpoint(home: &AipassHome) -> BrokerEndpoint {
    if cfg!(unix) {
        BrokerEndpoint::Unix(home.broker_socket())
    } else {
        // Windows has no UDS support in this build; the desktop broker listens on TCP.
        BrokerEndpoint::Http(Url::parse(DEFAULT_TCP_BROKER).expect("static URL"))
    }
}

/// Resolve the broker endpoint (flag > env > connection key > broker.json > default).
/// Empty strings count as unset. An invalid value at the winning level is an error — it is
/// never silently skipped.
pub fn resolve_broker(inputs: ResolveInputs<'_>) -> Result<ResolvedBroker, ClientError> {
    let pick = |v: Option<&str>| v.map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned);
    if let Some(v) = pick(inputs.flag) {
        return Ok(ResolvedBroker {
            endpoint: BrokerEndpoint::parse(&v)?,
            source: BrokerUrlSource::Flag,
        });
    }
    if let Some(v) = pick(inputs.env) {
        return Ok(ResolvedBroker {
            endpoint: BrokerEndpoint::parse(&v)?,
            source: BrokerUrlSource::Env,
        });
    }
    if let Some(v) = pick(inputs.connection_key) {
        return Ok(ResolvedBroker {
            endpoint: BrokerEndpoint::parse(&v)?,
            source: BrokerUrlSource::ConnectionKey,
        });
    }
    if let Some(ep) = read_broker_json(inputs.home)? {
        return Ok(ResolvedBroker {
            endpoint: ep,
            source: BrokerUrlSource::BrokerJson,
        });
    }
    Ok(ResolvedBroker {
        endpoint: default_endpoint(inputs.home),
        source: BrokerUrlSource::Default,
    })
}

/// A connection key that recorded the broker it was paired with only signs for that broker.
///
/// The `AIPass-Sig` string-to-sign has no host or audience (CONTRACTS §1.6), so a request
/// signed for one broker is valid on any broker that knows the key for the 300 s skew
/// window. A `--broker` flag or `AIPASS_BROKER_URL` that points elsewhere (for example a
/// tampered host config entry) would make the bridge hand signed, replayable requests to
/// that host. Returns an error when `resolved` came from the flag or the environment and
/// differs from `key_broker_url`; callers refuse to sign unless the user explicitly allows
/// the mismatch. Keys without a recorded broker are not checked.
pub fn check_key_broker(resolved: &ResolvedBroker, key_broker_url: Option<&str>) -> Result<(), ClientError> {
    let Some(recorded) = key_broker_url.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    if !matches!(resolved.source, BrokerUrlSource::Flag | BrokerUrlSource::Env) {
        return Ok(());
    }
    let recorded = BrokerEndpoint::parse(recorded)?;
    if recorded == resolved.endpoint {
        return Ok(());
    }
    Err(ClientError::Config(format!(
        "this connection was paired with the broker {recorded}, but {} points to {}; refusing to sign requests for a different broker (re-pair, or pass --allow-broker-mismatch if the broker really moved)",
        resolved.source.as_str(),
        resolved.endpoint
    )))
}

/// Derive the tunnel WebSocket URL (`wss://<cloud>/v1/tunnel`) from a cloud base URL.
pub fn tunnel_url(cloud_base: &str) -> Result<Url, ClientError> {
    let mut url = Url::parse(cloud_base.trim())
        .map_err(|e| ClientError::Config(format!("invalid cloud URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ClientError::Config(
            "cloud URLs must not contain credentials".into(),
        ));
    }
    let scheme = match url.scheme() {
        "https" | "wss" => "wss",
        "http" | "ws" => "ws",
        other => {
            return Err(ClientError::Config(format!(
                "unsupported cloud URL scheme {other:?}"
            )));
        }
    };
    url.set_scheme(scheme)
        .map_err(|_| ClientError::Config("cannot derive the tunnel URL".into()))?;
    let base = url.path().trim_end_matches('/').to_owned();
    url.set_path(&format!("{base}/v1/tunnel"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MNC-07: a key paired with broker A never signs for broker B given by flag / env.
    #[test]
    fn key_broker_mismatch_is_refused() {
        let at = |url: &str, source| ResolvedBroker { endpoint: BrokerEndpoint::parse(url).unwrap(), source };
        let a = "https://node.example.com/aipass";
        for src in [BrokerUrlSource::Flag, BrokerUrlSource::Env] {
            assert!(check_key_broker(&at("https://attacker.example", src), Some(a)).is_err());
            assert!(check_key_broker(&at("https://node.example.com/other", src), Some(a)).is_err());
            assert!(check_key_broker(&at("https://node.example.com/aipass/", src), Some(a)).is_ok());
            assert!(check_key_broker(&at("https://attacker.example", src), None).is_ok(), "no recorded broker");
        }
        assert!(check_key_broker(&at(a, BrokerUrlSource::ConnectionKey), Some(a)).is_ok());
        assert!(check_key_broker(&at("http://127.0.0.1:7878", BrokerUrlSource::BrokerJson), Some(a)).is_ok());
    }

    #[test]
    fn parse_forms() {
        assert_eq!(
            BrokerEndpoint::parse("unix:///tmp/b.sock").unwrap(),
            BrokerEndpoint::Unix("/tmp/b.sock".into())
        );
        assert!(BrokerEndpoint::parse("unix://rel/b.sock").is_err());
        assert!(BrokerEndpoint::parse("unix://").is_err());
        let h = BrokerEndpoint::parse("http://127.0.0.1:7878/").unwrap();
        assert_eq!(h.to_string(), "http://127.0.0.1:7878");
        assert!(h.is_local());
        let p = BrokerEndpoint::parse("https://node.example.com/aipass/").unwrap();
        assert_eq!(p.to_string(), "https://node.example.com/aipass");
        assert_eq!(p.path_prefix(), "/aipass");
        assert!(!p.is_local());
        assert!(BrokerEndpoint::parse("https://u:p@node.example.com").is_err());
        assert!(BrokerEndpoint::parse("https://node.example.com/?token=x").is_err());
        assert!(BrokerEndpoint::parse("ftp://node.example.com").is_err());
        assert!(BrokerEndpoint::parse("  ").is_err());
    }

    #[test]
    fn resolution_order() {
        let dir = tempfile::tempdir().unwrap();
        let home = AipassHome::new(dir.path());
        let base = ResolveInputs {
            flag: None,
            env: None,
            connection_key: None,
            home: &home,
        };
        let r = resolve_broker(base).unwrap();
        assert_eq!(r.source, BrokerUrlSource::Default);
        if cfg!(unix) {
            assert_eq!(r.endpoint, BrokerEndpoint::Unix(home.broker_socket()));
        }
        write_broker_json(&home, &BrokerEndpoint::parse("http://127.0.0.1:9000").unwrap())
            .unwrap();
        let r = resolve_broker(base).unwrap();
        assert_eq!(r.source, BrokerUrlSource::BrokerJson);
        assert_eq!(r.endpoint.to_string(), "http://127.0.0.1:9000");
        let r = resolve_broker(ResolveInputs {
            connection_key: Some("http://127.0.0.1:9100"),
            ..base
        })
        .unwrap();
        assert_eq!(r.source, BrokerUrlSource::ConnectionKey);
        let r = resolve_broker(ResolveInputs {
            env: Some("http://127.0.0.1:9200"),
            connection_key: Some("http://127.0.0.1:9100"),
            ..base
        })
        .unwrap();
        assert_eq!(r.source, BrokerUrlSource::Env);
        let r = resolve_broker(ResolveInputs {
            flag: Some("unix:///tmp/flag.sock"),
            env: Some("http://127.0.0.1:9200"),
            ..base
        })
        .unwrap();
        assert_eq!(r.source, BrokerUrlSource::Flag);
        // empty values are unset; invalid values are errors, never skipped
        let r = resolve_broker(ResolveInputs {
            flag: Some(""),
            env: Some(" "),
            ..base
        })
        .unwrap();
        assert_eq!(r.source, BrokerUrlSource::BrokerJson);
        assert!(
            resolve_broker(ResolveInputs {
                env: Some("bogus"),
                ..base
            })
            .is_err()
        );
        std::fs::write(home.broker_json(), b"not json").unwrap();
        assert!(resolve_broker(base).is_err());
        std::fs::write(home.broker_json(), br#"{"broker_url":"http://localhost:1"}"#).unwrap();
        assert_eq!(
            resolve_broker(base).unwrap().endpoint.to_string(),
            "http://localhost:1"
        );
    }

    #[test]
    fn tunnel_urls() {
        assert_eq!(
            tunnel_url("https://cloud.aipass.example").unwrap().as_str(),
            "wss://cloud.aipass.example/v1/tunnel"
        );
        assert_eq!(
            tunnel_url("http://127.0.0.1:8787/").unwrap().as_str(),
            "ws://127.0.0.1:8787/v1/tunnel"
        );
        assert!(tunnel_url("https://a:b@cloud.example").is_err());
    }
}
