// SPDX-License-Identifier: Apache-2.0
//! Egress guard for outbound HTTPS (design doc §9.6, CONTRACTS §8, acceptance A06).
//!
//! Every request a connector sends to an HTTP API goes through [`EgressGuard::fetch`]:
//!
//! 1. **Scheme** — `https` only (a test-only switch exists for the GitHub mock; it cannot be
//!    set from resource config).
//! 2. **Origin pinning** — the request URL must have exactly the scheme, host and port of the
//!    configured base URL; no user-info in URLs.
//! 3. **DNS vetting** — the host name is resolved once by the guard's resolver (hickory, or
//!    the system resolver as fallback). If *any* returned address is in a blocked range the
//!    request is refused (no "pick the public one" games). Blocked by default: loopback,
//!    RFC 1918, CGNAT `100.64/10`, link-local, ULA `fc00::/7`, site-local, documentation,
//!    benchmark and IETF ranges, plus IPv6 forms that embed IPv4 (`::ffff:a.b.c.d`,
//!    `::a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo). `allow_private_network`
//!    (set by the trusted client on the resource) unlocks those private ranges. **Always**
//!    blocked, even with `allow_private_network`: unspecified, broadcast, multicast,
//!    reserved `240/4`, and cloud metadata endpoints (`169.254.169.254`, `169.254.170.2`,
//!    `100.100.100.200`, `fd00:ec2::254`).
//! 4. **Connection pinning** — the HTTP client gets a resolver that only answers for the
//!    vetted host with the vetted addresses, so there is no second DNS lookup between check
//!    and connect (DNS-rebinding safe). Proxies from the environment are ignored.
//! 5. **TLS** — rustls with Mozilla roots (+ configured extra roots), host-name verified.
//! 6. **No redirects** — a 3xx response is returned as an error, never followed, so
//!    credentials are never sent to another origin.
//! 7. **Limits** — total timeout (default and maximum 10 s), connect timeout, response body
//!    cap (default and maximum 1 MiB), no automatic retries, no decompression.
//!
//! Errors never contain URLs, headers or bodies (a `reqwest::Error`'s text embeds the URL,
//! which can carry a query-string API key), so nothing here formats upstream errors.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use aipass_types::{ApiError, ErrorCode};
use async_trait::async_trait;
use ipnet::{Ipv4Net, Ipv6Net};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::sync::OnceCell;
use url::{Host, Url};

use crate::errors;

/// Hard upper bound for the total request timeout.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard upper bound for a response body.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// User agent sent upstream.
pub const USER_AGENT: &str = concat!("aipass-executor/", env!("CARGO_PKG_VERSION"));

// ======================================================================================
// Address classification
// ======================================================================================

/// Classification of a destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    /// Globally routable unicast.
    Public,
    /// Private / internal range; allowed only with `allow_private_network`.
    Private(&'static str),
    /// Never allowed (metadata, multicast, unspecified, broadcast, reserved).
    Forbidden(&'static str),
}

fn v4net(s: &str) -> Ipv4Net {
    s.parse().unwrap_or_else(|_| panic!("bad v4 net {s}"))
}
fn v6net(s: &str) -> Ipv6Net {
    s.parse().unwrap_or_else(|_| panic!("bad v6 net {s}"))
}

static V4_PRIVATE: std::sync::LazyLock<Vec<(Ipv4Net, &'static str)>> =
    std::sync::LazyLock::new(|| {
        vec![
            (v4net("0.0.0.0/8"), "this_network"),
            (v4net("10.0.0.0/8"), "private"),
            (v4net("100.64.0.0/10"), "cgnat"),
            (v4net("127.0.0.0/8"), "loopback"),
            (v4net("169.254.0.0/16"), "link_local"),
            (v4net("172.16.0.0/12"), "private"),
            (v4net("192.0.0.0/24"), "ietf_protocol"),
            (v4net("192.0.2.0/24"), "documentation"),
            (v4net("192.88.99.0/24"), "6to4_relay"),
            (v4net("192.168.0.0/16"), "private"),
            (v4net("198.18.0.0/15"), "benchmark"),
            (v4net("198.51.100.0/24"), "documentation"),
            (v4net("203.0.113.0/24"), "documentation"),
        ]
    });

static V6_PRIVATE: std::sync::LazyLock<Vec<(Ipv6Net, &'static str)>> =
    std::sync::LazyLock::new(|| {
        vec![
            (v6net("64:ff9b:1::/48"), "nat64_local"),
            (v6net("100::/64"), "discard"),
            (v6net("2001::/32"), "teredo"),
            (v6net("2001::/23"), "ietf_protocol"),
            (v6net("2001:db8::/32"), "documentation"),
            (v6net("3fff::/20"), "documentation"),
            (v6net("fc00::/7"), "unique_local"),
            (v6net("fe80::/10"), "link_local"),
            (v6net("fec0::/10"), "site_local"),
        ]
    });

const METADATA_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(169, 254, 169, 254),
    Ipv4Addr::new(169, 254, 170, 2),
    Ipv4Addr::new(100, 100, 100, 200),
];
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// Classify an IPv4 address.
pub fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    if METADATA_V4.contains(&ip) {
        return AddrClass::Forbidden("cloud_metadata");
    }
    if ip.is_unspecified() {
        return AddrClass::Forbidden("unspecified");
    }
    if ip.is_broadcast() {
        return AddrClass::Forbidden("broadcast");
    }
    if ip.is_multicast() {
        return AddrClass::Forbidden("multicast");
    }
    if ip.octets()[0] >= 240 {
        return AddrClass::Forbidden("reserved");
    }
    for (net, why) in V4_PRIVATE.iter() {
        if net.contains(&ip) {
            return AddrClass::Private(why);
        }
    }
    AddrClass::Public
}

/// Classify an IPv6 address (embedded IPv4 forms are classified by their IPv4 part, and are
/// never better than `Private`).
pub fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    if ip == METADATA_V6 {
        return AddrClass::Forbidden("cloud_metadata");
    }
    if ip.is_unspecified() {
        return AddrClass::Forbidden("unspecified");
    }
    if ip.is_loopback() {
        return AddrClass::Private("loopback");
    }
    if ip.is_multicast() {
        return AddrClass::Forbidden("multicast");
    }
    let seg = ip.segments();
    // ::ffff:a.b.c.d (IPv4-mapped)
    if let Some(v4) = ip.to_ipv4_mapped() {
        return match classify_v4(v4) {
            AddrClass::Public => AddrClass::Private("ipv4_mapped"),
            other => other,
        };
    }
    // ::a.b.c.d (deprecated IPv4-compatible)
    if seg[..6].iter().all(|s| *s == 0) {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            seg[6] as u8,
            (seg[7] >> 8) as u8,
            seg[7] as u8,
        );
        return match classify_v4(v4) {
            AddrClass::Public => AddrClass::Private("ipv4_compatible"),
            other => other,
        };
    }
    // NAT64 well-known prefix 64:ff9b::/96
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            seg[6] as u8,
            (seg[7] >> 8) as u8,
            seg[7] as u8,
        );
        return match classify_v4(v4) {
            AddrClass::Public => AddrClass::Private("nat64"),
            other => other,
        };
    }
    // 6to4 2002:AABB:CCDD::/48 embeds a.b.c.d
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return match classify_v4(v4) {
            AddrClass::Public => AddrClass::Private("6to4"),
            other => other,
        };
    }
    for (net, why) in V6_PRIVATE.iter() {
        if net.contains(&ip) {
            return AddrClass::Private(why);
        }
    }
    AddrClass::Public
}

/// Classify any address.
pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Whether `ip` may be contacted under `allow_private_network`.
pub fn is_allowed(ip: IpAddr, allow_private_network: bool) -> Result<(), &'static str> {
    match classify(ip) {
        AddrClass::Public => Ok(()),
        AddrClass::Private(why) if allow_private_network => {
            let _ = why;
            Ok(())
        }
        AddrClass::Private(why) | AddrClass::Forbidden(why) => Err(why),
    }
}

// ======================================================================================
// Resolvers
// ======================================================================================

/// DNS resolution used by the guard. Implementations must not consult proxies or caches
/// that could be poisoned by the AI host; tests use [`StaticResolver`].
#[async_trait]
pub trait EgressResolver: Send + Sync + fmt::Debug {
    /// Resolve `host` (a DNS name, never an IP literal) to addresses.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, EgressError>;
}

/// Default resolver: hickory (system configuration), falling back to the OS resolver when
/// hickory cannot be configured.
#[derive(Default)]
pub struct DefaultResolver {
    hickory: OnceCell<Option<hickory_resolver::TokioResolver>>,
}

impl fmt::Debug for DefaultResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DefaultResolver")
    }
}

#[async_trait]
impl EgressResolver for DefaultResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, EgressError> {
        let hickory = self
            .hickory
            .get_or_init(|| async {
                hickory_resolver::TokioResolver::builder_tokio()
                    .ok()
                    .and_then(|b| b.build().ok())
            })
            .await;
        match hickory {
            Some(r) => {
                let lookup = r
                    .lookup_ip(host)
                    .await
                    .map_err(|_| EgressError::Resolution)?;
                let ips: Vec<IpAddr> = lookup.iter().collect();
                if ips.is_empty() {
                    Err(EgressError::Resolution)
                } else {
                    Ok(ips)
                }
            }
            None => SystemResolver.resolve(host).await,
        }
    }
}

/// The operating-system resolver (`getaddrinfo` via tokio).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait]
impl EgressResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, EgressError> {
        let addrs = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|_| EgressError::Resolution)?;
        let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
        ips.dedup();
        if ips.is_empty() {
            Err(EgressError::Resolution)
        } else {
            Ok(ips)
        }
    }
}

/// A fixed name → addresses table (tests, air-gapped deployments). Lookups are counted so
/// tests can prove there is exactly one resolution per request.
#[derive(Debug, Default)]
pub struct StaticResolver {
    table: std::sync::Mutex<HashMap<String, Vec<IpAddr>>>,
    lookups: std::sync::atomic::AtomicUsize,
}

impl StaticResolver {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the answer for `host` (case-insensitive).
    pub fn set(&self, host: &str, ips: Vec<IpAddr>) {
        self.table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(host.trim_end_matches('.').to_ascii_lowercase(), ips);
    }
    /// Number of lookups served.
    pub fn lookups(&self) -> usize {
        self.lookups.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl EgressResolver for StaticResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, EgressError> {
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&host.trim_end_matches('.').to_ascii_lowercase())
            .cloned()
            .filter(|v| !v.is_empty())
            .ok_or(EgressError::Resolution)
    }
}

/// reqwest resolver that only answers for the vetted host.
struct PinnedResolve {
    host: String,
    addrs: Vec<SocketAddr>,
}

impl reqwest::dns::Resolve for PinnedResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let ok = name
            .as_str()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(self.host.trim_end_matches('.'));
        let addrs = self.addrs.clone();
        Box::pin(async move {
            if ok {
                let it: reqwest::dns::Addrs = Box::new(addrs.into_iter());
                Ok(it)
            } else {
                Err(Box::new(std::io::Error::other("host not pinned"))
                    as Box<dyn std::error::Error + Send + Sync>)
            }
        })
    }
}

// ======================================================================================
// Errors
// ======================================================================================

/// Why an egress request failed. Carries no URL, header or body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    /// Only `https` is allowed.
    #[error("scheme not allowed")]
    SchemeNotAllowed,
    /// URL is malformed, has user-info, or no host.
    #[error("invalid url")]
    InvalidUrl,
    /// Request origin differs from the pinned origin.
    #[error("origin not pinned")]
    OriginMismatch,
    /// Destination address is blocked.
    #[error("destination address blocked ({0})")]
    Blocked(&'static str),
    /// DNS resolution failed.
    #[error("dns resolution failed")]
    Resolution,
    /// TCP/TLS connection failed (request not sent).
    #[error("connection failed")]
    Connect,
    /// Timed out. `sent` = the request may have reached the server.
    #[error("timeout")]
    Timeout {
        /// Whether the request may have been delivered.
        sent: bool,
    },
    /// 3xx response; redirects are never followed. The request was delivered.
    #[error("redirect not followed")]
    Redirect {
        /// Upstream status.
        status: u16,
    },
    /// Response exceeded the size cap. The request was delivered and answered.
    #[error("response too large")]
    TooLarge {
        /// Upstream status.
        status: u16,
    },
    /// Other transport failure after sending.
    #[error("transport error")]
    Transport {
        /// Whether the request may have been delivered.
        sent: bool,
    },
    /// The client could not be configured.
    #[error("client setup failed")]
    Setup,
}

impl EgressError {
    /// Whether the request may have been delivered upstream. A redirect or an oversized
    /// response is an answer to a delivered request, so a write may have been applied.
    pub fn maybe_sent(&self) -> bool {
        matches!(
            self,
            EgressError::Timeout { sent: true }
                | EgressError::Transport { sent: true }
                | EgressError::Redirect { .. }
                | EgressError::TooLarge { .. }
        )
    }

    /// Map to an API error. `writes` = the operation has side effects, so a possibly
    /// delivered request is reported as `UPSTREAM_OUTCOME_UNKNOWN`.
    pub fn to_api(&self, writes: bool) -> ApiError {
        if writes && self.maybe_sent() {
            return errors::outcome_unknown(match self {
                EgressError::Timeout { .. } => "timeout",
                EgressError::Redirect { .. } => "redirect",
                EgressError::TooLarge { .. } => "response_too_large",
                _ => "transport",
            });
        }
        match self {
            EgressError::SchemeNotAllowed => errors::scope_denied(
                "只允许 HTTPS 目标",
                "Only HTTPS destinations are allowed.",
            )
            .with_detail("reason", "scheme_not_allowed"),
            EgressError::InvalidUrl => errors::scope_denied(
                "目标地址无效",
                "The destination URL is invalid.",
            )
            .with_detail("reason", "invalid_url"),
            EgressError::OriginMismatch => errors::scope_denied(
                "请求的目标与资源配置的地址不一致",
                "The request target does not match the configured origin.",
            )
            .with_detail("reason", "origin_mismatch"),
            EgressError::Blocked(why) => errors::scope_denied(
                "目标地址属于内网、本机或云元数据等受限网络，已拒绝",
                "The destination resolves to a blocked network (private, loopback, link-local, metadata…).",
            )
            .with_detail("reason", "blocked_address")
            .with_detail("range", (*why).to_owned()),
            EgressError::Resolution => errors::upstream(
                "dns",
                "无法解析目标域名",
                "The destination host name could not be resolved.",
            ),
            EgressError::Connect => errors::upstream(
                "connect",
                "无法连接外部服务",
                "Could not connect to the external service.",
            ),
            EgressError::Timeout { .. } => errors::upstream(
                "timeout",
                "外部服务响应超时",
                "The external service timed out.",
            ),
            EgressError::Redirect { .. } => errors::upstream(
                "redirect_not_followed",
                "外部服务返回了重定向，出于安全原因未跟随",
                "The external service redirected; redirects are not followed for safety.",
            ),
            EgressError::TooLarge { .. } => errors::upstream(
                "response_too_large",
                "外部服务的响应超过大小上限",
                "The external response exceeded the size limit.",
            ),
            EgressError::Transport { .. } => errors::upstream(
                "transport",
                "与外部服务通信失败",
                "Communication with the external service failed.",
            ),
            EgressError::Setup => ApiError::new(ErrorCode::Internal),
        }
    }
}

fn classify_reqwest(e: &reqwest::Error) -> EgressError {
    // Never format `e`: its Display includes the URL (and therefore query-string secrets).
    if e.is_timeout() {
        EgressError::Timeout {
            sent: !e.is_connect(),
        }
    } else if e.is_connect() {
        EgressError::Connect
    } else if e.is_redirect() {
        EgressError::Redirect {
            status: e.status().map_or(300, |s| s.as_u16()),
        }
    } else if e.is_builder() {
        EgressError::InvalidUrl
    } else {
        EgressError::Transport {
            sent: e.is_body() || e.is_decode() || e.is_request(),
        }
    }
}

// ======================================================================================
// Policy, request, response
// ======================================================================================

/// Per-request egress policy.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// Unlock private / loopback / link-local ranges (never metadata).
    pub allow_private_network: bool,
    /// Total timeout (clamped to [`MAX_TIMEOUT`]).
    pub timeout: Duration,
    /// Body cap (clamped to [`MAX_RESPONSE_BYTES`]).
    pub max_response_bytes: usize,
    /// Test-only: allow plain `http` (set only via the `test-util` GitHub override).
    pub(crate) allow_http: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allow_private_network: false,
            timeout: MAX_TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
            allow_http: false,
        }
    }
}

impl EgressPolicy {
    fn effective_timeout(&self) -> Duration {
        self.timeout.min(MAX_TIMEOUT).max(Duration::from_millis(50))
    }
    fn effective_cap(&self) -> usize {
        self.max_response_bytes.clamp(1, MAX_RESPONSE_BYTES)
    }
}

/// An outbound request (built by a connector from validated parameters).
pub struct EgressRequest {
    /// Method.
    pub method: reqwest::Method,
    /// Full URL (must be same-origin with `origin`).
    pub url: Url,
    /// Headers. Values marked sensitive by the connector are never logged.
    pub headers: HeaderMap,
    /// JSON body bytes.
    pub body: Option<Vec<u8>>,
}

impl fmt::Debug for EgressRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Path only: the query string may carry an API key.
        f.debug_struct("EgressRequest")
            .field("method", &self.method)
            .field("host", &self.url.host_str())
            .field("path", &self.url.path())
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A response with only the metadata connectors need — upstream headers are never passed on.
#[derive(Debug, Clone)]
pub struct EgressResponse {
    /// HTTP status.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// `Retry-After` seconds.
    pub retry_after: Option<u64>,
    /// `X-RateLimit-Remaining`.
    pub rate_limit_remaining: Option<u64>,
    /// `X-RateLimit-Reset` (unix seconds).
    pub rate_limit_reset: Option<u64>,
    /// Body (≤ cap).
    pub body: Vec<u8>,
}

/// A vetted origin: host resolved and every address allowed.
#[derive(Debug, Clone)]
pub struct VettedOrigin {
    /// `https` (or `http` under the test switch).
    pub scheme: String,
    /// Host as in the URL.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Vetted socket addresses.
    pub addrs: Vec<SocketAddr>,
    /// Whether the host is an IP literal.
    pub ip_literal: bool,
}

// ======================================================================================
// Guard
// ======================================================================================

/// The egress guard. Cheap to clone.
#[derive(Clone)]
pub struct EgressGuard {
    resolver: Arc<dyn EgressResolver>,
    tls: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for EgressGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressGuard")
            .field("resolver", &self.resolver)
            .finish()
    }
}

impl EgressGuard {
    /// Guard with the given resolver and TLS client configuration.
    pub fn new(resolver: Arc<dyn EgressResolver>, tls: rustls::ClientConfig) -> Self {
        Self {
            resolver,
            tls: Arc::new(tls),
        }
    }

    /// Validate a base URL's shape (scheme, host, no user-info) without resolving.
    pub fn check_url_shape(url: &Url, allow_http: bool) -> Result<(), EgressError> {
        match url.scheme() {
            "https" => {}
            "http" if allow_http => {}
            _ => return Err(EgressError::SchemeNotAllowed),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::InvalidUrl);
        }
        if url.host().is_none() || url.cannot_be_a_base() {
            return Err(EgressError::InvalidUrl);
        }
        Ok(())
    }

    /// Resolve and vet `url`'s origin.
    pub async fn vet(&self, url: &Url, policy: &EgressPolicy) -> Result<VettedOrigin, EgressError> {
        Self::check_url_shape(url, policy.allow_http)?;
        let port = url.port_or_known_default().ok_or(EgressError::InvalidUrl)?;
        let (host, ips, ip_literal) = match url.host() {
            Some(Host::Ipv4(ip)) => (ip.to_string(), vec![IpAddr::V4(ip)], true),
            Some(Host::Ipv6(ip)) => (format!("[{ip}]"), vec![IpAddr::V6(ip)], true),
            Some(Host::Domain(d)) => {
                let d = d.trim_end_matches('.').to_ascii_lowercase();
                if d.is_empty() {
                    return Err(EgressError::InvalidUrl);
                }
                // A name that parses as an IP would have been normalised by the URL parser;
                // anything left is a DNS name.
                let ips = self.resolver.resolve(&d).await?;
                (d, ips, false)
            }
            None => return Err(EgressError::InvalidUrl),
        };
        for ip in &ips {
            is_allowed(*ip, policy.allow_private_network).map_err(EgressError::Blocked)?;
        }
        Ok(VettedOrigin {
            scheme: url.scheme().to_owned(),
            host,
            port,
            addrs: ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
            ip_literal,
        })
    }

    fn client(
        &self,
        origin: &VettedOrigin,
        policy: &EgressPolicy,
    ) -> Result<reqwest::Client, EgressError> {
        let timeout = policy.effective_timeout();
        let mut b = reqwest::Client::builder()
            .tls_backend_preconfigured((*self.tls).clone())
            .https_only(!policy.allow_http)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .referer(false)
            .user_agent(USER_AGENT)
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .pool_max_idle_per_host(0);
        if !origin.ip_literal {
            b = b.dns_resolver(Arc::new(PinnedResolve {
                host: origin.host.clone(),
                addrs: origin.addrs.clone(),
            }));
        }
        b.build().map_err(|_| EgressError::Setup)
    }

    /// Send `req` to the pinned `origin_url` origin under `policy`.
    pub async fn fetch(
        &self,
        origin_url: &Url,
        req: EgressRequest,
        policy: &EgressPolicy,
    ) -> Result<EgressResponse, EgressError> {
        if req.url.origin() != origin_url.origin()
            || !req.url.username().is_empty()
            || req.url.password().is_some()
        {
            return Err(EgressError::OriginMismatch);
        }
        let origin = self.vet(origin_url, policy).await?;
        let client = self.client(&origin, policy)?;
        let mut rb = client.request(req.method.clone(), req.url.clone());
        rb = rb.headers(req.headers);
        if let Some(body) = req.body {
            rb = rb
                .header(
                    reqwest::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )
                .body(body);
        }
        tracing::debug!(host = %origin.host, path = %req.url.path(), method = %req.method, "egress request");
        let mut resp = rb.send().await.map_err(|e| classify_reqwest(&e))?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            return Err(EgressError::Redirect { status });
        }
        let cap = policy.effective_cap();
        if resp.content_length().is_some_and(|l| l > cap as u64) {
            return Err(EgressError::TooLarge { status });
        }
        let headers = resp.headers();
        let header_u64 = |name: &str| -> Option<u64> {
            headers
                .get(HeaderName::from_bytes(name.as_bytes()).ok()?)?
                .to_str()
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        let retry_after = header_u64("retry-after");
        let rate_limit_remaining = header_u64("x-ratelimit-remaining");
        let rate_limit_reset = header_u64("x-ratelimit-reset");
        let mut body = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > cap {
                        return Err(EgressError::TooLarge { status });
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    return Err(match classify_reqwest(&e) {
                        EgressError::Timeout { .. } => EgressError::Timeout { sent: true },
                        _ => EgressError::Transport { sent: true },
                    });
                }
            }
        }
        Ok(EgressResponse {
            status,
            content_type,
            retry_after,
            rate_limit_remaining,
            rate_limit_reset,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_allowed(s.parse().unwrap(), false).is_err()
    }

    #[test]
    fn ssrf_address_table() {
        for s in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.1.1",
            "100.64.0.1",
            "100.100.100.200",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:8.8.8.8",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "fd00:ec2::254",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(blocked(s), "{s} should be blocked");
        }
        for s in [
            "8.8.8.8",
            "140.82.112.6",
            "2606:4700::1111",
            "64:ff9b::808:808",
        ] {
            if s == "64:ff9b::808:808" {
                // NAT64 of a public address is still treated as private (embedded form).
                assert!(blocked(s));
                continue;
            }
            assert!(!blocked(s), "{s} should be allowed");
        }
    }

    #[test]
    fn private_network_flag_never_unlocks_metadata() {
        for s in [
            "169.254.169.254",
            "fd00:ec2::254",
            "224.0.0.1",
            "0.0.0.0",
            "100.100.100.200",
        ] {
            assert!(is_allowed(s.parse().unwrap(), true).is_err(), "{s}");
        }
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "::1",
            "fd12::1",
            "::ffff:192.168.0.1",
        ] {
            assert!(is_allowed(s.parse().unwrap(), true).is_ok(), "{s}");
        }
    }

    #[test]
    fn url_shape() {
        assert_eq!(
            EgressGuard::check_url_shape(&Url::parse("http://example.com").unwrap(), false),
            Err(EgressError::SchemeNotAllowed)
        );
        assert_eq!(
            EgressGuard::check_url_shape(&Url::parse("https://u:p@example.com").unwrap(), false),
            Err(EgressError::InvalidUrl)
        );
        // WHATWG parsing normalises numeric hosts, so 0x7f000001 is seen as 127.0.0.1.
        let u = Url::parse("https://0x7f000001/").unwrap();
        assert_eq!(u.host(), Some(Host::Ipv4(Ipv4Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn names_resolving_to_loopback_are_refused() {
        // The OS resolver answers `localhost` from the hosts file (no network needed).
        let guard = EgressGuard::new(
            Arc::new(SystemResolver),
            crate::tls::webpki_config(true, &[], true).unwrap(),
        );
        let url = Url::parse("https://localhost:8443/x").unwrap();
        let err = guard.vet(&url, &EgressPolicy::default()).await.unwrap_err();
        assert!(matches!(err, EgressError::Blocked(_)), "{err:?}");
        let ok = guard
            .vet(
                &url,
                &EgressPolicy {
                    allow_private_network: true,
                    ..EgressPolicy::default()
                },
            )
            .await
            .unwrap();
        assert!(ok.addrs.iter().all(|a| a.ip().is_loopback()));
        assert_eq!(ok.port, 8443);
    }

    #[test]
    fn errors_carry_no_url() {
        let e = EgressError::Blocked("loopback").to_api(false);
        assert_eq!(e.code, ErrorCode::ScopeDenied);
        let e = EgressError::Timeout { sent: true }.to_api(true);
        assert_eq!(e.code, ErrorCode::UpstreamOutcomeUnknown);
    }

    #[test]
    fn answered_writes_are_outcome_unknown() {
        // EGR-02: a 3xx or an oversized answer means the request was delivered.
        for (e, reason) in [
            (EgressError::Redirect { status: 303 }, "redirect"),
            (EgressError::TooLarge { status: 201 }, "response_too_large"),
            (EgressError::Timeout { sent: true }, "timeout"),
            (EgressError::Transport { sent: true }, "transport"),
        ] {
            assert!(e.maybe_sent(), "{e:?}");
            let api = e.to_api(true);
            assert_eq!(api.code, ErrorCode::UpstreamOutcomeUnknown, "{e:?}");
            assert_eq!(api.details["reason"], reason, "{e:?}");
        }
        // Reads keep the plain upstream errors.
        assert_eq!(
            EgressError::Redirect { status: 302 }.to_api(false).details["reason"],
            "redirect_not_followed"
        );
        assert_eq!(
            EgressError::TooLarge { status: 200 }.to_api(false).details["reason"],
            "response_too_large"
        );
        // Never delivered: a write is a plain failure.
        for e in [EgressError::Connect, EgressError::Timeout { sent: false }] {
            assert!(!e.maybe_sent());
            assert_ne!(e.to_api(true).code, ErrorCode::UpstreamOutcomeUnknown);
        }
    }
}
