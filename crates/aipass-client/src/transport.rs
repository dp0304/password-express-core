// SPDX-License-Identifier: Apache-2.0
//! Byte-level transports: Unix domain socket (hyper HTTP/1.1, one connection per request)
//! and HTTP(S) (reqwest + rustls, redirects disabled so credentials are never replayed to
//! another origin).

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use url::Url;

use crate::endpoint::BrokerEndpoint;
use crate::error::ClientError;

/// Largest response body accepted from the broker.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A raw response.
#[derive(Debug, Clone)]
pub struct RawResponse {
    /// HTTP status.
    pub status: u16,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
}

#[derive(Clone)]
pub(crate) enum Transport {
    #[cfg(unix)]
    Unix { path: std::path::PathBuf },
    Http { client: reqwest::Client, base: Url },
}

impl Transport {
    pub(crate) fn new(
        endpoint: &BrokerEndpoint,
        user_agent: &str,
        connect_timeout: Duration,
    ) -> Result<Self, ClientError> {
        match endpoint {
            #[cfg(unix)]
            BrokerEndpoint::Unix(p) => Ok(Transport::Unix { path: p.clone() }),
            #[cfg(not(unix))]
            BrokerEndpoint::Unix(_) => Err(ClientError::Config(
                "unix:// broker URLs are not supported on this platform; use http://127.0.0.1:7878".into(),
            )),
            BrokerEndpoint::Http(base) => {
                let client = reqwest::Client::builder()
                    .user_agent(user_agent)
                    .connect_timeout(connect_timeout)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|e| ClientError::Config(format!("HTTP client: {e}")))?;
                Ok(Transport::Http {
                    client,
                    base: base.clone(),
                })
            }
        }
    }

    /// The path+query exactly as it will appear on the wire for `path_and_query`
    /// (prefixing an HTTP base path, normalized like the URL parser does).
    pub(crate) fn wire_path(&self, path_and_query: &str) -> Result<String, ClientError> {
        match self {
            #[cfg(unix)]
            Transport::Unix { .. } => {
                let uri: http::Uri = path_and_query
                    .parse()
                    .map_err(|_| ClientError::Config(format!("invalid request path {path_and_query:?}")))?;
                Ok(uri
                    .path_and_query()
                    .map(|p| p.as_str().to_owned())
                    .unwrap_or_else(|| "/".to_owned()))
            }
            Transport::Http { base, .. } => {
                let url = self.http_url(base, path_and_query)?;
                Ok(match url.query() {
                    Some(q) => format!("{}?{}", url.path(), q),
                    None => url.path().to_owned(),
                })
            }
        }
    }

    fn http_url(&self, base: &Url, path_and_query: &str) -> Result<Url, ClientError> {
        let prefix = {
            let p = base.path();
            if p == "/" { "" } else { p }
        };
        let origin = base.origin().ascii_serialization();
        Url::parse(&format!("{origin}{prefix}{path_and_query}"))
            .map_err(|_| ClientError::Config(format!("invalid request path {path_and_query:?}")))
    }

    pub(crate) async fn send(
        &self,
        endpoint_label: &str,
        method: Method,
        wire_path: &str,
        headers: Vec<(HeaderName, HeaderValue)>,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<RawResponse, ClientError> {
        let fut = self.send_inner(endpoint_label, method, wire_path, headers, body);
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(_) => Err(ClientError::Unreachable {
                endpoint: endpoint_label.to_owned(),
                reason: format!("no response within {} s", timeout.as_secs()),
            }),
        }
    }

    async fn send_inner(
        &self,
        endpoint_label: &str,
        method: Method,
        wire_path: &str,
        headers: Vec<(HeaderName, HeaderValue)>,
        body: Vec<u8>,
    ) -> Result<RawResponse, ClientError> {
        let unreachable = |reason: String| ClientError::Unreachable {
            endpoint: endpoint_label.to_owned(),
            reason,
        };
        match self {
            #[cfg(unix)]
            Transport::Unix { path } => {
                use http_body_util::{BodyExt, Full, Limited};
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|e| {
                        unreachable(match e.kind() {
                            std::io::ErrorKind::NotFound => "socket not found".to_owned(),
                            std::io::ErrorKind::ConnectionRefused => "connection refused".to_owned(),
                            std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
                            std::io::ErrorKind::InvalidInput => "invalid socket path (too long?)".to_owned(),
                            _ => e.to_string(),
                        })
                    })?;
                let io = hyper_util::rt::TokioIo::new(stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(|e| unreachable(format!("HTTP handshake failed: {e}")))?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!(error = %e, "broker UDS connection closed with error");
                    }
                });
                let mut req = http::Request::builder()
                    .method(method)
                    .uri(wire_path)
                    .header(http::header::HOST, "localhost");
                for (k, v) in headers {
                    req = req.header(k, v);
                }
                let req = req
                    .body(Full::new(Bytes::from(body)))
                    .map_err(|e| ClientError::Config(format!("invalid request: {e}")))?;
                let resp = sender
                    .send_request(req)
                    .await
                    .map_err(|e| unreachable(format!("request failed: {e}")))?;
                let (parts, body) = resp.into_parts();
                let collected = Limited::new(body, MAX_RESPONSE_BYTES)
                    .collect()
                    .await
                    .map_err(|_| {
                        ClientError::Protocol(format!(
                            "response body larger than {MAX_RESPONSE_BYTES} bytes or truncated"
                        ))
                    })?;
                Ok(RawResponse {
                    status: parts.status.as_u16(),
                    headers: parts.headers,
                    body: collected.to_bytes(),
                })
            }
            Transport::Http { client, base } => {
                // `wire_path` (from `wire_path()`) already carries the endpoint's path prefix
                // and is exactly the path that was signed: send it verbatim on the origin.
                let url = Url::parse(&format!("{}{wire_path}", base.origin().ascii_serialization()))
                    .map_err(|_| ClientError::Config(format!("invalid request path {wire_path:?}")))?;
                let mut req = client.request(method, url);
                for (k, v) in headers {
                    req = req.header(k, v);
                }
                let mut resp = req
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| unreachable(describe_reqwest(&e)))?;
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                if resp
                    .content_length()
                    .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
                {
                    return Err(ClientError::Protocol(format!(
                        "response body larger than {MAX_RESPONSE_BYTES} bytes"
                    )));
                }
                let mut buf = Vec::new();
                while let Some(chunk) = resp
                    .chunk()
                    .await
                    .map_err(|e| unreachable(describe_reqwest(&e)))?
                {
                    if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                        return Err(ClientError::Protocol(format!(
                            "response body larger than {MAX_RESPONSE_BYTES} bytes"
                        )));
                    }
                    buf.extend_from_slice(&chunk);
                }
                Ok(RawResponse {
                    status,
                    headers,
                    body: Bytes::from(buf),
                })
            }
        }
    }
}

/// Short reason without URL query strings or headers (reqwest errors may contain the URL,
/// which never carries secrets here, but keep the text compact).
fn describe_reqwest(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_connect() {
        "connection failed".into()
    } else if e.is_body() || e.is_decode() {
        "response body error".into()
    } else if e.is_request() {
        "request error".into()
    } else {
        "HTTP error".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_paths() {
        let ep = BrokerEndpoint::parse("http://127.0.0.1:7878").unwrap();
        let t = Transport::new(&ep, "t", Duration::from_secs(1)).unwrap();
        assert_eq!(
            t.wire_path("/v1/resources?project_id=proj_1&service=a+b").unwrap(),
            "/v1/resources?project_id=proj_1&service=a+b"
        );
        let ep = BrokerEndpoint::parse("https://node.example.com/aipass/").unwrap();
        let t = Transport::new(&ep, "t", Duration::from_secs(1)).unwrap();
        assert_eq!(t.wire_path("/v1/health").unwrap(), "/aipass/v1/health");
        #[cfg(unix)]
        {
            let ep = BrokerEndpoint::parse("unix:///tmp/x.sock").unwrap();
            let t = Transport::new(&ep, "t", Duration::from_secs(1)).unwrap();
            assert_eq!(t.wire_path("/v1/a?b=c").unwrap(), "/v1/a?b=c");
            assert!(t.wire_path("/v1/a b").is_err());
        }
    }
}
