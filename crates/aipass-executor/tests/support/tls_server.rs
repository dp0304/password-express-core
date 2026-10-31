// SPDX-License-Identifier: Apache-2.0
//! A minimal HTTPS/1.1 server for egress-guard tests. It records every request (including
//! the TLS SNI-independent `Host` header) so tests can prove that nothing reached an
//! unapproved origin.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::certs::TestPki;

/// One received request.
#[derive(Debug, Clone)]
pub struct Hit {
    /// `Host` header.
    pub host: String,
    /// Method.
    pub method: String,
    /// Request target (path + query).
    pub target: String,
    /// Headers (lower-case names).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Hit {
    /// Header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A response.
pub struct Reply {
    /// Status.
    pub status: u16,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// Delay before answering.
    pub delay: Option<Duration>,
}

impl Reply {
    /// JSON reply.
    pub fn json(status: u16, v: serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&v).unwrap_or_default(),
            delay: None,
        }
    }
}

type Handler = Arc<dyn Fn(&Hit) -> Reply + Send + Sync>;

/// Running server.
pub struct TlsServer {
    /// Bound address (127.0.0.1).
    pub addr: SocketAddr,
    /// PKI (trust `pki.ca_pem`).
    pub pki: TestPki,
    /// Requests received.
    pub hits: Arc<Mutex<Vec<Hit>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsServer {
    /// Start on 127.0.0.1 with a certificate for `names`.
    pub async fn start(names: &[&str], handler: Handler) -> Self {
        let pki = TestPki::new(names);
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![pki.leaf_der.clone()], pki.key())
            .expect("server cert");
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::default();
        let hits2 = hits.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                let hits = hits2.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        if buf.len() > 64 * 1024 {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let mut lines = head.split("\r\n");
                    let first = lines.next().unwrap_or("");
                    let mut parts = first.split(' ');
                    let method = parts.next().unwrap_or("").to_owned();
                    let target = parts.next().unwrap_or("").to_owned();
                    let headers: Vec<(String, String)> = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                        .collect();
                    let len: usize = headers
                        .iter()
                        .find(|(k, _)| k == "content-length")
                        .and_then(|(_, v)| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = buf[header_end..].to_vec();
                    while body.len() < len {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => body.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let hit = Hit {
                        host: headers
                            .iter()
                            .find(|(k, _)| k == "host")
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default(),
                        method,
                        target,
                        headers,
                        body,
                    };
                    hits.lock().unwrap().push(hit.clone());
                    let reply = handler(&hit);
                    if let Some(d) = reply.delay {
                        tokio::time::sleep(d).await;
                    }
                    let mut out = format!(
                        "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    for (k, v) in &reply.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str("\r\n");
                    let _ = tls.write_all(out.as_bytes()).await;
                    let _ = tls.write_all(&reply.body).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            addr,
            pki,
            hits,
            task,
        }
    }

    /// Requests so far.
    pub fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
}
