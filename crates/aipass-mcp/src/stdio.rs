// SPDX-License-Identifier: Apache-2.0
//! stdio transport: newline-delimited JSON-RPC on stdin/stdout. **stdout carries protocol
//! messages only** (one JSON per line, no embedded newlines); logs go to stderr.
//!
//! Requests are served concurrently (bounded), so a slow `tools/call` never blocks `ping`.
//! Oversized lines are discarded and answered with a parse error. On EOF the server waits
//! for in-flight requests, flushes and returns.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::protocol::{self, PARSE_ERROR};
use crate::server::{MAX_MESSAGE_BYTES, McpContext, McpServer};

/// Maximum concurrently served requests.
pub const MAX_IN_FLIGHT: usize = 32;
/// How long EOF waits for in-flight requests.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

enum Line {
    Message(Vec<u8>),
    TooLong,
    Eof,
}

async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let mut too_long = false;
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() && !too_long {
                return Ok(Line::Eof);
            }
            break;
        }
        let (chunk, done) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (&available[..i], Some(i + 1)),
            None => (available, None),
        };
        if !too_long {
            if buf.len() + chunk.len() > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let consumed = done.unwrap_or(available.len());
        r.consume(consumed);
        if done.is_some() {
            break;
        }
    }
    Ok(if too_long { Line::TooLong } else { Line::Message(buf) })
}

/// Serve MCP over the given reader/writer until EOF.
pub async fn serve<R, W>(server: Arc<McpServer>, ctx: McpContext, input: R, output: W) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Value>(64);
    let writer = tokio::spawn(async move {
        let mut out = output;
        while let Some(msg) = rx.recv().await {
            // serde_json escapes control characters, so a message never contains a raw newline
            let mut line = match serde_json::to_vec(&msg) {
                Ok(l) => l,
                Err(_) => continue,
            };
            line.push(b'\n');
            if out.write_all(&line).await.is_err() || out.flush().await.is_err() {
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stdout closed"));
            }
        }
        out.flush().await
    });
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = JoinSet::new();
    let mut input = input;
    loop {
        let line = read_line(&mut input, MAX_MESSAGE_BYTES).await?;
        match line {
            Line::Eof => break,
            Line::TooLong => {
                tracing::warn!("discarding an oversized stdin message");
                let _ = tx.send(protocol::error(&Value::Null, PARSE_ERROR, "Parse error: message too large")).await;
            }
            Line::Message(bytes) => {
                let trimmed = trim_ascii(&bytes);
                if trimmed.is_empty() {
                    continue;
                }
                let msg = trimmed.to_vec();
                let permit = match limit.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let server = server.clone();
                let ctx = ctx.clone();
                let tx = tx.clone();
                // initialize must complete before later messages are interpreted
                let sequential = is_lifecycle(&msg);
                let fut = async move {
                    let _permit = permit;
                    if let Some(resp) = server.handle(&msg, &ctx).await {
                        let _ = tx.send(resp).await;
                    }
                };
                if sequential {
                    fut.await;
                } else {
                    tasks.spawn(fut);
                }
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        tracing::warn!("in-flight requests did not finish before shutdown");
    }
    drop(tx);
    match writer.await {
        Ok(r) => r,
        Err(_) => Ok(()),
    }
}

/// `initialize` and notifications are handled in order (they change session state).
fn is_lifecycle(msg: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(msg) {
        Ok(Value::Object(o)) => {
            let method = o.get("method").and_then(Value::as_str);
            matches!(method, Some("initialize")) || (method.is_some() && !o.contains_key("id"))
        }
        _ => true,
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &b[start..end.max(start)]
}

/// Serve on the process's stdin/stdout.
pub async fn run(server: Arc<McpServer>, ctx: McpContext) -> std::io::Result<()> {
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    serve(server, ctx, stdin, tokio::io::stdout()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn line_reader_limits() {
        let data = b"{\"a\":1}\n\n   \n".to_vec();
        let mut r = tokio::io::BufReader::new(&data[..]);
        assert!(matches!(read_line(&mut r, 100).await.unwrap(), Line::Message(m) if m == b"{\"a\":1}"));
        assert!(matches!(read_line(&mut r, 100).await.unwrap(), Line::Message(m) if m.is_empty()));
        assert!(matches!(read_line(&mut r, 100).await.unwrap(), Line::Message(_)));
        assert!(matches!(read_line(&mut r, 100).await.unwrap(), Line::Eof));
        let big = [vec![b'x'; 50], b"\n{}\n".to_vec()].concat();
        let mut r = tokio::io::BufReader::with_capacity(8, &big[..]);
        assert!(matches!(read_line(&mut r, 10).await.unwrap(), Line::TooLong));
        assert!(matches!(read_line(&mut r, 10).await.unwrap(), Line::Message(m) if m == b"{}"));
        // last line without trailing newline
        let tail = b"{}".to_vec();
        let mut r = tokio::io::BufReader::new(&tail[..]);
        assert!(matches!(read_line(&mut r, 10).await.unwrap(), Line::Message(m) if m == b"{}"));
        assert_eq!(trim_ascii(b"  {} \r"), b"{}");
    }
}
