// SPDX-License-Identifier: Apache-2.0
//! Desktop IPC endpoint used by `aipass-nm-host`.
//!
//! * Unix: socket `<AIPASS_HOME>/run/desktop.sock` (mode 0600 inside a 0700 directory).
//! * Windows: named pipe `\\.\pipe\aipass-desktop-<hash of AIPASS_HOME>`.
//!
//! The first frame on every connection is `{"type":"auth","v":1,"token":…,"origin":…}`.
//! `token` is the per-install secret from `<AIPASS_HOME>/run/desktop.token` (0600) and
//! `origin` is the `chrome-extension://<id>/` origin Chrome passed to the host. The desktop
//! answers `{"type":"auth","ok":true}` or `{"type":"auth","ok":false,"code":…}` and closes.
//! Afterwards both sides exchange CONTRACTS §11 request/response frames verbatim.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::frame::{read_frame, write_json};

/// Environment variable that relocates the data root (CONTRACTS §1.7).
pub const ENV_HOME: &str = "AIPASS_HOME";
/// Token file name inside `run/`.
pub const TOKEN_FILE: &str = "desktop.token";
/// Socket file name inside `run/` (Unix).
pub const SOCKET_FILE: &str = "desktop.sock";
/// Token length in bytes (hex-encoded on disk).
pub const TOKEN_BYTES: usize = 32;

/// `AIPASS_HOME`, or `~/.aipass`.
pub fn aipass_home() -> Option<PathBuf> {
    match std::env::var_os(ENV_HOME) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => dirs::home_dir().map(|h| h.join(".aipass")),
    }
}

/// `<home>/run`.
pub fn run_dir(home: &Path) -> PathBuf {
    home.join("run")
}

/// `<home>/run/desktop.token`.
pub fn token_path(home: &Path) -> PathBuf {
    run_dir(home).join(TOKEN_FILE)
}

/// `<home>/run/desktop.sock`.
pub fn socket_path(home: &Path) -> PathBuf {
    run_dir(home).join(SOCKET_FILE)
}

/// Windows named-pipe name for `home` (FNV-1a of the path keeps one pipe per data root).
pub fn pipe_name(home: &Path) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in home.to_string_lossy().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!(r"\\.\pipe\aipass-desktop-{h:016x}")
}

/// Read and validate the token file (64 lowercase hex characters).
pub fn read_token(home: &Path) -> io::Result<String> {
    let raw = std::fs::read_to_string(token_path(home))?;
    let t = raw.trim().to_owned();
    if !is_valid_token(&t) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed desktop token"));
    }
    Ok(t)
}

/// 64 lowercase hex characters.
pub fn is_valid_token(t: &str) -> bool {
    t.len() == TOKEN_BYTES * 2 && t.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Constant-time token comparison.
pub fn token_matches(expected: &str, got: &str) -> bool {
    expected.len() == got.len() && bool::from(expected.as_bytes().ct_eq(got.as_bytes()))
}

/// `chrome-extension://<32 chars a-p>/` as passed by Chromium browsers in argv.
pub fn is_extension_origin(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("chrome-extension://") else {
        return false;
    };
    let Some(id) = rest.strip_suffix('/') else {
        return false;
    };
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// First argument that is an extension origin (Chrome passes it as argv[1]; Windows adds
/// `--parent-window=…`).
pub fn extension_origin_from_args<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    args.into_iter().find(|a| is_extension_origin(a))
}

/// The auth frame sent by the host.
pub fn auth_frame(token: &str, origin: &str) -> Value {
    json!({"type": "auth", "v": 1, "token": token, "origin": origin})
}

/// Any duplex byte stream.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// Connect to the desktop IPC endpoint.
pub async fn connect(home: &Path) -> io::Result<Box<dyn Duplex>> {
    #[cfg(unix)]
    {
        let s = tokio::net::UnixStream::connect(socket_path(home)).await?;
        Ok(Box::new(s))
    }
    #[cfg(windows)]
    {
        let c = tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name(home))?;
        Ok(Box::new(c))
    }
}

/// Why the handshake failed.
#[derive(Debug)]
pub enum HandshakeError {
    /// I/O or framing failure.
    Io(String),
    /// The desktop refused (e.g. `NOT_PAIRED`).
    Refused(String),
}

/// Perform the client side of the auth handshake.
pub async fn client_handshake(stream: &mut Box<dyn Duplex>, token: &str, origin: &str) -> Result<(), HandshakeError> {
    write_json(stream, &auth_frame(token, origin))
        .await
        .map_err(|e| HandshakeError::Io(e.to_string()))?;
    let reply = read_frame(stream)
        .await
        .map_err(|e| HandshakeError::Io(e.to_string()))?
        .ok_or_else(|| HandshakeError::Io("closed during handshake".into()))?;
    let v: Value = serde_json::from_slice(&reply).map_err(|_| HandshakeError::Io("bad handshake reply".into()))?;
    if v.get("type").and_then(Value::as_str) == Some("auth") && v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(HandshakeError::Refused(
            v.get("code").and_then(Value::as_str).unwrap_or("NOT_PAIRED").to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_and_tokens() {
        let o = format!("chrome-extension://{}/", "a".repeat(32));
        assert!(is_extension_origin(&o));
        assert!(!is_extension_origin("chrome-extension://abc/"));
        assert!(!is_extension_origin(&format!("chrome-extension://{}/", "z".repeat(32))));
        assert!(!is_extension_origin("https://example.com/"));
        assert_eq!(
            extension_origin_from_args(vec!["--parent-window=0".into(), o.clone()]),
            Some(o)
        );
        let t = "ab".repeat(32);
        assert!(is_valid_token(&t));
        assert!(!is_valid_token("AB"));
        assert!(token_matches(&t, &t));
        assert!(!token_matches(&t, &"cd".repeat(32)));
        assert!(!token_matches(&t, "ab"));
        assert!(pipe_name(Path::new("/x")).starts_with(r"\\.\pipe\aipass-desktop-"));
    }
}
