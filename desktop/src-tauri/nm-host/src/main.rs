// SPDX-License-Identifier: Apache-2.0
//! `aipass-nm-host` — native-messaging host `com.aipass.native` (CONTRACTS §11).
//!
//! Chromium starts this binary when the AI 通行证 extension calls `connectNative`. It reads
//! framed requests on stdin, forwards them to the running desktop app over the local IPC
//! endpoint (authenticated with the per-install token), and writes the replies to stdout.
//! It holds no vault data itself. Message bodies are never logged.

use std::time::Duration;

use aipass_nm::frame::{FrameError, read_frame, write_json};
use aipass_nm::ipc::{self, Duplex};
use aipass_nm::proto::{self, codes};
use serde_json::{Value, json};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let origin = ipc::extension_origin_from_args(std::env::args().skip(1));
    let code = run(origin).await;
    std::process::exit(code);
}

async fn run(origin: Option<String>) -> i32 {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let home = ipc::aipass_home();
    let mut desktop: Option<Box<dyn Duplex>> = None;
    loop {
        let frame = match read_frame(&mut stdin).await {
            Ok(Some(f)) => f,
            Ok(None) => return 0,
            Err(FrameError::TooLarge(_)) => {
                eprintln!("aipass-nm-host: oversized message from browser; closing");
                return 1;
            }
            Err(FrameError::Io(_)) => return 1,
        };
        let Ok(req) = serde_json::from_slice::<Value>(&frame) else {
            eprintln!("aipass-nm-host: ignoring a message that is not JSON");
            continue;
        };
        let Some(id) = proto::request_id(&req).map(str::to_owned) else {
            eprintln!("aipass-nm-host: ignoring a message without a valid id");
            continue;
        };
        let kind = req.get("type").and_then(Value::as_str).unwrap_or("").to_owned();
        let reply = match (&origin, &home) {
            (None, _) => proto::err(&id, codes::NOT_PAIRED, "未知的扩展来源 / Unknown extension origin"),
            (_, None) => proto::offline_reply(&id, &kind, env!("CARGO_PKG_VERSION")),
            (Some(o), Some(h)) => forward(&mut desktop, h, o, &frame, &id, &kind).await,
        };
        if write_json(&mut stdout, &reply).await.is_err() {
            return 1;
        }
    }
}

async fn forward(
    desktop: &mut Option<Box<dyn Duplex>>,
    home: &std::path::Path,
    origin: &str,
    frame: &[u8],
    id: &str,
    kind: &str,
) -> Value {
    for attempt in 0..2 {
        if desktop.is_none() {
            match open(home, origin).await {
                Ok(s) => *desktop = Some(s),
                Err(code) if code == codes::LOCKED => {
                    // The app is not running (or not reachable): answer what we can
                    // truthfully answer ourselves so the extension can show "locked" and
                    // offer 打开桌面 App instead of failing its `hello`.
                    if kind == "open_app" {
                        return if launch_app() {
                            proto::ok(id, json!({}))
                        } else {
                            proto::err(id, codes::LOCKED, proto::APP_NOT_RUNNING)
                        };
                    }
                    return proto::offline_reply(id, kind, env!("CARGO_PKG_VERSION"));
                }
                Err(code) => {
                    return proto::err(id, &code, "桌面 App 未授权此扩展 / The desktop app has not authorised this extension");
                }
            }
        }
        let Some(s) = desktop.as_mut() else { break };
        let res = tokio::time::timeout(REQUEST_TIMEOUT, async {
            aipass_nm::frame::write_frame(s, frame).await.map_err(|_| ())?;
            match read_frame(s).await {
                Ok(Some(b)) => serde_json::from_slice::<Value>(&b).map_err(|_| ()),
                _ => Err(()),
            }
        })
        .await;
        match res {
            Ok(Ok(v)) if v.get("id").and_then(Value::as_str) == Some(id) => return v,
            Ok(Ok(_)) | Ok(Err(())) | Err(_) => {
                // Stale or broken connection: reconnect once, then give up.
                *desktop = None;
                if attempt == 1 {
                    break;
                }
            }
        }
    }
    proto::offline_reply(id, kind, env!("CARGO_PKG_VERSION"))
}

async fn open(home: &std::path::Path, origin: &str) -> Result<Box<dyn Duplex>, String> {
    let token = ipc::read_token(home).map_err(|_| codes::LOCKED.to_owned())?;
    let mut s = ipc::connect(home).await.map_err(|_| codes::LOCKED.to_owned())?;
    match ipc::client_handshake(&mut s, &token, origin).await {
        Ok(()) => Ok(s),
        Err(ipc::HandshakeError::Refused(code)) => Err(code),
        Err(ipc::HandshakeError::Io(_)) => Err(codes::LOCKED.to_owned()),
    }
}

/// Best-effort launch of the desktop app for `open_app` when it is not running.
fn launch_app() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .args(["-b", "com.aipass.desktop"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // The host is installed next to the app binary.
        let Ok(me) = std::env::current_exe() else { return false };
        let Some(dir) = me.parent() else { return false };
        let name = if cfg!(windows) { "aipass-desktop.exe" } else { "aipass-desktop" };
        std::process::Command::new(dir.join(name)).spawn().is_ok()
    }
}
