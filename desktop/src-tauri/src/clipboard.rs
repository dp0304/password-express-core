// SPDX-License-Identifier: Apache-2.0
//! Copy-to-clipboard with auto-clear. The secret goes from Rust straight to the OS
//! clipboard (never through the WebView). After the delay the clipboard is cleared if it
//! still holds our value; only a SHA-256 of the value is kept for that comparison.
//!
//! The value is written with the platform's "concealed" markers (review CLI-03), so
//! clipboard history, clipboard managers and cloud clipboard sync skip it: macOS
//! `org.nspasteboard.ConcealedType` (also keeps it out of Universal Clipboard), Windows
//! `ExcludeClipboardContentFromMonitorProcessing` / `CanIncludeInClipboardHistory=0` /
//! `CanUploadToCloudClipboard=0`, Linux `x-kde-passwordManagerHint=secret`. These are
//! honoured by the OS and by well-behaved clipboard tools; a hostile process that polls
//! the clipboard can still read it while it is there, which is why it is cleared.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aipass_crypto::SecretString;
use serde_json::json;
use zeroize::Zeroizing;

use crate::core::EventSink;
use crate::error::{UiError, UiResult};

/// Tracks the latest copy so an older timer never clears a newer value.
#[derive(Debug, Default)]
pub struct ClipboardGuard {
    generation: Arc<AtomicU64>,
}

impl ClipboardGuard {
    /// Put `secret` on the clipboard and clear it after `delay`.
    pub fn copy(&self, secret: SecretString, delay: Duration, sink: Arc<dyn EventSink>) -> UiResult<()> {
        let my_gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let generation = self.generation.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), ()>>();
        std::thread::Builder::new()
            .name("aipass-clipboard".into())
            .spawn(move || {
                let mut cb = match arboard::Clipboard::new() {
                    Ok(c) => c,
                    Err(_) => {
                        let _ = tx.send(Err(()));
                        return;
                    }
                };
                let digest = aipass_crypto::sha256(secret.expose().as_bytes());
                let text = Zeroizing::new(secret.expose().to_owned());
                drop(secret);
                if set_concealed(&mut cb, text.as_str()).is_err() {
                    let _ = tx.send(Err(()));
                    return;
                }
                drop(text);
                let _ = tx.send(Ok(()));
                // Keep the clipboard object alive (X11 ownership) until the clear time.
                std::thread::sleep(delay);
                if generation.load(Ordering::SeqCst) != my_gen {
                    return;
                }
                let still_ours = cb
                    .get_text()
                    .map(|t| {
                        let t = Zeroizing::new(t);
                        aipass_crypto::ct_eq(&aipass_crypto::sha256(t.as_bytes()), &digest)
                    })
                    .unwrap_or(false);
                if still_ours {
                    let _ = cb.clear();
                    sink.emit("clipboard", json!({"cleared": true}));
                }
            })
            .map_err(|_| UiError::internal("clipboard thread"))?;
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(()),
            _ => Err(UiError::new(
                "INTERNAL",
                "无法访问系统剪贴板。",
                "Could not access the system clipboard.",
            )),
        }
    }
}

/// Write `text` marked as a concealed / transient value: excluded from clipboard history,
/// cloud clipboard sync and clipboard monitoring where the platform supports it.
fn set_concealed(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    let set = cb.set();
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple;
        set.exclude_from_history()
    };
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_cloud().exclude_from_history().exclude_from_monitoring()
    };
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))))]
    let set = {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    };
    set.text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review CLI-03: on macOS the copied value carries `org.nspasteboard.ConcealedType`.
    /// Touches the real system clipboard, so it only runs with
    /// `AIPASS_TEST_SYSTEM_CLIPBOARD=1`; the previous clipboard text is restored afterwards.
    #[cfg(target_os = "macos")]
    #[test]
    fn copy_marks_the_pasteboard_concealed() {
        use std::process::Command;
        if std::env::var("AIPASS_TEST_SYSTEM_CLIPBOARD").as_deref() != Ok("1") {
            eprintln!("skipped: set AIPASS_TEST_SYSTEM_CLIPBOARD=1 to run against the system clipboard");
            return;
        }
        let previous = Command::new("pbpaste").output().map(|o| o.stdout).unwrap_or_default();
        struct Null;
        impl EventSink for Null {
            fn emit(&self, _: &str, _: serde_json::Value) {}
        }
        let guard = ClipboardGuard::default();
        guard.copy("FAKE-concealed-test-value".into(), Duration::from_secs(1), Arc::new(Null)).unwrap();
        let types = Command::new("osascript")
            .args(["-l", "JavaScript", "-e", "ObjC.import('AppKit'); ObjC.deepUnwrap($.NSPasteboard.generalPasteboard.types).join('\\n')"])
            .output()
            .expect("osascript");
        let types = String::from_utf8_lossy(&types.stdout).into_owned();
        std::thread::sleep(Duration::from_millis(1500));
        let after = Command::new("pbpaste").output().map(|o| o.stdout).unwrap_or_default();
        // Restore what the developer had on the clipboard.
        let mut pb = Command::new("pbcopy").stdin(std::process::Stdio::piped()).spawn().unwrap();
        std::io::Write::write_all(pb.stdin.as_mut().unwrap(), &previous).unwrap();
        drop(pb.stdin.take());
        let _ = pb.wait();
        assert!(types.lines().any(|t| t == "org.nspasteboard.ConcealedType"), "pasteboard types: {types}");
        assert!(!String::from_utf8_lossy(&after).contains("FAKE-concealed-test-value"), "cleared after the delay");
    }
}
