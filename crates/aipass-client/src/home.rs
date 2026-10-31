// SPDX-License-Identifier: Apache-2.0
//! `AIPASS_HOME` layout (CONTRACTS §1.7, §9).
//!
//! ```text
//! <AIPASS_HOME>/                      default ~/.aipass  (0700)
//! ├── broker.json                     optional {"url": "unix:///…" | "http://127.0.0.1:7878"}
//! ├── connections/<conn_id>.key       connection keys of AI host bridges (0600)
//! └── run/broker.sock                 local broker UDS (desktop app / `aipass node`)
//! ```

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::ClientError;

/// Environment variable naming the AI Pass home directory.
pub const ENV_HOME: &str = "AIPASS_HOME";
/// Environment variable naming the broker URL.
pub const ENV_BROKER_URL: &str = "AIPASS_BROKER_URL";
/// Environment variable naming the cloud base URL.
pub const ENV_CLOUD_URL: &str = "AIPASS_CLOUD_URL";
/// Default cloud base URL (placeholder domain, CONTRACTS §1.7).
pub const DEFAULT_CLOUD_URL: &str = "https://cloud.aipass.example";

/// The AI Pass home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AipassHome {
    root: PathBuf,
}

impl AipassHome {
    /// Use an explicit directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `AIPASS_HOME` from the process environment, else `~/.aipass`.
    pub fn from_env() -> Result<Self, ClientError> {
        Self::from_env_value(std::env::var_os(ENV_HOME))
    }

    /// Like [`AipassHome::from_env`] with an explicit value of `AIPASS_HOME` (tests, embedders).
    /// An empty value counts as unset.
    pub fn from_env_value(value: Option<OsString>) -> Result<Self, ClientError> {
        match value {
            Some(v) if !v.is_empty() => {
                let p = PathBuf::from(v);
                if !p.is_absolute() {
                    return Err(ClientError::Config(format!(
                        "{ENV_HOME} must be an absolute path (got {})",
                        p.display()
                    )));
                }
                Ok(Self::new(p))
            }
            _ => {
                let home = dirs::home_dir().ok_or_else(|| {
                    ClientError::Config("cannot determine the home directory".into())
                })?;
                Ok(Self::new(home.join(".aipass")))
            }
        }
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<home>/connections`.
    pub fn connections_dir(&self) -> PathBuf {
        self.root.join("connections")
    }

    /// `<home>/run`.
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// `<home>/run/broker.sock` — the default local broker socket.
    pub fn broker_socket(&self) -> PathBuf {
        self.run_dir().join("broker.sock")
    }

    /// `<home>/broker.json`.
    pub fn broker_json(&self) -> PathBuf {
        self.root.join("broker.json")
    }
}

/// Create `dir` (and parents) and restrict it to the owner (0700 on Unix).
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), ClientError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir)?;
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let h = AipassHome::from_env_value(Some("/tmp/aph".into())).unwrap();
        assert_eq!(h.connections_dir(), PathBuf::from("/tmp/aph/connections"));
        assert_eq!(h.broker_socket(), PathBuf::from("/tmp/aph/run/broker.sock"));
        assert_eq!(h.broker_json(), PathBuf::from("/tmp/aph/broker.json"));
        assert!(AipassHome::from_env_value(Some("relative/dir".into())).is_err());
        let d = AipassHome::from_env_value(Some("".into())).unwrap();
        assert!(d.root().ends_with(".aipass"));
    }
}
