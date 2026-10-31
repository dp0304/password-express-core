// SPDX-License-Identifier: Apache-2.0
//! On-disk layout of the desktop app. Everything lives under `AIPASS_HOME`
//! (default `~/.aipass`, CONTRACTS §1.7) so `aipass-mcp` bridges find the embedded
//! broker at `unix://<AIPASS_HOME>/run/broker.sock` without extra configuration.
//!
//! ```text
//! <home>/vault/            VaultClient data dir (device.json, state.json, cache/, outbox)
//! <home>/vault/secrets.json  device / storage secrets, Argon2id + XChaCha20 under the unlock password
//! <home>/node/             embedded broker (broker.db, admin.token)
//! <home>/connections/      AI connection keys written for host-config entries (0600)
//! <home>/run/broker.sock   broker API for aipass-mcp bridges (0600, dir 0700)
//! <home>/run/desktop.sock  native-messaging IPC (0600) + desktop.token (0600)
//! <home>/desktop.json      non-secret settings
//! ```

use std::path::{Path, PathBuf};

/// Resolved paths.
#[derive(Debug, Clone)]
pub struct AppPaths {
    /// Data root.
    pub home: PathBuf,
}

impl AppPaths {
    /// Paths under an explicit root.
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// `AIPASS_HOME` or `~/.aipass`.
    pub fn from_env() -> Option<Self> {
        aipass_nm::ipc::aipass_home().map(Self::new)
    }

    /// Root.
    pub fn home(&self) -> &Path {
        &self.home
    }
    /// VaultClient data dir.
    pub fn vault_dir(&self) -> PathBuf {
        self.home.join("vault")
    }
    /// Encrypted secret-store file.
    pub fn secrets_file(&self) -> PathBuf {
        self.vault_dir().join("secrets.json")
    }
    /// Embedded broker data dir.
    pub fn node_dir(&self) -> PathBuf {
        self.home.join("node")
    }
    /// `run/`.
    pub fn run_dir(&self) -> PathBuf {
        aipass_nm::ipc::run_dir(&self.home)
    }
    /// Broker socket.
    pub fn broker_socket(&self) -> PathBuf {
        self.run_dir().join("broker.sock")
    }
    /// Native-messaging IPC socket.
    pub fn desktop_socket(&self) -> PathBuf {
        aipass_nm::ipc::socket_path(&self.home)
    }
    /// Native-messaging IPC token.
    pub fn desktop_token(&self) -> PathBuf {
        aipass_nm::ipc::token_path(&self.home)
    }
    /// Settings file.
    pub fn settings_file(&self) -> PathBuf {
        self.home.join("desktop.json")
    }
    /// Default directory for "local folder" storage.
    pub fn default_local_storage(&self) -> PathBuf {
        self.home.join("storage")
    }
}

/// Create `dir` (and parents) with mode 0700 on Unix.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically with mode 0600 on Unix.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| std::io::Error::other("no parent"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
