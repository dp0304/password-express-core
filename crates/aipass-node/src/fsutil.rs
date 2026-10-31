// SPDX-License-Identifier: Apache-2.0
//! Private file helpers (0700 directories, 0600 files, atomic replace).

use std::io::Write;
use std::path::Path;

use anyhow::{Context, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Create `dir` (and parents) with mode 0700 for the leaf.
pub fn private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot chmod {}", dir.display()))?;
    }
    Ok(())
}

/// Refuse files readable or writable by group / others.
pub fn check_private_file(path: &Path) -> anyhow::Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("{} is accessible by other users; run `chmod 600` on it", path.display());
        }
    }
    let _ = meta;
    Ok(())
}

/// Atomically write `bytes` to `path` with mode 0600.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        aipass_crypto::b64u::encode(aipass_crypto::rng::random_array::<6>())
    ));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

/// Read a JSON file; `None` if it does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b).with_context(|| format!("{} is corrupt", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Write a JSON file privately.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    write_private(path, &serde_json::to_vec_pretty(value)?)
}
