// SPDX-License-Identifier: Apache-2.0
//! Small filesystem helpers: atomic private writes (0600 on Unix).

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::Result;

/// Write `bytes` to `path` atomically (temp file in the same directory + fsync + rename),
/// creating parent directories. On Unix the file is created with mode 0600 and the parent
/// directory (when newly created) with 0700.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let suffix: [u8; 8] = aipass_crypto::rng::try_random_array()?;
    let tmp = dir.join(format!(
        ".{name}.tmp-{}",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        let r = f.write_all(bytes).and_then(|_| f.sync_all());
        if let Err(e) = r {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Create a directory (and parents); new directories get mode 0700 on Unix.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)?;
    Ok(())
}

/// Read a file, `Ok(None)` when it does not exist.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_private_write() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/x.json");
        write_private_atomic(&p, b"one").unwrap();
        write_private_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(read_optional(&d.path().join("nope")).unwrap(), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(p.parent().unwrap()).unwrap().count(), 1);
    }
}
