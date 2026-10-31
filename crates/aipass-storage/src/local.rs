// SPDX-License-Identifier: Apache-2.0
//! `LocalDirStore` — local directory backend (design doc §10.1: 本地目录, V1).
//!
//! Layout: each object key maps to a file under the root (`entries/ent_…/3.json` →
//! `<root>/entries/ent_…/3.json`). Keys are validated with
//! [`crate::validate_key`] (no `..`, no empty segments, safe characters only) and every
//! existing path component below the root is checked not to be a symlink, so a key can
//! never escape the root.
//!
//! Write semantics:
//! * every write first lands in `<root>/.aipass-tmp/<random>` (same filesystem), is
//!   `fsync`ed, and only then becomes visible — readers never see partial content of a
//!   regular write;
//! * `IfAbsent` publishes with `link(2)` (fails atomically with `EEXIST`); on filesystems
//!   without hard links it falls back to an `O_EXCL` claim followed by an atomic rename
//!   (a concurrent reader may then briefly observe an empty file);
//! * `IfMatch` / `None` / delete hold an exclusive lock on `<root>/.aipass-lock`
//!   (`flock`, also across processes) around compare-and-rename.
//!
//! ETag = b64u(SHA-256(content)), identical to [`crate::MemoryStore`]. Internal names
//! starting with `.aipass-` are reserved; listings skip dot-files and symlinks. Files are
//! created `0600`, directories `0700` (Unix).

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    etag_for, validate_key, validate_prefix,
};

const TMP_DIR: &str = ".aipass-tmp";
const LOCK_FILE: &str = ".aipass-lock";
const RESERVED_PREFIX: &str = ".aipass-";

/// Local directory object store.
#[derive(Debug, Clone)]
pub struct LocalDirStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    root: PathBuf,
    max_object_size: Option<u64>,
    /// In-process serialization of writers (the file lock covers other processes).
    write_lock: tokio::sync::Mutex<()>,
}

impl LocalDirStore {
    /// Open (and create, `0700`) a store rooted at `root`. The root is canonicalized, so
    /// a symlinked root directory is resolved once at open time.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        Self::open_inner(root.into(), None)
    }

    /// Open with a per-object size limit in bytes.
    pub fn open_with_limit(root: impl Into<PathBuf>, limit: u64) -> Result<Self, StorageError> {
        Self::open_inner(root.into(), Some(limit))
    }

    fn open_inner(root: PathBuf, max_object_size: Option<u64>) -> Result<Self, StorageError> {
        create_dir_all_private(&root)?;
        let root = fs::canonicalize(&root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(StorageError::Io("storage root is not a directory".into()));
        }
        create_dir_all_private(&root.join(TMP_DIR))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                max_object_size,
                write_lock: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.inner.root
    }
}

fn check_reserved(key: &str) -> Result<(), StorageError> {
    if key.starts_with(RESERVED_PREFIX) {
        Err(StorageError::InvalidKey)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn create_dir_all_private(p: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(StorageError::from)
}

#[cfg(not(unix))]
fn create_dir_all_private(p: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(p).map_err(StorageError::from)
}

#[cfg(unix)]
fn new_file_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = OpenOptions::new();
    o.mode(0o600);
    o
}

#[cfg(not(unix))]
fn new_file_options() -> OpenOptions {
    OpenOptions::new()
}

impl Inner {
    /// Map a validated key to its path, refusing symlinked components.
    fn path_for(&self, key: &str) -> Result<PathBuf, StorageError> {
        validate_key(key)?;
        check_reserved(key)?;
        let mut p = self.root.clone();
        let mut missing = false;
        for seg in key.split('/') {
            p.push(seg);
            if missing {
                continue;
            }
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => return Err(StorageError::InvalidKey),
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => missing = true,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(p)
    }

    fn read(&self, key: &str) -> Result<Option<Object>, StorageError> {
        let p = self.path_for(key)?;
        match fs::read(&p) {
            Ok(bytes) => {
                let etag = etag_for(&bytes);
                Ok(Some(Object { bytes, etag }))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            // a directory at that path (key is a "prefix") is not an object
            Err(e) if p.is_dir() || e.kind() == ErrorKind::IsADirectory => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn lock_file(&self) -> Result<File, StorageError> {
        let f = new_file_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(LOCK_FILE))?;
        f.lock()?;
        Ok(f)
    }

    fn write_temp(&self, bytes: &[u8]) -> Result<PathBuf, StorageError> {
        let tmp_dir = self.root.join(TMP_DIR);
        create_dir_all_private(&tmp_dir)?;
        let name: String = aipass_crypto::rng::try_random_array::<16>()
            .map_err(|_| StorageError::Io("random number generator failure".into()))?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let tmp = tmp_dir.join(name);
        let mut f = new_file_options().write(true).create_new(true).open(&tmp)?;
        let res = f.write_all(bytes).and_then(|_| f.sync_all());
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(tmp)
    }

    fn ensure_parent(&self, dest: &Path) -> Result<(), StorageError> {
        if let Some(parent) = dest.parent() {
            create_dir_all_private(parent)?;
        }
        Ok(())
    }

    fn put(
        &self,
        key: &str,
        bytes: &[u8],
        cond: &PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        if let Some(limit) = self.max_object_size
            && bytes.len() as u64 > limit
        {
            return Err(StorageError::TooLarge { limit });
        }
        let dest = self.path_for(key)?;
        let _guard = self.lock_file()?;
        // re-check after acquiring the lock (a component may have been replaced)
        let dest2 = self.path_for(key)?;
        if dest2 != dest {
            return Err(StorageError::InvalidKey);
        }
        if dest.is_dir() {
            return Err(StorageError::InvalidKey);
        }
        let new_etag = etag_for(bytes);
        match cond {
            PutCondition::IfAbsent => {
                if dest.exists() {
                    return Ok(PutOutcome::PreconditionFailed);
                }
                self.ensure_parent(&dest)?;
                let tmp = self.write_temp(bytes)?;
                let res = match fs::hard_link(&tmp, &dest) {
                    Ok(()) => Ok(PutOutcome::Written {
                        etag: new_etag.clone(),
                    }),
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                        Ok(PutOutcome::PreconditionFailed)
                    }
                    Err(_) => {
                        // no hard links on this filesystem: O_EXCL claim, then atomic rename
                        match new_file_options().write(true).create_new(true).open(&dest) {
                            Ok(_) => match fs::rename(&tmp, &dest) {
                                Ok(()) => {
                                    sync_dir(dest.parent());
                                    return Ok(PutOutcome::Written { etag: new_etag });
                                }
                                Err(e) => Err(e.into()),
                            },
                            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                                Ok(PutOutcome::PreconditionFailed)
                            }
                            Err(e) => Err(e.into()),
                        }
                    }
                };
                let _ = fs::remove_file(&tmp);
                if matches!(res, Ok(PutOutcome::Written { .. })) {
                    sync_dir(dest.parent());
                }
                res
            }
            PutCondition::IfMatch(expected) => {
                let current = match fs::read(&dest) {
                    Ok(b) => b,
                    Err(e) if e.kind() == ErrorKind::NotFound => {
                        return Ok(PutOutcome::PreconditionFailed);
                    }
                    Err(e) => return Err(e.into()),
                };
                if etag_for(&current) != *expected {
                    return Ok(PutOutcome::PreconditionFailed);
                }
                let tmp = self.write_temp(bytes)?;
                if let Err(e) = fs::rename(&tmp, &dest) {
                    let _ = fs::remove_file(&tmp);
                    return Err(e.into());
                }
                sync_dir(dest.parent());
                Ok(PutOutcome::Written { etag: new_etag })
            }
            PutCondition::None => {
                self.ensure_parent(&dest)?;
                let tmp = self.write_temp(bytes)?;
                if let Err(e) = fs::rename(&tmp, &dest) {
                    let _ = fs::remove_file(&tmp);
                    return Err(e.into());
                }
                sync_dir(dest.parent());
                Ok(PutOutcome::Written { etag: new_etag })
            }
        }
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        let p = self.path_for(key)?;
        let _guard = self.lock_file()?;
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) if p.is_dir() => {
                let _ = e;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        // prune now-empty parent directories (best effort, never the root)
        let mut dir = p.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d == self.root || !d.starts_with(&self.root) {
                break;
            }
            if fs::remove_dir(&d).is_err() {
                break;
            }
            dir = d.parent().map(Path::to_path_buf);
        }
        sync_dir(p.parent());
        Ok(())
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_prefix(prefix)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        // walk only below the directory part of the prefix
        let (dir_part, _) = match prefix.rfind('/') {
            Some(i) => (&prefix[..i], &prefix[i + 1..]),
            None => ("", prefix),
        };
        let mut start = self.root.clone();
        if !dir_part.is_empty() {
            for seg in dir_part.split('/') {
                start.push(seg);
                match fs::symlink_metadata(&start) {
                    Ok(m) if m.is_dir() => {}
                    Ok(_) => return Ok(Vec::new()),
                    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let mut keys: Vec<String> = Vec::new();
        let mut stack: Vec<(PathBuf, String)> = vec![(start, dir_part.to_owned())];
        while let Some((dir, rel)) = stack.pop() {
            let rd = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for ent in rd {
                let ent = ent?;
                let name = match ent.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                if name.starts_with('.') {
                    continue; // reserved internals and dot-files
                }
                let key = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let ft = ent.file_type()?;
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    // descend only if keys below could match the prefix
                    let dir_key = format!("{key}/");
                    if dir_key.starts_with(prefix) || prefix.starts_with(&dir_key) {
                        stack.push((ent.path(), key));
                    }
                } else if ft.is_file()
                    && key.starts_with(prefix)
                    && start_after.is_none_or(|s| key.as_str() > s)
                    && validate_key(&key).is_ok()
                {
                    keys.push(key);
                }
            }
        }
        keys.sort();
        keys.truncate(limit);
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let p = self.root.join(&key);
            let bytes = match fs::read(&p) {
                Ok(b) => b,
                Err(e) if e.kind() == ErrorKind::NotFound => continue, // deleted meanwhile
                Err(e) => return Err(e.into()),
            };
            let modified_at = fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .map(DateTime::<Utc>::from);
            out.push(ObjectMeta {
                etag: etag_for(&bytes),
                size: bytes.len() as u64,
                key,
                modified_at,
            });
        }
        Ok(out)
    }
}

#[cfg(unix)]
fn sync_dir(dir: Option<&Path>) {
    if let Some(d) = dir
        && let Ok(f) = File::open(d)
    {
        let _ = f.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: Option<&Path>) {}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StorageError> + Send + 'static,
) -> Result<T, StorageError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| StorageError::Io("storage worker task failed".into()))?
}

#[async_trait]
impl ObjectStore for LocalDirStore {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        let inner = self.inner.clone();
        let key = key.to_owned();
        blocking(move || inner.read(&key)).await
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        let _g = self.inner.write_lock.lock().await;
        let inner = self.inner.clone();
        let key = key.to_owned();
        blocking(move || inner.put(&key, &bytes, &cond)).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let _g = self.inner.write_lock.lock().await;
        let inner = self.inner.clone();
        let key = key.to_owned();
        blocking(move || inner.delete(&key)).await
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        let inner = self.inner.clone();
        let prefix = prefix.to_owned();
        let start_after = start_after.map(str::to_owned);
        blocking(move || inner.list(&prefix, start_after.as_deref(), limit)).await
    }

    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "local".into(),
            endpoint: Some(self.inner.root.display().to_string()),
            detail: None,
        }
    }
}
