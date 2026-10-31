// SPDX-License-Identifier: Apache-2.0
//! Local object cache: a directory-backed [`ObjectStore`] holding **verified** ciphertext
//! objects (manifests, member records, entry versions, keyrings) so a device can unlock and
//! read its vault offline (design doc §10.6).
//!
//! Keys are validated with `aipass_types::vault::keys::is_valid` (no traversal). Writes are
//! atomic (temp file + rename; create-only via hard link). ETag = b64u(SHA-256(bytes)).
//! This store is meant for a single process; concurrent conditional updates are serialized
//! with an in-process lock.

use std::path::{Path, PathBuf};

use aipass_storage::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    etag_for, validate_key,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

/// Directory-backed object store used as the local cache.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
    lock: Mutex<()>,
}

impl FileStore {
    /// Store rooted at `root` (created on first write).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            lock: Mutex::new(()),
        }
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> Result<PathBuf, StorageError> {
        validate_key(key)?;
        Ok(key.split('/').fold(self.root.clone(), |p, seg| p.join(seg)))
    }

    fn write_tmp(&self, path: &Path, bytes: &[u8]) -> Result<PathBuf, StorageError> {
        let dir = path.parent().ok_or(StorageError::InvalidKey)?;
        aipass_vault::fsutil::create_private_dir(dir)
            .map_err(|_| StorageError::Io("create dir".into()))?;
        let rnd: [u8; 8] = aipass_crypto::rng::random_array();
        let tmp = dir.join(format!(
            ".tmp-{}",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(tmp)
    }

    fn list_sync(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = Vec::new();
        if !self.root.exists() {
            return Ok(out);
        }
        let mut stack = vec![(self.root.clone(), String::new())];
        while let Some((dir, rel)) = stack.pop() {
            let rd = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for ent in rd {
                let ent = ent?;
                let name = ent.file_name().to_string_lossy().to_string();
                if name.starts_with(".tmp-") || name.starts_with('.') {
                    continue;
                }
                let key = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let ft = ent.file_type()?;
                if ft.is_dir() {
                    // prune directories that cannot contain the prefix
                    let k = format!("{key}/");
                    if k.starts_with(prefix) || prefix.starts_with(&k) {
                        stack.push((ent.path(), key));
                    }
                } else if ft.is_file()
                    && key.starts_with(prefix)
                    && aipass_types::vault::keys::is_valid(&key)
                {
                    let bytes = std::fs::read(ent.path())?;
                    let modified = ent
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .map(chrono::DateTime::<chrono::Utc>::from);
                    out.push(ObjectMeta {
                        key,
                        etag: etag_for(&bytes),
                        size: bytes.len() as u64,
                        modified_at: modified,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }
}

#[async_trait]
impl ObjectStore for FileStore {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        let p = self.path(key)?;
        match tokio::fs::read(&p).await {
            Ok(bytes) => {
                let etag = etag_for(&bytes);
                Ok(Some(Object { bytes, etag }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        let p = self.path(key)?;
        let _g = self.lock.lock().await;
        let etag = etag_for(&bytes);
        let tmp = self.write_tmp(&p, &bytes)?;
        let result = match cond {
            PutCondition::IfAbsent => match std::fs::hard_link(&tmp, &p) {
                Ok(()) => PutOutcome::Written { etag },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    PutOutcome::PreconditionFailed
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e.into());
                }
            },
            PutCondition::IfMatch(expected) => match std::fs::read(&p) {
                Ok(cur) if etag_for(&cur) == expected => {
                    std::fs::rename(&tmp, &p)?;
                    return Ok(PutOutcome::Written { etag });
                }
                Ok(_) => PutOutcome::PreconditionFailed,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    PutOutcome::PreconditionFailed
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e.into());
                }
            },
            PutCondition::None => {
                std::fs::rename(&tmp, &p)?;
                return Ok(PutOutcome::Written { etag });
            }
        };
        let _ = std::fs::remove_file(&tmp);
        Ok(result)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let p = self.path(key)?;
        match tokio::fs::remove_file(&p).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        let all = self.list_sync(prefix)?;
        Ok(all
            .into_iter()
            .filter(|m| start_after.is_none_or(|s| m.key.as_str() > s))
            .take(limit)
            .collect())
    }

    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "local-cache".into(),
            endpoint: None,
            detail: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn file_store_semantics_pass_capability_test() {
        let d = tempfile::tempdir().unwrap();
        let s = FileStore::new(d.path().join("objects"));
        assert!(matches!(
            s.put("a/b.json", b"1".to_vec(), PutCondition::IfAbsent)
                .await
                .unwrap(),
            PutOutcome::Written { .. }
        ));
        assert_eq!(
            s.put("a/b.json", b"2".to_vec(), PutCondition::IfAbsent)
                .await
                .unwrap(),
            PutOutcome::PreconditionFailed
        );
        assert_eq!(s.get("a/b.json").await.unwrap().unwrap().bytes, b"1");
        assert!(s.get("../x").await.is_err());
        let r = aipass_storage::capability_test(&s, "_captest").await;
        assert_eq!(
            r.verdict,
            aipass_storage::StorageVerdict::SyncCapable,
            "{:?}",
            r.details
        );
    }
}
