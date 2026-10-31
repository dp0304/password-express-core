// SPDX-License-Identifier: Apache-2.0
//! In-memory [`ObjectStore`] with exact conditional-write semantics (tests, ephemeral use).

use std::collections::BTreeMap;
use std::ops::Bound;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;

use crate::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    validate_key,
};

#[derive(Debug, Clone)]
struct Stored {
    bytes: Vec<u8>,
    etag: String,
    modified_at: chrono::DateTime<Utc>,
}

/// An in-memory object store. Conditional writes are atomic (a single write lock covers
/// check + write). ETag = b64u(SHA-256(bytes)), like `LocalDirStore`.
#[derive(Debug, Default)]
pub struct MemoryStore {
    objects: RwLock<BTreeMap<String, Stored>>,
    max_object_size: Option<u64>,
}

impl MemoryStore {
    /// Empty store without a size limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty store rejecting objects larger than `limit` bytes.
    pub fn with_max_object_size(limit: u64) -> Self {
        Self {
            objects: RwLock::new(BTreeMap::new()),
            max_object_size: Some(limit),
        }
    }

    /// Number of stored objects.
    pub async fn len(&self) -> usize {
        self.objects.read().await.len()
    }

    /// True when empty.
    pub async fn is_empty(&self) -> bool {
        self.objects.read().await.is_empty()
    }

    /// Snapshot of all keys (tests / debugging).
    pub async fn keys(&self) -> Vec<String> {
        self.objects.read().await.keys().cloned().collect()
    }

    /// Replace an object's bytes *bypassing* all conditions — for tests that simulate a
    /// malicious or rolled-back storage provider.
    pub async fn tamper(&self, key: &str, bytes: Vec<u8>) {
        let etag = crate::etag_for(&bytes);
        self.objects.write().await.insert(
            key.to_owned(),
            Stored {
                bytes,
                etag,
                modified_at: Utc::now(),
            },
        );
    }
}

#[async_trait]
impl ObjectStore for MemoryStore {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        validate_key(key)?;
        Ok(self.objects.read().await.get(key).map(|s| Object {
            bytes: s.bytes.clone(),
            etag: s.etag.clone(),
        }))
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        validate_key(key)?;
        if let Some(limit) = self.max_object_size
            && bytes.len() as u64 > limit
        {
            return Err(StorageError::TooLarge { limit });
        }
        let mut map = self.objects.write().await;
        let current = map.get(key);
        let allowed = match &cond {
            PutCondition::None => true,
            PutCondition::IfAbsent => current.is_none(),
            PutCondition::IfMatch(etag) => current.is_some_and(|c| c.etag == *etag),
        };
        if !allowed {
            return Ok(PutOutcome::PreconditionFailed);
        }
        let etag = crate::etag_for(&bytes);
        map.insert(
            key.to_owned(),
            Stored {
                bytes,
                etag: etag.clone(),
                modified_at: Utc::now(),
            },
        );
        Ok(PutOutcome::Written { etag })
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        validate_key(key)?;
        self.objects.write().await.remove(key);
        Ok(())
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        let map = self.objects.read().await;
        let lower = match start_after {
            Some(s) => Bound::Excluded(s.to_owned()),
            None => Bound::Included(prefix.to_owned()),
        };
        // Keys sharing `prefix` are contiguous in lexicographic order and all ≥ `prefix`.
        Ok(map
            .range((lower, Bound::Unbounded))
            .skip_while(|(k, _)| k.as_str() < prefix)
            .take_while(|(k, _)| k.starts_with(prefix))
            .take(limit)
            .map(|(k, s)| ObjectMeta {
                key: k.clone(),
                etag: s.etag.clone(),
                size: s.bytes.len() as u64,
                modified_at: Some(s.modified_at),
            })
            .collect())
    }

    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "memory".into(),
            endpoint: None,
            detail: None,
        }
    }
}
