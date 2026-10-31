// SPDX-License-Identifier: Apache-2.0
//! `PrefixedStore` — exposes the objects of an inner store below a fixed key prefix as a
//! store of their own (keys are relative to the prefix). Used by the sync server for its
//! per-vault namespaces (`vaults/<vault_id>/…`) and usable for any "subdirectory" view.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    normalize_root_prefix, validate_key, validate_prefix,
};

/// A store namespaced below `prefix` of an inner store.
#[derive(Clone)]
pub struct PrefixedStore {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
}

impl core::fmt::Debug for PrefixedStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrefixedStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl PrefixedStore {
    /// Wrap `inner`, exposing the keys below `prefix` (normalized to end with `/`).
    pub fn new(inner: Arc<dyn ObjectStore>, prefix: &str) -> Result<Self, StorageError> {
        Ok(Self {
            inner,
            prefix: normalize_root_prefix(prefix)?,
        })
    }

    /// The normalized prefix (`""` or ends with `/`).
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn full(&self, key: &str) -> Result<String, StorageError> {
        validate_key(key)?;
        Ok(format!("{}{key}", self.prefix))
    }
}

#[async_trait]
impl ObjectStore for PrefixedStore {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        self.inner.get(&self.full(key)?).await
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        self.inner.put(&self.full(key)?, bytes, cond).await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.inner.delete(&self.full(key)?).await
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_prefix(prefix)?;
        let full_prefix = format!("{}{prefix}", self.prefix);
        let full_after = start_after.map(|s| format!("{}{s}", self.prefix));
        let page = self
            .inner
            .list(&full_prefix, full_after.as_deref(), limit)
            .await?;
        Ok(page
            .into_iter()
            .filter_map(|mut m| {
                let rel = m.key.strip_prefix(&self.prefix)?.to_owned();
                m.key = rel;
                Some(m)
            })
            .collect())
    }

    fn describe(&self) -> StorageDescription {
        let mut d = self.inner.describe();
        let extra = format!("prefix={}", self.prefix);
        d.detail = Some(match d.detail {
            Some(x) => format!("{x}, {extra}"),
            None => extra,
        });
        d
    }
}
