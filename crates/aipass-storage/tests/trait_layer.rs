// SPDX-License-Identifier: Apache-2.0
//! Tests of the ObjectStore trait layer: MemoryStore semantics and the capability test
//! against a correct store and deliberately broken stores.

use aipass_storage::*;
use async_trait::async_trait;

#[tokio::test]
async fn memory_store_semantics() {
    let s = MemoryStore::new();
    assert!(s.get("a/b.json").await.unwrap().is_none());

    let PutOutcome::Written { etag: e1 } = s
        .put("a/b.json", b"one".to_vec(), PutCondition::IfAbsent)
        .await
        .unwrap()
    else {
        panic!("create failed")
    };
    assert_eq!(e1, etag_for(b"one"));
    assert_eq!(
        s.put("a/b.json", b"two".to_vec(), PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert_eq!(s.get("a/b.json").await.unwrap().unwrap().bytes, b"one");

    let PutOutcome::Written { etag: e2 } = s
        .put(
            "a/b.json",
            b"two".to_vec(),
            PutCondition::IfMatch(e1.clone()),
        )
        .await
        .unwrap()
    else {
        panic!("update failed")
    };
    assert_ne!(e1, e2);
    assert_eq!(
        s.put("a/b.json", b"three".to_vec(), PutCondition::IfMatch(e1))
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert_eq!(
        s.put(
            "a/missing.json",
            b"x".to_vec(),
            PutCondition::IfMatch(e2.clone())
        )
        .await
        .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert!(matches!(
        s.put("a/b.json", b"four".to_vec(), PutCondition::None)
            .await
            .unwrap(),
        PutOutcome::Written { .. }
    ));

    // delete is idempotent
    s.delete("a/b.json").await.unwrap();
    s.delete("a/b.json").await.unwrap();
    assert!(s.get("a/b.json").await.unwrap().is_none());

    // invalid keys are rejected everywhere
    for bad in ["../etc/passwd", "/abs", "a//b", "a/../b", ""] {
        assert_eq!(
            s.get(bad).await.unwrap_err(),
            StorageError::InvalidKey,
            "{bad}"
        );
        assert_eq!(
            s.put(bad, vec![], PutCondition::None).await.unwrap_err(),
            StorageError::InvalidKey
        );
        assert_eq!(s.delete(bad).await.unwrap_err(), StorageError::InvalidKey);
    }

    let small = MemoryStore::with_max_object_size(4);
    assert_eq!(
        small
            .put("k", vec![0; 5], PutCondition::None)
            .await
            .unwrap_err(),
        StorageError::TooLarge { limit: 4 }
    );
}

#[tokio::test]
async fn memory_store_listing() {
    let s = MemoryStore::new();
    for k in [
        "m/000000000002.json",
        "m/000000000001.json",
        "m/000000000010.json",
        "n/x.json",
        "l/y.json",
        "m.json",
    ] {
        s.put(k, b"{}".to_vec(), PutCondition::None).await.unwrap();
    }
    let all = s.list("m/", None, 100).await.unwrap();
    let keys: Vec<&str> = all.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "m/000000000001.json",
            "m/000000000002.json",
            "m/000000000010.json"
        ]
    );
    assert!(all.iter().all(|m| m.size == 2 && m.modified_at.is_some()));
    let after = s.list("m/", Some("m/000000000001.json"), 1).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].key, "m/000000000002.json");
    // start_after before the prefix range still starts at the prefix
    assert_eq!(s.list("m/", Some("a"), 10).await.unwrap().len(), 3);
    assert_eq!(s.list("m/", Some("z"), 10).await.unwrap().len(), 0);
    assert_eq!(s.list("m/", None, 0).await.unwrap().len(), 0);
    assert_eq!(s.list("", None, 100).await.unwrap().len(), 6);

    // list_all follows pagination
    let big = MemoryStore::new();
    for i in 0..2_345u32 {
        big.put(&format!("e/{i:06}.json"), vec![1], PutCondition::None)
            .await
            .unwrap();
    }
    let listed = list_all(&big, "e/").await.unwrap();
    assert_eq!(listed.len(), 2_345);
    assert!(listed.windows(2).all(|w| w[0].key < w[1].key));
}

#[tokio::test]
async fn capability_test_memory_store_is_sync_capable() {
    let s = MemoryStore::new();
    let r = capability_test(&s, "_aipass_captest").await;
    assert!(
        r.read
            && r.write
            && r.list
            && r.conditional_create
            && r.conditional_update
            && r.delete
            && r.roundtrip,
        "{r:#?}"
    );
    assert_eq!(r.verdict, StorageVerdict::SyncCapable);
    assert!(
        s.is_empty().await,
        "scratch objects must be cleaned up: {:?}",
        s.keys().await
    );
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["verdict"], "sync_capable");
    for k in [
        "read",
        "write",
        "list",
        "conditional_create",
        "conditional_update",
        "delete",
        "roundtrip",
        "details",
    ] {
        assert!(json.get(k).is_some(), "{k}");
    }
}

/// A store that silently ignores every write precondition (like a naive WebDAV server).
struct IgnoresConditions(MemoryStore);

#[async_trait]
impl ObjectStore for IgnoresConditions {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        self.0.get(key).await
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        _cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        self.0.put(key, bytes, PutCondition::None).await
    }
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.0.delete(key).await
    }
    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        self.0.list(prefix, start_after, limit).await
    }
    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "broken-conditions".into(),
            endpoint: Some("https://dav.example/aipass".into()),
            detail: None,
        }
    }
}

#[tokio::test]
async fn capability_test_broken_conditions_is_backup_only() {
    let s = IgnoresConditions(MemoryStore::new());
    let r = capability_test(&s, "_aipass_captest/").await;
    assert!(r.read && r.write && r.list && r.roundtrip && r.delete);
    assert!(!r.conditional_create);
    assert!(!r.conditional_update);
    assert_eq!(r.verdict, StorageVerdict::BackupOnly);
    assert!(r.details.iter().any(|d| d.contains("backup_only")));
    assert!(r.details[0].contains("https://dav.example/aipass"));
}

/// Honours IfAbsent only sequentially: check-then-write without atomicity, so concurrent
/// create-only writers can all "win".
struct RacyCreate(MemoryStore);

#[async_trait]
impl ObjectStore for RacyCreate {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        self.0.get(key).await
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        if cond == PutCondition::IfAbsent {
            let exists = self.0.get(key).await?.is_some();
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if exists {
                return Ok(PutOutcome::PreconditionFailed);
            }
            return self.0.put(key, bytes, PutCondition::None).await;
        }
        self.0.put(key, bytes, cond).await
    }
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.0.delete(key).await
    }
    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        self.0.list(prefix, start_after, limit).await
    }
    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "racy".into(),
            endpoint: None,
            detail: None,
        }
    }
}

#[tokio::test]
async fn capability_test_detects_non_atomic_create() {
    let r = capability_test(&RacyCreate(MemoryStore::new()), "_cap").await;
    assert!(r.conditional_update, "{r:#?}");
    assert!(!r.conditional_create, "{r:#?}");
    assert_eq!(r.verdict, StorageVerdict::BackupOnly);
}

/// Ignores `start_after` (broken pagination).
struct NoPagination(MemoryStore);

#[async_trait]
impl ObjectStore for NoPagination {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        self.0.get(key).await
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        self.0.put(key, bytes, cond).await
    }
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.0.delete(key).await
    }
    async fn list(
        &self,
        prefix: &str,
        _start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        self.0.list(prefix, None, limit).await
    }
    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "nopage".into(),
            endpoint: None,
            detail: None,
        }
    }
}

#[tokio::test]
async fn capability_test_detects_broken_listing_and_list_all_guards() {
    let r = capability_test(&NoPagination(MemoryStore::new()), "_cap").await;
    assert!(!r.list);
    assert_eq!(r.verdict, StorageVerdict::BackupOnly);

    let s = NoPagination(MemoryStore::new());
    for i in 0..(LIST_PAGE + 5) {
        s.put(&format!("p/{i:06}"), vec![], PutCondition::None)
            .await
            .unwrap();
    }
    assert!(
        list_all(&s, "p/").await.is_err(),
        "list_all must not loop forever"
    );
}

/// Always fails (offline backend).
struct Offline;

#[async_trait]
impl ObjectStore for Offline {
    async fn get(&self, _: &str) -> Result<Option<Object>, StorageError> {
        Err(StorageError::Network("connection refused".into()))
    }
    async fn put(&self, _: &str, _: Vec<u8>, _: PutCondition) -> Result<PutOutcome, StorageError> {
        Err(StorageError::Network("connection refused".into()))
    }
    async fn delete(&self, _: &str) -> Result<(), StorageError> {
        Err(StorageError::Timeout)
    }
    async fn list(
        &self,
        _: &str,
        _: Option<&str>,
        _: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        Err(StorageError::Unauthorized)
    }
    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "offline".into(),
            endpoint: None,
            detail: None,
        }
    }
}

#[tokio::test]
async fn capability_test_offline_backend() {
    let r = capability_test(&Offline, "_cap").await;
    assert!(
        !r.write
            && !r.read
            && !r.list
            && !r.conditional_create
            && !r.conditional_update
            && !r.delete
            && !r.roundtrip
    );
    assert_eq!(r.verdict, StorageVerdict::BackupOnly);
    assert!(StorageError::Network("x".into()).is_retryable());
    assert!(!StorageError::Unauthorized.is_retryable());
    let api: aipass_types::ApiError = StorageError::Unauthorized.into();
    assert_eq!(api.code, aipass_types::ErrorCode::Forbidden);
}
