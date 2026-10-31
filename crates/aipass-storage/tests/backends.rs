// SPDX-License-Identifier: Apache-2.0
//! Backend tests: LocalDirStore, S3Store (against a SigV4-verifying mock S3) and
//! WebDavStore (against a mock WebDAV server), including capability-test verdicts.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use aipass_crypto::SecretString;
use aipass_storage::*;
use common::*;

// ======================================================================================
// LocalDirStore
// ======================================================================================

#[tokio::test]
async fn local_semantics_and_capability() {
    let dir = tempfile::tempdir().unwrap();
    let s = LocalDirStore::open(dir.path().join("vault")).unwrap();
    assert!(s.get("entries/a/1.json").await.unwrap().is_none());

    let PutOutcome::Written { etag: e1 } = s
        .put("entries/a/1.json", b"one".to_vec(), PutCondition::IfAbsent)
        .await
        .unwrap()
    else {
        panic!("create failed")
    };
    assert_eq!(e1, etag_for(b"one"));
    assert_eq!(
        s.put("entries/a/1.json", b"two".to_vec(), PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    let o = s.get("entries/a/1.json").await.unwrap().unwrap();
    assert_eq!(o.bytes, b"one");
    assert_eq!(o.etag, e1);

    // If-Match: current succeeds, stale and absent fail
    s.put("HEAD", b"1".to_vec(), PutCondition::None)
        .await
        .unwrap();
    let h = s.get("HEAD").await.unwrap().unwrap();
    let PutOutcome::Written { etag: h2 } = s
        .put("HEAD", b"2".to_vec(), PutCondition::IfMatch(h.etag.clone()))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_ne!(h2, h.etag);
    assert_eq!(
        s.put("HEAD", b"3".to_vec(), PutCondition::IfMatch(h.etag.clone()))
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert_eq!(
        s.put("nope", b"3".to_vec(), PutCondition::IfMatch(h2.clone()))
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );

    // listing: lexicographic, prefix, start_after, limit
    for k in [
        "manifests/000000000002.json",
        "manifests/000000000001.json",
        "members/dev/1.json",
    ] {
        s.put(k, b"{}".to_vec(), PutCondition::IfAbsent)
            .await
            .unwrap();
    }
    let all = list_all(&s, "").await.unwrap();
    let keys: Vec<&str> = all.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "HEAD",
            "entries/a/1.json",
            "manifests/000000000001.json",
            "manifests/000000000002.json",
            "members/dev/1.json"
        ]
    );
    let m = s
        .list("manifests/", Some("manifests/000000000001.json"), 10)
        .await
        .unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].key, "manifests/000000000002.json");
    assert_eq!(m[0].size, 2);
    assert_eq!(s.list("m", None, 1).await.unwrap().len(), 1);
    assert_eq!(s.list("entries/a/", None, 10).await.unwrap().len(), 1);
    assert!(s.list("zzz/", None, 10).await.unwrap().is_empty());

    // delete is idempotent and prunes empty directories
    s.delete("entries/a/1.json").await.unwrap();
    s.delete("entries/a/1.json").await.unwrap();
    assert!(!dir.path().join("vault/entries/a").exists());

    // persistence across reopen
    let s2 = LocalDirStore::open(dir.path().join("vault")).unwrap();
    assert_eq!(s2.get("HEAD").await.unwrap().unwrap().bytes, b"2");

    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(
        rep.verdict,
        StorageVerdict::SyncCapable,
        "{:?}",
        rep.details
    );
    assert!(rep.delete);
    // scratch cleaned up, internals hidden
    let after = list_all(&s, "").await.unwrap();
    assert!(after.iter().all(|m| !m.key.starts_with("_aipass_captest")));
    assert!(after.iter().all(|m| !m.key.starts_with('.')));
    assert_eq!(s.describe().kind, "local");
}

#[tokio::test]
async fn local_rejects_traversal_and_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
    let s = LocalDirStore::open(dir.path()).unwrap();
    for bad in [
        "../x",
        "a/../../x",
        "/etc/passwd",
        "a//b",
        "",
        ".aipass-lock",
        ".aipass-tmp/x",
        "a\\b",
    ] {
        assert_eq!(
            s.get(bad).await.unwrap_err(),
            StorageError::InvalidKey,
            "{bad}"
        );
        assert_eq!(
            s.put(bad, b"x".to_vec(), PutCondition::None)
                .await
                .unwrap_err(),
            StorageError::InvalidKey,
            "{bad}"
        );
    }
    assert!(s.list("../", None, 10).await.is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        assert_eq!(
            s.get("link/secret.txt").await.unwrap_err(),
            StorageError::InvalidKey
        );
        assert_eq!(
            s.put("link/new.txt", b"x".to_vec(), PutCondition::None)
                .await
                .unwrap_err(),
            StorageError::InvalidKey
        );
        assert!(!outside.path().join("new.txt").exists());
        // listings skip symlinks
        assert!(
            list_all(&s, "")
                .await
                .unwrap()
                .iter()
                .all(|m| !m.key.starts_with("link"))
        );
        // files are private
        use std::os::unix::fs::PermissionsExt;
        s.put("p/q.json", b"{}".to_vec(), PutCondition::None)
            .await
            .unwrap();
        let mode = std::fs::metadata(dir.path().join("p/q.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "object file must not be group/world accessible"
        );
    }
}

#[tokio::test]
async fn local_concurrent_writers_two_instances() {
    // two store instances on the same directory (as two processes would be): the
    // lock file and link(2) still give exactly one winner
    let dir = tempfile::tempdir().unwrap();
    let a = Arc::new(LocalDirStore::open(dir.path()).unwrap());
    let b = Arc::new(LocalDirStore::open(dir.path()).unwrap());
    let mut tasks = Vec::new();
    for i in 0..16 {
        let s = if i % 2 == 0 { a.clone() } else { b.clone() };
        tasks.push(tokio::spawn(async move {
            s.put(
                "manifests/000000000007.json",
                format!("writer-{i}").into_bytes(),
                PutCondition::IfAbsent,
            )
            .await
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if matches!(t.await.unwrap().unwrap(), PutOutcome::Written { .. }) {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);

    // compare-and-swap race on HEAD: each writer reads then swaps once
    a.put("HEAD", b"0".to_vec(), PutCondition::None)
        .await
        .unwrap();
    let etag0 = a.get("HEAD").await.unwrap().unwrap().etag;
    let mut tasks = Vec::new();
    for i in 0..16 {
        let s = if i % 2 == 0 { a.clone() } else { b.clone() };
        let e = etag0.clone();
        tasks.push(tokio::spawn(async move {
            s.put(
                "HEAD",
                format!("w{i}").into_bytes(),
                PutCondition::IfMatch(e),
            )
            .await
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if matches!(t.await.unwrap().unwrap(), PutOutcome::Written { .. }) {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

#[tokio::test]
async fn local_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let s = LocalDirStore::open_with_limit(dir.path(), 4).unwrap();
    assert_eq!(
        s.put("a", b"12345".to_vec(), PutCondition::None)
            .await
            .unwrap_err(),
        StorageError::TooLarge { limit: 4 }
    );
}

// ======================================================================================
// S3Store against the SigV4-verifying mock
// ======================================================================================

fn s3_store(m: &MockS3, addr: std::net::SocketAddr, host: Option<&str>) -> S3Store {
    let endpoint = match host {
        Some(h) => url::Url::parse(&format!("http://{h}:{}", addr.port())).unwrap(),
        None => url::Url::parse(&format!("http://{addr}")).unwrap(),
    };
    let mut cfg =
        S3Config::new(endpoint, m.region.clone(), m.bucket.clone()).with_prefix("aipass/v1");
    cfg.path_style = !m.virtual_host;
    cfg.allow_http = host.is_some();
    let mut creds = S3Credentials::new(m.access_key.clone(), SecretString::from(m.secret.as_str()));
    if let Some(t) = &m.session_token {
        creds = creds.with_session_token(SecretString::from(t.as_str()));
    }
    let mut cb = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    if let Some(h) = host {
        cb = cb
            .resolve(h, addr)
            .resolve(&format!("{}.{h}", m.bucket), addr);
    }
    S3Store::with_client(cfg, Arc::new(creds), cb.build().unwrap()).unwrap()
}

#[tokio::test]
async fn s3_path_style_full_semantics() {
    let m = MockS3::new(S3Mode::Strict);
    let addr = serve(s3_router(m.clone())).await;
    let s = s3_store(&m, addr, None);

    assert!(s.get("vault.json").await.unwrap().is_none());
    let PutOutcome::Written { etag } = s
        .put("vault.json", b"{\"v\":1}".to_vec(), PutCondition::IfAbsent)
        .await
        .unwrap()
    else {
        panic!()
    };
    // stored under the prefix
    assert!(m.objects.lock().await.contains_key("aipass/v1/vault.json"));
    assert_eq!(
        s.put("vault.json", b"x".to_vec(), PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    let o = s.get("vault.json").await.unwrap().unwrap();
    assert_eq!(o.etag, etag);
    assert_eq!(
        s.put(
            "vault.json",
            b"y".to_vec(),
            PutCondition::IfMatch("deadbeef".into())
        )
        .await
        .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert_eq!(
        s.put(
            "missing.json",
            b"y".to_vec(),
            PutCondition::IfMatch(etag.clone())
        )
        .await
        .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert!(matches!(
        s.put("vault.json", b"z".to_vec(), PutCondition::IfMatch(etag))
            .await
            .unwrap(),
        PutOutcome::Written { .. }
    ));

    // pagination across continuation tokens (mock caps pages at 1000; ask for 3 per call
    // through the trait's limit, and also run list_all over > page)
    for i in 0..25 {
        s.put(
            &format!("entries/e{i:03}/1.json"),
            vec![i as u8],
            PutCondition::None,
        )
        .await
        .unwrap();
    }
    let page = s.list("entries/", None, 3).await.unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(page[0].key, "entries/e000/1.json");
    let next = s.list("entries/", Some(&page[2].key), 100).await.unwrap();
    assert_eq!(next.len(), 22);
    assert_eq!(next[0].key, "entries/e003/1.json");
    assert!(
        next.iter()
            .all(|x| x.size == 1 && !x.etag.is_empty() && x.modified_at.is_some())
    );

    s.delete("entries/e000/1.json").await.unwrap();
    s.delete("entries/e000/1.json").await.unwrap();
    assert!(s.get("entries/e000/1.json").await.unwrap().is_none());

    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(
        rep.verdict,
        StorageVerdict::SyncCapable,
        "{:?}",
        rep.details
    );
    assert_eq!(m.sig_failures.load(Ordering::SeqCst), 0);
    let d = s.describe();
    assert_eq!(d.kind, "s3");
    assert!(!format!("{d:?}").contains(&m.secret));
    assert!(!format!("{s:?}").contains(&m.secret));
}

#[tokio::test]
async fn s3_paginates_small_pages() {
    let m = Arc::new(MockS3 {
        page_cap: 2,
        ..Arc::try_unwrap(MockS3::new(S3Mode::Strict)).ok().unwrap()
    });
    let addr = serve(s3_router(m.clone())).await;
    let s = s3_store(&m, addr, None);
    for i in 0..7 {
        s.put(&format!("k{i}"), vec![1], PutCondition::None)
            .await
            .unwrap();
    }
    let all = s.list("", None, 1000).await.unwrap();
    assert_eq!(all.len(), 7);
    let before = m.requests.load(Ordering::SeqCst);
    let some = s.list("", None, 5).await.unwrap();
    assert_eq!(some.len(), 5);
    assert_eq!(
        m.requests.load(Ordering::SeqCst) - before,
        3,
        "5 keys at 2 per page = 3 pages"
    );
}

#[tokio::test]
async fn s3_virtual_host_with_session_token() {
    let m = Arc::new(MockS3 {
        virtual_host: true,
        session_token: Some("FwoGZXIvYXdzEXAMPLETOKEN".into()),
        ..Arc::try_unwrap(MockS3::new(S3Mode::Strict)).ok().unwrap()
    });
    let addr = serve(s3_router(m.clone())).await;
    let s = s3_store(&m, addr, Some("s3.mock.test"));
    s.put("HEAD", b"1".to_vec(), PutCondition::None)
        .await
        .unwrap();
    assert_eq!(s.get("HEAD").await.unwrap().unwrap().bytes, b"1");
    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(
        rep.verdict,
        StorageVerdict::SyncCapable,
        "{:?}",
        rep.details
    );
    assert_eq!(m.sig_failures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn s3_409_conflict_maps_to_precondition_failed() {
    let m = MockS3::new(S3Mode::Conflict409);
    let addr = serve(s3_router(m.clone())).await;
    let s = s3_store(&m, addr, None);
    s.put("a", b"1".to_vec(), PutCondition::IfAbsent)
        .await
        .unwrap();
    assert_eq!(
        s.put("a", b"2".to_vec(), PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(
        rep.verdict,
        StorageVerdict::SyncCapable,
        "{:?}",
        rep.details
    );
}

#[tokio::test]
async fn s3_ignoring_conditions_is_backup_only() {
    let m = MockS3::new(S3Mode::IgnoreConditions);
    let addr = serve(s3_router(m.clone())).await;
    let s = s3_store(&m, addr, None);
    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(rep.verdict, StorageVerdict::BackupOnly);
    assert!(!rep.conditional_create);
    assert!(rep.read && rep.write && rep.list);
}

#[tokio::test]
async fn s3_wrong_secret_is_unauthorized() {
    let m = MockS3::new(S3Mode::Strict);
    let addr = serve(s3_router(m.clone())).await;
    let cfg = S3Config::new(
        url::Url::parse(&format!("http://{addr}")).unwrap(),
        m.region.clone(),
        m.bucket.clone(),
    );
    let creds = S3Credentials::new(m.access_key.clone(), SecretString::from("wrong-secret"));
    let s = S3Store::with_client(cfg, Arc::new(creds), test_client()).unwrap();
    let err = s.get("x").await.unwrap_err();
    assert_eq!(err, StorageError::Unauthorized);
    assert!(!err.to_string().contains("wrong-secret"));
    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(rep.verdict, StorageVerdict::BackupOnly);
    assert!(rep.details.iter().all(|d| !d.contains("wrong-secret")));
}

#[tokio::test]
async fn s3_config_validation() {
    let creds: Arc<dyn aipass_storage::s3::S3CredentialProvider> =
        Arc::new(S3Credentials::new("AK", SecretString::from("SK")));
    let ep = |s: &str| url::Url::parse(s).unwrap();
    assert!(
        S3Store::new(
            S3Config::new(ep("http://s3.example.com"), "us-east-1", "b-1"),
            creds.clone()
        )
        .is_err()
    );
    assert!(
        S3Store::new(
            S3Config::new(ep("https://s3.example.com/path"), "us-east-1", "b-1"),
            creds.clone()
        )
        .is_err()
    );
    assert!(
        S3Store::new(
            S3Config::new(ep("https://s3.example.com"), "us-east-1", "x"),
            creds.clone()
        )
        .is_err()
    );
    assert!(
        S3Store::new(
            S3Config::new(ep("https://s3.example.com"), "us east", "bucket"),
            creds.clone()
        )
        .is_err()
    );
    assert!(
        S3Store::new(
            S3Config::new(ep("https://s3.example.com"), "us-east-1", "bucket").with_prefix("../x"),
            creds.clone()
        )
        .is_err()
    );
    assert!(
        S3Store::new(
            S3Config::new(ep("https://s3.example.com"), "us-east-1", "bucket").with_prefix("/a/b/"),
            creds
        )
        .is_ok()
    );
    let c = S3Credentials::new("AKIAEXAMPLE", SecretString::from("topsecret"))
        .with_session_token(SecretString::from("tok"));
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("topsecret") && !dbg.contains("tok\"") && !dbg.contains("AKIAEXAMPLE"));
}

// ======================================================================================
// WebDavStore (experimental) against the mock
// ======================================================================================

#[tokio::test]
async fn webdav_strict_is_sync_capable() {
    let d = MockDav::new(true);
    let addr = serve(dav_router(d.clone())).await;
    let s = WebDavStore::with_client(WebDavConfig::new(dav_base(addr)), test_client()).unwrap();

    s.put("entries/ent1/1.json", b"a".to_vec(), PutCondition::IfAbsent)
        .await
        .unwrap();
    assert!(
        d.mkcols.load(Ordering::SeqCst) >= 2,
        "parent collections created with MKCOL"
    );
    assert_eq!(
        s.put("entries/ent1/1.json", b"b".to_vec(), PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );
    s.put(
        "entries/ent2/1.json",
        b"bb".to_vec(),
        PutCondition::IfAbsent,
    )
    .await
    .unwrap();
    s.put(
        "manifests/000000000001.json",
        b"m".to_vec(),
        PutCondition::IfAbsent,
    )
    .await
    .unwrap();
    let o = s.get("entries/ent1/1.json").await.unwrap().unwrap();
    assert_eq!(o.bytes, b"a");
    let l = s.list("entries/", None, 10).await.unwrap();
    let keys: Vec<&str> = l.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(keys, ["entries/ent1/1.json", "entries/ent2/1.json"]);
    assert_eq!(l[1].size, 2);
    assert_eq!(l[0].etag, o.etag);
    assert_eq!(s.list("", None, 10).await.unwrap().len(), 3);
    assert_eq!(
        s.list("entries/ent1/", Some("entries/ent1/1.json"), 10)
            .await
            .unwrap()
            .len(),
        0
    );
    s.delete("entries/ent1/1.json").await.unwrap();
    s.delete("entries/ent1/1.json").await.unwrap();

    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(
        rep.verdict,
        StorageVerdict::SyncCapable,
        "{:?}",
        rep.details
    );
    assert_eq!(s.describe().kind, "webdav");
}

#[tokio::test]
async fn webdav_without_put_etag_uses_propfind() {
    let d = Arc::new(MockDav {
        etag_on_put: false,
        ..Arc::try_unwrap(MockDav::new(true)).ok().unwrap()
    });
    let addr = serve(dav_router(d.clone())).await;
    let s = WebDavStore::with_client(WebDavConfig::new(dav_base(addr)), test_client()).unwrap();
    let PutOutcome::Written { etag } = s
        .put("a/b.json", b"x".to_vec(), PutCondition::None)
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(etag, s.get("a/b.json").await.unwrap().unwrap().etag);
}

#[tokio::test]
async fn webdav_lax_is_backup_only() {
    let d = MockDav::new(false);
    let addr = serve(dav_router(d.clone())).await;
    let s = WebDavStore::with_client(WebDavConfig::new(dav_base(addr)), test_client()).unwrap();
    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(rep.verdict, StorageVerdict::BackupOnly);
    assert!(!rep.conditional_create);
}

#[tokio::test]
async fn webdav_basic_auth() {
    let d = Arc::new(MockDav {
        required_auth: Some("Basic bWU6YXBwLXBhc3N3b3Jk".into()), // me:app-password
        ..Arc::try_unwrap(MockDav::new(true)).ok().unwrap()
    });
    let addr = serve(dav_router(d.clone())).await;
    let ok = WebDavStore::with_client(
        WebDavConfig::new(dav_base(addr)).with_basic_auth("me", SecretString::from("app-password")),
        test_client(),
    )
    .unwrap();
    ok.put("x.json", b"1".to_vec(), PutCondition::None)
        .await
        .unwrap();
    let bad = WebDavStore::with_client(
        WebDavConfig::new(dav_base(addr)).with_basic_auth("me", SecretString::from("nope")),
        test_client(),
    )
    .unwrap();
    assert_eq!(
        bad.get("x.json").await.unwrap_err(),
        StorageError::Unauthorized
    );
    // credentials over plain http to a non-loopback host are refused
    let mut cfg = WebDavConfig::new(url::Url::parse("http://dav.example.com/x/").unwrap())
        .with_basic_auth("me", SecretString::from("pw"));
    assert!(WebDavStore::new(cfg.clone()).is_err());
    cfg.base_url = url::Url::parse("https://dav.example.com/x/").unwrap();
    assert!(WebDavStore::new(cfg).is_ok());
}

// ======================================================================================
// PrefixedStore + profile factory
// ======================================================================================

#[tokio::test]
async fn prefixed_store_namespaces() {
    let inner: Arc<dyn ObjectStore> = Arc::new(MemoryStore::new());
    let a = PrefixedStore::new(inner.clone(), "vaults/a").unwrap();
    let b = PrefixedStore::new(inner.clone(), "vaults/b/").unwrap();
    a.put("HEAD", b"a".to_vec(), PutCondition::None)
        .await
        .unwrap();
    b.put("HEAD", b"b".to_vec(), PutCondition::None)
        .await
        .unwrap();
    assert_eq!(a.get("HEAD").await.unwrap().unwrap().bytes, b"a");
    assert_eq!(a.list("", None, 10).await.unwrap()[0].key, "HEAD");
    assert_eq!(inner.list("vaults/", None, 10).await.unwrap().len(), 2);
    assert!(PrefixedStore::new(inner.clone(), "../x").is_err());
    let rep = capability_test(&a, "_aipass_captest").await;
    assert_eq!(rep.verdict, StorageVerdict::SyncCapable);
    assert_eq!(b.list("", None, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn profile_factory() {
    use aipass_storage::profile::{ProfileSecrets, open_store};
    let dir = tempfile::tempdir().unwrap();
    let mut p = StorageProfile::new(StorageKind::Local);
    p.path = Some(dir.path().display().to_string());
    let s = open_store(&p, ProfileSecrets::default()).unwrap();
    assert_eq!(s.describe().kind, "local");

    let m = MockS3::new(S3Mode::Strict);
    let addr = serve(s3_router(m.clone())).await;
    let mut p = StorageProfile::new(StorageKind::S3);
    p.endpoint = Some(format!("http://{addr}"));
    p.region = Some(m.region.clone());
    p.bucket = Some(m.bucket.clone());
    p.username = Some(m.access_key.clone());
    assert!(
        open_store(&p, ProfileSecrets::default()).is_err(),
        "secret required"
    );
    let s = open_store(
        &p,
        ProfileSecrets {
            secret: Some(SecretString::from(m.secret.as_str())),
            ..Default::default()
        },
    )
    .unwrap();
    s.put("HEAD", b"1".to_vec(), PutCondition::None)
        .await
        .unwrap();
    assert_eq!(s.get("HEAD").await.unwrap().unwrap().bytes, b"1");
}
