// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests: `HttpSyncStore` (aipass-storage) ↔ `sync_router` in-process.

mod common;

use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_storage::{
    HttpSyncStore, ObjectStore, PutCondition, PutOutcome, StorageError, StorageVerdict,
    capability_test, list_all,
};
use aipass_sync_server::sync::StaticQuota;
use aipass_types::ids::{EntryId, VaultId};
use aipass_types::vault::{MemberRole, MemberStatus, keys};
use common::*;

#[tokio::test]
async fn create_vault_then_sync_capable() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let s = srv.store_for(&vault, &owner);

    let info = s.vault_info().await.unwrap();
    assert_eq!(info.vault_id, vault);
    assert_eq!(info.object_count, 2, "vault.json + genesis member record");
    assert!(info.quota_bytes.is_none());

    // the genesis objects are stored byte-for-byte as sent
    let g = s.get(&keys::member(&owner.id, 1)).await.unwrap().unwrap();
    let rec: aipass_types::vault::MemberRecord = serde_json::from_slice(&g.bytes).unwrap();
    assert_eq!(member_bytes(&rec), g.bytes);

    // entries + manifests
    let e = EntryId::generate();
    let out = s
        .put(
            &keys::entry(&e, 1),
            entry(&vault, &e, 1, &owner),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap();
    assert!(matches!(out, PutOutcome::Written { .. }));
    let (seq, m1) = srv.next_manifest(&vault, &owner, &[], "a").await;
    assert_eq!(seq, 1);
    assert!(matches!(
        s.put(&keys::manifest(1), m1, PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::Written { .. }
    ));
    s.put(keys::HEAD, b"1".to_vec(), PutCondition::None)
        .await
        .unwrap();
    let head = s.get(keys::HEAD).await.unwrap().unwrap();
    assert!(matches!(
        s.put(
            keys::HEAD,
            b"2".to_vec(),
            PutCondition::IfMatch(head.etag.clone())
        )
        .await
        .unwrap(),
        PutOutcome::Written { .. }
    ));
    assert_eq!(
        s.put(keys::HEAD, b"3".to_vec(), PutCondition::IfMatch(head.etag))
            .await
            .unwrap(),
        PutOutcome::PreconditionFailed
    );

    // listing with pagination through the client
    for i in 0..7u64 {
        let e = EntryId::generate();
        s.put(
            &keys::entry(&e, i + 1),
            entry(&vault, &e, i + 1, &owner),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap();
    }
    let all = list_all(&s, "entries/").await.unwrap();
    assert_eq!(all.len(), 8);
    let page = s.list("entries/", None, 3).await.unwrap();
    assert_eq!(page.len(), 3);
    let rest = s.list("entries/", Some(&page[2].key), 100).await.unwrap();
    assert_eq!(rest.len(), 5);
    let info = s.vault_info().await.unwrap();
    assert_eq!(info.object_count, 2 + 8 + 1 + 1);

    let rep = capability_test(&s, "_aipass_captest").await;
    assert_eq!(
        rep.verdict,
        StorageVerdict::SyncCapable,
        "{:?}",
        rep.details
    );
    assert!(rep.delete, "owner may delete scratch objects");
    assert!(list_all(&s, "_aipass_captest").await.unwrap().is_empty());
    // the blob backend namespaces the vault
    let raw = list_all(srv.blob_store().as_ref(), "").await.unwrap();
    assert!(
        raw.iter()
            .all(|m| m.key.starts_with(&format!("vaults/{vault}/"))
                || m.key.starts_with("index/devices/")
                || m.key.starts_with("index/keys/")
                || m.key.starts_with("index/views/"))
    );
}

#[tokio::test]
async fn vault_creation_admission() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = VaultId::generate();
    let h = header_bytes(&vault, &owner);
    let g = member_bytes(&member(
        &vault,
        &owner,
        1,
        MemberRole::Owner,
        MemberStatus::Active,
        &owner,
    ));
    let c = http();
    // no / wrong token
    for token in ["aipe_wrong", "aips_session"] {
        let err =
            HttpSyncStore::create_vault(&c, &srv.base, &SecretString::from(token), &h, &g, false)
                .await
                .unwrap_err();
        assert_eq!(err, StorageError::Unauthorized);
    }
    let resp = c
        .post(srv.base.join("v1/vaults").unwrap())
        .body(aipass_storage::http::create_vault_body(&h, &g).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "UNAUTHENTICATED");

    // one-time token: first use creates, second use is refused
    let token = srv.admission.generate(Some(1), None).unwrap();
    HttpSyncStore::create_vault(&c, &srv.base, &token, &h, &g, false)
        .await
        .unwrap();
    assert_eq!(
        HttpSyncStore::create_vault(&c, &srv.base, &token, &h, &g, false)
            .await
            .unwrap_err(),
        StorageError::Unauthorized
    );
    // same vault id with another genesis → 412 (and the token reservation is released)
    let other = Device::new();
    let h2 = header_bytes(&vault, &other);
    let g2 = member_bytes(&member(
        &vault,
        &other,
        1,
        MemberRole::Owner,
        MemberStatus::Active,
        &other,
    ));
    let t2 = srv.admission.generate(Some(1), None).unwrap();
    let err = HttpSyncStore::create_vault(&c, &srv.base, &t2, &h2, &g2, false)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(412),
                ..
            }
        ),
        "{err:?}"
    );
    // retry with identical bytes is idempotent
    let t3 = srv.admission.generate(Some(1), None).unwrap();
    HttpSyncStore::create_vault(&c, &srv.base, &t3, &h, &g, false)
        .await
        .unwrap();
    // t2 was refunded and is usable
    let v3 = VaultId::generate();
    let h3 = header_bytes(&v3, &other);
    let g3 = member_bytes(&member(
        &v3,
        &other,
        1,
        MemberRole::Owner,
        MemberStatus::Active,
        &other,
    ));
    HttpSyncStore::create_vault(&c, &srv.base, &t2, &h3, &g3, false)
        .await
        .unwrap();

    // forged genesis: header signed by someone else
    let forger = Device::new();
    let v4 = VaultId::generate();
    let mut hv: serde_json::Value = serde_json::from_slice(&header_bytes(&v4, &forger)).unwrap();
    hv["genesis_device_id"] = serde_json::Value::String(owner.id.to_string());
    let g4 = member_bytes(&member(
        &v4,
        &owner,
        1,
        MemberRole::Owner,
        MemberStatus::Active,
        &owner,
    ));
    let t4 = srv.admission.generate(Some(1), None).unwrap();
    let err = HttpSyncStore::create_vault(
        &c,
        &srv.base,
        &t4,
        &serde_json::to_vec(&hv).unwrap(),
        &g4,
        false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn concurrent_conditional_writes_have_one_winner() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let member_dev = Device::new();
    let vault = srv.create_vault(&owner).await;
    let rec = srv
        .add_member(
            &vault,
            &member_dev,
            1,
            MemberRole::Member,
            MemberStatus::Active,
            &owner,
        )
        .await;
    assert_eq!(srv.commit(&vault, &owner, &[&rec]).await, 1);
    let a = Arc::new(srv.store_for(&vault, &owner));
    let b = Arc::new(srv.store_for(&vault, &member_dev));

    // create-only commit point: 12 writers race for manifests/…02
    let mut tasks = Vec::new();
    for i in 0..12 {
        let (s, author) = if i % 2 == 0 {
            (a.clone(), &owner)
        } else {
            (b.clone(), &member_dev)
        };
        let (seq, bytes) = srv
            .next_manifest(&vault, author, &[], &format!("w{i}"))
            .await;
        assert_eq!(seq, 2);
        tasks.push(tokio::spawn(async move {
            s.put(&keys::manifest(2), bytes, PutCondition::IfAbsent)
                .await
        }));
    }
    let mut won = 0;
    for t in tasks {
        match t.await.unwrap().unwrap() {
            PutOutcome::Written { .. } => won += 1,
            PutOutcome::PreconditionFailed => {}
        }
    }
    assert_eq!(won, 1, "exactly one manifest commit wins");

    // compare-and-swap race on HEAD
    a.put(keys::HEAD, b"0".to_vec(), PutCondition::None)
        .await
        .unwrap();
    let e0 = a.get(keys::HEAD).await.unwrap().unwrap().etag;
    let mut tasks = Vec::new();
    for i in 0..12 {
        let s = if i % 2 == 0 { a.clone() } else { b.clone() };
        let e = e0.clone();
        tasks.push(tokio::spawn(async move {
            s.put(
                keys::HEAD,
                format!("w{i}").into_bytes(),
                PutCondition::IfMatch(e),
            )
            .await
        }));
    }
    let mut won = 0;
    for t in tasks {
        if matches!(t.await.unwrap().unwrap(), PutOutcome::Written { .. }) {
            won += 1;
        }
    }
    assert_eq!(won, 1, "exactly one If-Match writer wins");
}

#[tokio::test]
async fn immutable_objects_cannot_be_overwritten() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let s = srv.store_for(&vault, &owner);
    let e = EntryId::generate();
    let k = keys::entry(&e, 1);
    let PutOutcome::Written { etag } = s
        .put(&k, entry(&vault, &e, 1, &owner), PutCondition::None)
        .await
        .unwrap()
    else {
        panic!()
    };
    // unconditional, create-only and If-Match overwrites are all refused
    for cond in [
        PutCondition::None,
        PutCondition::IfAbsent,
        PutCondition::IfMatch(etag.clone()),
    ] {
        assert_eq!(
            s.put(&k, entry(&vault, &e, 1, &owner), cond).await.unwrap(),
            PutOutcome::PreconditionFailed
        );
    }
    assert_eq!(s.get(&k).await.unwrap().unwrap().etag, etag);
    assert_eq!(
        s.put(
            keys::VAULT_HEADER,
            header_bytes(&vault, &owner),
            PutCondition::None
        )
        .await
        .unwrap(),
        PutOutcome::PreconditionFailed
    );
    assert_eq!(
        s.put(
            &keys::member(&owner.id, 1),
            b"{}".to_vec(),
            PutCondition::None
        )
        .await
        .unwrap(),
        PutOutcome::PreconditionFailed
    );
}

#[tokio::test]
async fn unauthorized_and_revoked_devices_are_rejected() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;

    // stranger: not a member
    let stranger = Device::new();
    let s = srv.store_for(&vault, &stranger);
    assert_eq!(
        s.get(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::Unauthorized
    );
    assert_eq!(
        s.put(keys::HEAD, b"1".to_vec(), PutCondition::None)
            .await
            .unwrap_err(),
        StorageError::Unauthorized
    );
    // someone using a member's id with their own key
    let impostor = srv.store_as(&vault, owner.principal(), &stranger);
    assert_eq!(
        impostor.get(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::Unauthorized
    );
    // a vault that does not exist looks the same as one you are not a member of
    let other_vault = srv.store_for(&VaultId::generate(), &owner);
    assert_eq!(
        other_vault.get(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::Unauthorized
    );

    // member, then revoked by the owner
    let phone = Device::new();
    srv.add_member(
        &vault,
        &phone,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;
    let ps = srv.store_for(&vault, &phone);
    ps.put(keys::HEAD, b"7".to_vec(), PutCondition::None)
        .await
        .unwrap();
    srv.add_member(
        &vault,
        &phone,
        2,
        MemberRole::Member,
        MemberStatus::Revoked,
        &owner,
    )
    .await;
    assert_eq!(
        ps.get(keys::HEAD).await.unwrap_err(),
        StorageError::Unauthorized
    );

    // the revoked device cannot re-activate itself (it cannot even authenticate), and an
    // active member cannot self-promote to owner
    let m2 = Device::new();
    srv.add_member(
        &vault,
        &m2,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;
    let m2s = srv.store_for(&vault, &m2);
    let promo = member(&vault, &m2, 2, MemberRole::Owner, MemberStatus::Active, &m2);
    let err = m2s
        .put(
            &keys::member(&m2.id, 2),
            member_bytes(&promo),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
    // a member cannot add an owner
    let x = Device::new();
    let rec = member(&vault, &x, 1, MemberRole::Owner, MemberStatus::Active, &m2);
    let err = m2s
        .put(
            &keys::member(&x.id, 1),
            member_bytes(&rec),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
    // a record signed by a non-member is refused
    let rec = member(
        &vault,
        &x,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &stranger,
    );
    let err = m2s
        .put(
            &keys::member(&x.id, 1),
            member_bytes(&rec),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
    // a record whose key does not match its content is refused
    let rec = member(
        &vault,
        &x,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    );
    let err = m2s
        .put(
            &keys::member(&x.id, 5),
            member_bytes(&rec),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
    // a manifest signed by a stranger is refused; an entry under the wrong key too
    let err = m2s
        .put(
            &keys::manifest(9),
            manifest(&vault, 9, &stranger, "x"),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
    let e = EntryId::generate();
    let err = m2s
        .put(
            &keys::entry(&e, 2),
            entry(&vault, &e, 1, &m2),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(400),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn executors_are_read_only() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let node = Device::new();
    srv.add_member(
        &vault,
        &node,
        1,
        MemberRole::Executor,
        MemberStatus::Active,
        &owner,
    )
    .await;
    // the dev_<same ulid> alias of an executor record is not a valid kid (CVS-08)
    assert_eq!(
        srv.store_for(&vault, &node)
            .get(keys::VAULT_HEADER)
            .await
            .unwrap_err(),
        StorageError::Unauthorized
    );
    // as exe_<same ulid>
    {
        let s = srv.store_as(&vault, node.executor_principal(), &node);
        assert!(s.get(keys::VAULT_HEADER).await.unwrap().is_some());
        assert!(!s.list("members/", None, 10).await.unwrap().is_empty());
        assert_eq!(
            s.put(keys::HEAD, b"1".to_vec(), PutCondition::None)
                .await
                .unwrap_err(),
            StorageError::Unauthorized
        );
        assert_eq!(
            s.delete(keys::HEAD).await.unwrap_err(),
            StorageError::Unauthorized
        );
    }
    // exe_ kid of a *member* (non-executor) record is not accepted
    let phone = Device::new();
    srv.add_member(
        &vault,
        &phone,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;
    let s = srv.store_as(&vault, phone.executor_principal(), &phone);
    assert_eq!(
        s.get(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::Unauthorized
    );
    // an executor cannot sign member records (not a trusted signer)
    let x = Device::new();
    let rec = member(
        &vault,
        &x,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &node,
    );
    let err = srv
        .store_for(&vault, &owner)
        .put(
            &keys::member(&x.id, 1),
            member_bytes(&rec),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::Backend {
                status: Some(422),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn delete_permissions() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let phone = Device::new();
    srv.add_member(
        &vault,
        &phone,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;
    let os = srv.store_for(&vault, &owner);
    let ps = srv.store_for(&vault, &phone);
    let e = EntryId::generate();
    os.put(
        &keys::entry(&e, 1),
        entry(&vault, &e, 1, &owner),
        PutCondition::IfAbsent,
    )
    .await
    .unwrap();
    // a member may not GC immutable objects; the owner may
    assert_eq!(
        ps.delete(&keys::entry(&e, 1)).await.unwrap_err(),
        StorageError::Unauthorized
    );
    os.delete(&keys::entry(&e, 1)).await.unwrap();
    assert!(os.get(&keys::entry(&e, 1)).await.unwrap().is_none());
    // mutable keys: member may delete
    ps.put("_scratch/x", b"1".to_vec(), PutCondition::None)
        .await
        .unwrap();
    ps.delete("_scratch/x").await.unwrap();
    // nobody deletes vault.json or member records
    assert_eq!(
        os.delete(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::Unauthorized
    );
    assert_eq!(
        os.delete(&keys::member(&phone.id, 1)).await.unwrap_err(),
        StorageError::Unauthorized
    );
    assert!(
        ps.get(keys::VAULT_HEADER).await.unwrap().is_some(),
        "phone still a member"
    );
}

#[allow(clippy::too_many_arguments)]
async fn raw_signed(
    c: &reqwest::Client,
    srv: &Server,
    dev: &Device,
    method: &str,
    path: &str,
    body: Vec<u8>,
    ts: i64,
    nonce: &str,
) -> reqwest::Response {
    let h = aipass_types::signing::sign_request_with(
        dev.ident.as_ref(),
        dev.id.as_str(),
        method,
        path,
        &body,
        ts,
        nonce,
    );
    c.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        srv.base.join(path.trim_start_matches('/')).unwrap(),
    )
    .header("authorization", h.to_header_value())
    .header("accept-language", "en-US")
    .body(body)
    .send()
    .await
    .unwrap()
}

#[tokio::test]
async fn replayed_and_skewed_signatures_are_rejected() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let c = http();
    let path = format!("/v1/vaults/{vault}");
    let now = aipass_types::time::unix_now();
    let nonce = aipass_crypto::b64u::encode([7u8; 16]);
    let r1 = raw_signed(&c, &srv, &owner, "GET", &path, vec![], now, &nonce).await;
    assert_eq!(r1.status(), 200);
    let r2 = raw_signed(&c, &srv, &owner, "GET", &path, vec![], now, &nonce).await;
    assert_eq!(r2.status(), 401, "replay must be refused");
    let body: serde_json::Value = r2.json().await.unwrap();
    assert_eq!(body["error"]["code"], "IDENTITY_UNVERIFIED");
    assert_eq!(body["error"]["details"]["reason"], "nonce replay");
    assert_eq!(
        body["error"]["message"],
        "The caller's identity could not be verified."
    );
    assert!(
        body["error"]["request_id"]
            .as_str()
            .unwrap()
            .starts_with("req_")
    );

    // skew
    let n2 = aipass_crypto::b64u::encode([8u8; 16]);
    let r = raw_signed(&c, &srv, &owner, "GET", &path, vec![], now - 1000, &n2).await;
    assert_eq!(r.status(), 401);
    // signature over another path is refused
    let n3 = aipass_crypto::b64u::encode([9u8; 16]);
    let h = aipass_types::signing::sign_request_with(
        owner.ident.as_ref(),
        owner.id.as_str(),
        "GET",
        "/v1/vaults/other",
        &[],
        now,
        &n3,
    );
    let r = c
        .get(srv.base.join(path.trim_start_matches('/')).unwrap())
        .header("authorization", h.to_header_value())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["error"]["message"], "无法验证调用方身份",
        "zh-CN by default"
    );
    // tampered body on PUT
    let n4 = aipass_crypto::b64u::encode([10u8; 16]);
    let obj = format!("/v1/vaults/{vault}/objects/HEAD");
    let h = aipass_types::signing::sign_request_with(
        owner.ident.as_ref(),
        owner.id.as_str(),
        "PUT",
        &obj,
        b"1",
        now,
        &n4,
    );
    let r = c
        .put(srv.base.join(obj.trim_start_matches('/')).unwrap())
        .header("authorization", h.to_header_value())
        .body("2")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    // bearer / connection principals are not accepted on the sync API
    let r = c
        .get(srv.base.join(path.trim_start_matches('/')).unwrap())
        .header("authorization", "Bearer aipc_xyz")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn limits_quota_and_bad_input() {
    let srv = start(Options {
        quota: Arc::new(StaticQuota {
            max_bytes_per_vault: Some(20_000),
            max_objects_per_vault: None,
        }),
        sync_cfg: aipass_sync_server::SyncConfig {
            max_object_bytes: 50_000,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let s = srv.store_for(&vault, &owner);
    assert_eq!(s.vault_info().await.unwrap().quota_bytes, Some(20_000));
    s.put("_blob/a", vec![0u8; 10_000], PutCondition::None)
        .await
        .unwrap();
    let err = s
        .put("_blob/b", vec![0u8; 15_000], PutCondition::None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StorageError::Backend { status: Some(429), ref message } if message == "QUOTA_EXCEEDED"),
        "{err:?}"
    );
    // replacing an object counts the freed bytes
    s.put("_blob/a", vec![0u8; 12_000], PutCondition::None)
        .await
        .unwrap();
    // HEAD is a tiny hint
    let err = s
        .put(keys::HEAD, vec![b'1'; 100], PutCondition::None)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::TooLarge { .. }), "{err:?}");
    // client refuses > 4 MiB before sending
    assert!(matches!(
        s.put(
            "_blob/c",
            vec![0u8; 4 * 1024 * 1024 + 1],
            PutCondition::None
        )
        .await
        .unwrap_err(),
        StorageError::TooLarge { .. }
    ));
    // the server enforces its own limit (configured to 50 000 bytes here)
    let c = http();
    let path = format!("/v1/vaults/{vault}/objects/_blob/big");
    let r = raw_signed(
        &c,
        &srv,
        &owner,
        "PUT",
        &path,
        vec![0u8; 50_001],
        aipass_types::time::unix_now(),
        &aipass_crypto::b64u::encode([1u8; 16]),
    )
    .await;
    assert_eq!(r.status(), 400);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["details"]["reason"], "too_large");
    // invalid keys / ids
    let r = raw_signed(
        &c,
        &srv,
        &owner,
        "GET",
        &format!("/v1/vaults/{vault}/objects/a%20b"),
        vec![],
        aipass_types::time::unix_now(),
        &aipass_crypto::b64u::encode([2u8; 16]),
    )
    .await;
    assert_eq!(r.status(), 400);
    let r = raw_signed(
        &c,
        &srv,
        &owner,
        "GET",
        "/v1/vaults/not-a-vault",
        vec![],
        aipass_types::time::unix_now(),
        &aipass_crypto::b64u::encode([3u8; 16]),
    )
    .await;
    assert_eq!(r.status(), 400);
    let r = raw_signed(
        &c,
        &srv,
        &owner,
        "GET",
        &format!("/v1/vaults/{vault}/objects?limit=5000"),
        vec![],
        aipass_types::time::unix_now(),
        &aipass_crypto::b64u::encode([4u8; 16]),
    )
    .await;
    assert_eq!(r.status(), 400);
    // conflicting conditions
    let path = format!("/v1/vaults/{vault}/objects/_blob/x");
    let now = aipass_types::time::unix_now();
    let n = aipass_crypto::b64u::encode([5u8; 16]);
    let h = aipass_types::signing::sign_request_with(
        owner.ident.as_ref(),
        owner.id.as_str(),
        "PUT",
        &path,
        b"x",
        now,
        &n,
    );
    let r = c
        .put(srv.base.join(path.trim_start_matches('/')).unwrap())
        .header("authorization", h.to_header_value())
        .header("if-none-match", "*")
        .header("if-match", "\"abc\"")
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn object_responses_carry_etag_and_no_store() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let s = srv.store_for(&vault, &owner);
    let PutOutcome::Written { etag } = s
        .put("_x/y", b"hello".to_vec(), PutCondition::IfAbsent)
        .await
        .unwrap()
    else {
        panic!()
    };
    let c = http();
    let path = format!("/v1/vaults/{vault}/objects/_x/y");
    let r = raw_signed(
        &c,
        &srv,
        &owner,
        "GET",
        &path,
        vec![],
        aipass_types::time::unix_now(),
        &aipass_crypto::b64u::encode([11u8; 16]),
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["etag"], format!("\"{etag}\"").as_str());
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"hello");
}

#[tokio::test]
async fn member_index_and_rebuild() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let v1 = srv.create_vault(&owner).await;
    let v2 = srv.create_vault(&owner).await;
    let mut vs = srv.sync.vaults_of(&owner.id).await.unwrap();
    vs.sort();
    let mut want = vec![v1.clone(), v2.clone()];
    want.sort();
    assert_eq!(vs, want);
    // wipe the index and rebuild it from the vault namespaces
    for m in list_all(srv.blob_store().as_ref(), "index/").await.unwrap() {
        srv.blob_store().delete(&m.key).await.unwrap();
    }
    assert!(srv.sync.vaults_of(&owner.id).await.unwrap().is_empty());
    assert_eq!(srv.sync.rebuild_member_index().await.unwrap(), 2);
    assert_eq!(srv.sync.vaults_of(&owner.id).await.unwrap().len(), 2);
}

#[tokio::test]
async fn tampered_member_record_fails_closed() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let phone = Device::new();
    srv.add_member(
        &vault,
        &phone,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;
    srv.add_member(
        &vault,
        &phone,
        2,
        MemberRole::Member,
        MemberStatus::Revoked,
        &owner,
    )
    .await;
    // a malicious storage provider corrupts the revocation record: the device must not
    // fall back to its older active revision
    let key = format!("vaults/{vault}/{}", keys::member(&phone.id, 2));
    srv.blobs.tamper(&key, b"{\"garbage\":true}".to_vec()).await;
    // a fresh state (empty caches) over the same blobs
    let state = aipass_sync_server::SyncState::new(
        srv.blob_store(),
        Arc::new(aipass_sync_server::sync::DenyAllAdmission),
    );
    let r = state
        .resolve_member(&vault, &phone.principal())
        .await
        .unwrap();
    assert!(
        r.is_none(),
        "damaged latest revision ⇒ unknown, never the older active one"
    );
    // the owner is unaffected
    assert!(
        state
            .resolve_member(&vault, &owner.principal())
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
}

#[tokio::test]
async fn responses_do_not_reveal_membership() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let stranger = Device::new();
    let c = http();
    let path = format!("/v1/vaults/{vault}");
    let now = aipass_types::time::unix_now();
    // a real member id signed with the wrong key vs. an id that is not a member at all
    let impostor = Device {
        id: owner.id.clone(),
        ident: stranger.ident.clone(),
    };
    let a = raw_signed(
        &c,
        &srv,
        &impostor,
        "GET",
        &path,
        vec![],
        now,
        &aipass_crypto::b64u::encode([21u8; 16]),
    )
    .await;
    let b = raw_signed(
        &c,
        &srv,
        &stranger,
        "GET",
        &path,
        vec![],
        now,
        &aipass_crypto::b64u::encode([22u8; 16]),
    )
    .await;
    let other = format!("/v1/vaults/{}", VaultId::generate());
    let d = raw_signed(
        &c,
        &srv,
        &owner,
        "GET",
        &other,
        vec![],
        now,
        &aipass_crypto::b64u::encode([23u8; 16]),
    )
    .await;
    let mut bodies = Vec::new();
    for r in [a, b, d] {
        assert_eq!(r.status(), 401);
        let v: serde_json::Value = r.json().await.unwrap();
        bodies.push((v["error"]["code"].clone(), v["error"]["details"].clone()));
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
}

#[tokio::test]
async fn per_principal_rate_limit() {
    let srv = start(Options {
        sync_cfg: aipass_sync_server::SyncConfig {
            principal_rate: aipass_sync_server::RateLimitConfig::new(0.001, 3.0),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let s = srv.store_for(&vault, &owner);
    for _ in 0..3 {
        s.get(keys::VAULT_HEADER).await.unwrap();
    }
    assert_eq!(
        s.get(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::RateLimited
    );
    // another principal has its own budget
    let phone = Device::new();
    let m = member(
        &vault,
        &phone,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    );
    // (the owner is throttled, so write the record straight into the blob namespace the
    // way a migration would, then resolve it)
    srv.blob_store()
        .put(
            &format!("vaults/{vault}/{}", keys::member(&phone.id, 1)),
            member_bytes(&m),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap();
    srv.store_for(&vault, &phone)
        .get(keys::VAULT_HEADER)
        .await
        .unwrap();
}
