// SPDX-License-Identifier: Apache-2.0
//! Regression tests for the crypto-vault-sync security review (CVS-01/02/03/07/08):
//! cross-tenant device-key hijacking on the relay, unlisted "sock puppet" members, member
//! records that bypass the client transition rules, quota races and kid-alias replays.

mod common;

use std::sync::Arc;

use aipass_storage::relay_client::{RelayAuth, RelayClient, RelayClientError};
use aipass_storage::{ObjectStore, PutCondition, PutOutcome, StorageError};
use aipass_sync_server::sync::StaticQuota;
use aipass_types::ErrorCode;
use aipass_types::ids::{MailboxId, PrincipalId, VaultId};
use aipass_types::vault::{MemberRecord, MemberRole, MemberStatus, SignedObject, keys};
use common::*;

fn relay(srv: &Server, kid: PrincipalId, dev: &Device) -> RelayClient {
    RelayClient::with_client(
        srv.base.clone(),
        RelayAuth::Signed {
            kid,
            signer: dev.signer(),
        },
        http(),
        false,
    )
    .unwrap()
}

/// A device that claims `victim`'s id but holds the attacker's own key.
fn impostor(victim: &Device, attacker_key: &Device) -> Device {
    Device {
        id: victim.id.clone(),
        ident: attacker_key.ident.clone(),
    }
}

fn status_of(err: &StorageError) -> Option<u16> {
    match err {
        StorageError::Backend { status, .. } => *status,
        StorageError::Unauthorized => Some(401),
        _ => None,
    }
}

async fn put_record(
    srv: &Server,
    vault: &VaultId,
    uploader: &Device,
    rec: &MemberRecord,
) -> Result<PutOutcome, StorageError> {
    srv.store_for(vault, uploader)
        .put(
            &keys::member(&rec.device_id, rec.rev),
            member_bytes(rec),
            PutCondition::IfAbsent,
        )
        .await
}

/// Plant a record bypassing the API (data stored before key binding existed).
async fn plant(srv: &Server, vault: &VaultId, rec: &MemberRecord) {
    let b: Arc<dyn ObjectStore> = srv.blobs.clone();
    b.put(
        &format!("vaults/{vault}/{}", keys::member(&rec.device_id, rec.rev)),
        member_bytes(rec),
        PutCondition::None,
    )
    .await
    .unwrap();
    b.put(
        &format!("index/devices/{}/{vault}", rec.device_id),
        Vec::new(),
        PutCondition::None,
    )
    .await
    .unwrap();
}

fn assert_unverified(r: Result<Vec<aipass_types::relay::MailboxMessage>, RelayClientError>) {
    match r {
        Err(RelayClientError::Api(a)) => assert_eq!(a.code, ErrorCode::IdentityUnverified),
        other => panic!("expected IDENTITY_UNVERIFIED, got {other:?}"),
    }
}

/// CVS-01: a vault owner cannot bind a foreign device id to its own key, and a planted
/// record never lets the attacker into the victim's relay mailbox.
#[tokio::test]
async fn cross_vault_relay_key_hijack_is_refused() {
    let srv = start(Options::default()).await;
    let victim = Device::new();
    let _victim_vault = srv.create_vault(&victim).await;
    let attacker = Device::new();
    let attacker_vault = srv.create_vault(&attacker).await;
    let fake = impostor(&victim, &attacker);

    // the API refuses the foreign record (device id already bound to another key)
    let forged = member(
        &attacker_vault,
        &fake,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &attacker,
    );
    let err = put_record(&srv, &attacker_vault, &attacker, &forged)
        .await
        .unwrap_err();
    assert_eq!(status_of(&err), Some(422), "{err:?}");
    // … also as a vault genesis on another vault
    let v3 = VaultId::generate();
    let h = header_bytes(&v3, &fake);
    let g = member(
        &v3,
        &fake,
        1,
        MemberRole::Owner,
        MemberStatus::Active,
        &fake,
    );
    assert!(
        aipass_storage::HttpSyncStore::create_vault(
            &http(),
            &srv.base,
            &srv.token(),
            &h,
            &member_bytes(&g),
            false,
        )
        .await
        .is_err(),
        "genesis with a foreign device id must be refused"
    );

    // a planted record (pre-binding data) does not change the victim's key
    plant(&srv, &attacker_vault, &forged).await;
    let mb = MailboxId::Device(victim.id.clone());
    assert!(
        relay(&srv, victim.principal(), &victim)
            .fetch(&mb, None, 0)
            .await
            .is_ok(),
        "the real device keeps its mailbox"
    );
    assert_unverified(
        relay(&srv, victim.principal(), &fake)
            .fetch(&mb, None, 0)
            .await,
    );

    // without a binding (legacy), differing keys fail closed instead of "first vault wins"
    let b: Arc<dyn ObjectStore> = srv.blobs.clone();
    b.delete(&format!("index/keys/{}", victim.id))
        .await
        .unwrap();
    srv.sync.rebuild_member_index().await.unwrap();
    assert_unverified(
        relay(&srv, victim.principal(), &fake)
            .fetch(&mb, None, 0)
            .await,
    );
}

/// CVS-01 for executor mailboxes (`exe_U` ⇔ member `dev_U`).
#[tokio::test]
async fn executor_mailbox_cannot_be_hijacked() {
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
    let attacker = Device::new();
    let attacker_vault = srv.create_vault(&attacker).await;
    let fake = impostor(&node, &attacker);
    let forged = member(
        &attacker_vault,
        &fake,
        1,
        MemberRole::Executor,
        MemberStatus::Active,
        &attacker,
    );
    let err = put_record(&srv, &attacker_vault, &attacker, &forged)
        .await
        .unwrap_err();
    assert_eq!(status_of(&err), Some(422), "{err:?}");
    plant(&srv, &attacker_vault, &forged).await;

    let exe = node.executor_principal();
    let mb = MailboxId::parse(exe.as_str()).unwrap();
    assert!(
        relay(&srv, exe.clone(), &node)
            .fetch(&mb, None, 0)
            .await
            .is_ok()
    );
    assert_unverified(relay(&srv, exe, &fake).fetch(&mb, None, 0).await);
}

/// CVS-02: an unlisted device introduced by a member cannot author manifests and loses
/// all access when its introducer is revoked; honest commits keep working.
#[tokio::test]
async fn sock_puppet_loses_access_with_its_voucher() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let m = Device::new();
    let m_rec = srv
        .add_member(
            &vault,
            &m,
            1,
            MemberRole::Member,
            MemberStatus::Active,
            &owner,
        )
        .await;
    assert_eq!(srv.commit(&vault, &owner, &[&m_rec]).await, 1);

    // M (still active) introduces puppet P without listing it in any manifest
    let p = Device::new();
    srv.add_member(&vault, &p, 1, MemberRole::Member, MemberStatus::Active, &m)
        .await;
    let ps = srv.store_for(&vault, &p);
    assert!(
        ps.get(keys::VAULT_HEADER).await.unwrap().is_some(),
        "in-flight window"
    );

    // P cannot author a manifest: it is not a member of the previous manifest
    let (seq, bytes) = srv.next_manifest(&vault, &p, &[], "puppet").await;
    assert_eq!(seq, 2);
    let err = ps
        .put(&keys::manifest(2), bytes, PutCondition::IfAbsent)
        .await
        .unwrap_err();
    assert_eq!(status_of(&err), Some(422), "{err:?}");

    // the owner revokes M (record + key rotation + manifest), as a client does
    let mut o2 = member(
        &vault,
        &owner,
        2,
        MemberRole::Owner,
        MemberStatus::Active,
        &owner,
    );
    o2.key_epoch = 2;
    o2.sign_with(owner.ident.as_ref()).unwrap();
    assert!(put_record(&srv, &vault, &owner, &o2).await.is_ok());
    let m2 = member(
        &vault,
        &m,
        2,
        MemberRole::Member,
        MemberStatus::Revoked,
        &owner,
    );
    assert!(put_record(&srv, &vault, &owner, &m2).await.is_ok());
    let (seq, bytes) = srv
        .next_manifest_epoch(&vault, &owner, &[&o2, &m2], "revoke", Some(2))
        .await;
    assert_eq!(seq, 2);
    assert!(matches!(
        srv.store_for(&vault, &owner)
            .put(&keys::manifest(2), bytes, PutCondition::IfAbsent)
            .await
            .unwrap(),
        PutOutcome::Written { .. }
    ));

    // M and its unlisted puppet are out
    for d in [&m, &p] {
        let s = srv.store_for(&vault, d);
        assert_eq!(
            s.get(keys::VAULT_HEADER).await.unwrap_err(),
            StorageError::Unauthorized
        );
        assert_eq!(
            s.put("blob/x", b"x".to_vec(), PutCondition::None)
                .await
                .unwrap_err(),
            StorageError::Unauthorized
        );
    }
    // a further self-signed revision of the puppet does not revive it
    let p2 = member(&vault, &p, 2, MemberRole::Member, MemberStatus::Active, &p);
    let _ = put_record(&srv, &vault, &owner, &p2).await;
    assert_eq!(
        ps.get(keys::VAULT_HEADER).await.unwrap_err(),
        StorageError::Unauthorized
    );

    // honest clients keep committing
    assert_eq!(srv.commit(&vault, &owner, &[]).await, 3);
}

/// CVS-03: member records must follow the client transition rules on the server too.
#[tokio::test]
async fn member_records_follow_transition_rules() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let m = Device::new();
    srv.add_member(
        &vault,
        &m,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;

    // (a) a member cannot revoke or demote the owner
    for (role, status) in [
        (MemberRole::Member, MemberStatus::Revoked),
        (MemberRole::Member, MemberStatus::Active),
        (MemberRole::Owner, MemberStatus::Revoked),
    ] {
        let r = member(&vault, &owner, 2, role, status, &m);
        let err = put_record(&srv, &vault, &m, &r).await.unwrap_err();
        assert_eq!(status_of(&err), Some(422), "{role:?}/{status:?}: {err:?}");
    }
    assert!(
        srv.store_for(&vault, &owner)
            .get(keys::VAULT_HEADER)
            .await
            .unwrap()
            .is_some(),
        "the owner keeps access"
    );

    // a member cannot revoke another member either (status change needs an owner)
    let x = Device::new();
    srv.add_member(
        &vault,
        &x,
        1,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    )
    .await;
    let r = member(&vault, &x, 2, MemberRole::Member, MemberStatus::Revoked, &m);
    assert_eq!(
        status_of(&put_record(&srv, &vault, &m, &r).await.unwrap_err()),
        Some(422)
    );
    // nor rewrite its keys
    let other_key = Device::new();
    let r = member(
        &vault,
        &impostor(&x, &other_key),
        2,
        MemberRole::Member,
        MemberStatus::Active,
        &owner,
    );
    assert_eq!(
        status_of(&put_record(&srv, &vault, &owner, &r).await.unwrap_err()),
        Some(422)
    );

    // (b) a revoked device is never reinstated — by a member or by an owner
    srv.add_member(
        &vault,
        &x,
        2,
        MemberRole::Member,
        MemberStatus::Revoked,
        &owner,
    )
    .await;
    for by in [&m, &owner] {
        let r = member(&vault, &x, 3, MemberRole::Member, MemberStatus::Active, by);
        let err = put_record(&srv, &vault, by, &r).await.unwrap_err();
        assert_eq!(status_of(&err), Some(422), "{err:?}");
    }
    assert_eq!(
        srv.store_for(&vault, &x)
            .get(keys::VAULT_HEADER)
            .await
            .unwrap_err(),
        StorageError::Unauthorized
    );

    // (c) records signed by a revoked signer are refused on upload
    let y = Device::new();
    let r = member(&vault, &y, 1, MemberRole::Member, MemberStatus::Active, &x);
    let err = put_record(&srv, &vault, &owner, &r).await.unwrap_err();
    assert_eq!(status_of(&err), Some(422), "{err:?}");

    // the owner may still demote / revoke members
    srv.add_member(
        &vault,
        &m,
        2,
        MemberRole::Member,
        MemberStatus::Revoked,
        &owner,
    )
    .await;
}

/// CVS-03: a device with a long revision history still resolves (bottom-up verification
/// keeps the recursion shallow).
#[tokio::test]
async fn long_revision_histories_resolve() {
    let srv = start(Options::default()).await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let m = Device::new();
    for rev in 1..=40 {
        srv.add_member(
            &vault,
            &m,
            rev,
            MemberRole::Member,
            MemberStatus::Active,
            &owner,
        )
        .await;
    }
    assert!(
        srv.store_for(&vault, &m)
            .get(keys::VAULT_HEADER)
            .await
            .unwrap()
            .is_some()
    );
}

/// CVS-07: concurrent writes cannot overshoot the vault quota.
#[tokio::test]
async fn parallel_puts_respect_the_quota() {
    const MAX: u64 = 20_000;
    const OBJ: usize = 1_000;
    let srv = start(Options {
        quota: Arc::new(StaticQuota {
            max_bytes_per_vault: Some(MAX),
            max_objects_per_vault: None,
        }),
        ..Options::default()
    })
    .await;
    let owner = Device::new();
    let vault = srv.create_vault(&owner).await;
    let s = Arc::new(srv.store_for(&vault, &owner));
    let mut tasks = Vec::new();
    for i in 0..60 {
        let s = s.clone();
        tasks.push(tokio::spawn(async move {
            s.put(&format!("blob/{i}"), vec![9; OBJ], PutCondition::None)
                .await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    let usage = srv.sync.usage(&vault).await.unwrap();
    assert!(ok > 0 && ok < 60, "{ok}");
    assert!(usage.bytes_used <= MAX + OBJ as u64, "{usage:?}");
    // the accounting matches what is stored
    let stored: u64 = aipass_storage::list_all(&*s, "")
        .await
        .unwrap()
        .iter()
        .map(|m| m.size)
        .sum();
    assert_eq!(stored, usage.bytes_used);
}

/// CVS-08: a captured `exe_U` request replayed with the `dev_U` alias is refused.
#[tokio::test]
async fn executor_alias_kid_replay_is_refused() {
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
    let path = format!("/v1/vaults/{vault}/objects/{}", keys::VAULT_HEADER);
    let exe = node.executor_principal();
    let h = aipass_types::signing::sign_request_with(
        node.ident.as_ref(),
        exe.as_str(),
        "GET",
        &path,
        &[],
        aipass_types::time::unix_now(),
        &aipass_crypto::b64u::encode([3u8; 16]),
    );
    let send = |auth: String| {
        let url = srv.base.join(path.trim_start_matches('/')).unwrap();
        async move {
            http()
                .get(url)
                .header("authorization", auth)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    let original = h.to_header_value();
    assert_eq!(send(original.clone()).await, 200);
    let alias = original.replace(exe.as_str(), node.id.as_str());
    assert_ne!(alias, original);
    assert_eq!(send(alias).await, 401);
    assert_eq!(send(original).await, 401, "plain replay");
}

/// A13 regression: an owner that re-signs the record of a device in its own voucher chain
/// (a key-epoch rotation after a revocation re-signs every remaining member) must not lock
/// itself out. Before the fix, resolving the new owner's voucher chain looped back to the
/// owner itself (`member_chain_cycle`) and every request of that owner was refused.
#[tokio::test]
async fn owner_resigning_its_vouchers_record_keeps_access() {
    let srv = start(Options::default()).await;
    let genesis = Device::new();
    let vault = srv.create_vault(&genesis).await;
    // genesis → recovery member → recovered device (the `vault recover` chain)
    let recovery = Device::new();
    let r1 = srv.add_member(&vault, &recovery, 1, MemberRole::Owner, MemberStatus::Active, &genesis).await;
    let lost = Device::new();
    let l1 = srv.add_member(&vault, &lost, 1, MemberRole::Owner, MemberStatus::Active, &genesis).await;
    srv.commit(&vault, &genesis, &[&r1, &l1]).await;
    let recovered = Device::new();
    let n1 = srv.add_member(&vault, &recovered, 1, MemberRole::Owner, MemberStatus::Active, &recovery).await;
    srv.commit(&vault, &recovery, &[&n1]).await;
    // the recovered device revokes the lost one and re-signs the remaining members
    let rotated = |dev: &Device, status: MemberStatus| {
        let mut m = member(&vault, dev, 2, MemberRole::Owner, status, &recovered);
        m.key_epoch = 2;
        m.sign_with(recovered.ident.as_ref()).unwrap();
        m
    };
    let (l2, g2, r2, n2) = (
        rotated(&lost, MemberStatus::Revoked),
        rotated(&genesis, MemberStatus::Active),
        rotated(&recovery, MemberStatus::Active),
        rotated(&recovered, MemberStatus::Active),
    );
    for rec in [&l2, &g2, &r2, &n2] {
        let out = put_record(&srv, &vault, &recovered, rec).await;
        assert!(matches!(out, Ok(PutOutcome::Written { .. })), "{out:?}");
    }
    // revoking a trusted device rotates the key epoch
    let (seq, bytes) = srv.next_manifest_epoch(&vault, &recovered, &[&l2, &g2, &r2, &n2], "revoke", Some(2)).await;
    let out = srv.store_for(&vault, &recovered).put(&keys::manifest(seq), bytes, PutCondition::IfAbsent).await;
    assert!(matches!(out, Ok(PutOutcome::Written { .. })), "revocation manifest: {out:?}");
    for (name, d) in [("recovered", &recovered), ("genesis", &genesis), ("recovery", &recovery)] {
        assert!(
            srv.store_for(&vault, d).get(keys::VAULT_HEADER).await.unwrap().is_some(),
            "{name} must keep access"
        );
    }
    // the revocation still holds
    let err = srv.store_for(&vault, &lost).get(keys::VAULT_HEADER).await.unwrap_err();
    assert!(matches!(status_of(&err), Some(401 | 403)), "{err:?}");
    // and the cycle fallback never applies to uploads: a revoked signer cannot add members
    let puppet = Device::new();
    let r = put_record(&srv, &vault, &lost, &member(&vault, &puppet, 1, MemberRole::Member, MemberStatus::Active, &lost)).await;
    assert!(r.is_err(), "a revoked device must not add members");
}
