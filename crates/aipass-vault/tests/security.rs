// SPDX-License-Identifier: Apache-2.0
//! Vault Core security properties: AAD binding (moved / relabelled ciphertexts fail),
//! manifest chain rules, generator distribution sanity, no secrets in Debug output.

use std::collections::BTreeMap;

use aipass_crypto::{Argon2Params, DeviceIdentity, SecretString};
use aipass_types::ids::{DeviceId, EntryId};
use aipass_types::vault::{
    EntryKind, EntryPayload, EntryVersion, MemberRole, PasswordRules, Platform,
};
use aipass_vault::manifest::{
    ManifestDraft, staged_member_records, verify_entry_object, verify_transition,
};
use aipass_vault::member::device_public;
use aipass_vault::vault::{GenesisParams, create_genesis, stage_add_member, stage_revocation};

fn genesis() -> aipass_vault::Genesis {
    create_genesis(GenesisParams {
        device_name: "Laptop",
        platform: Platform::Linux,
        master_password: None,
        argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        now: aipass_types::time::now(),
    })
    .unwrap()
}

#[test]
fn moved_or_relabelled_ciphertexts_fail_authentication() {
    let g = genesis();
    let now = aipass_types::time::now();
    let e1 = EntryId::generate();
    let e2 = EntryId::generate();
    let mut p = EntryPayload::new(EntryKind::ApiKey, "OpenAI key");
    p.secret = Some(SecretString::from("sk-test-not-real-0000"));
    let s1 = g.unlocked.encrypt_entry(&e1, 1, &p, &now).unwrap();
    let s1v2 = g.unlocked.encrypt_entry(&e1, 2, &p, &now).unwrap();

    // copy entry 1's object to entry 2's location and rewrite the id field
    let mut moved: EntryVersion = serde_json::from_slice(&s1.bytes).unwrap();
    moved.entry_id = e2.clone();
    assert!(g.unlocked.decrypt_entry(&e2, 1, &moved).is_err());
    // relabel version 1 as version 2
    let mut relabel: EntryVersion = serde_json::from_slice(&s1.bytes).unwrap();
    relabel.version = 2;
    assert!(g.unlocked.decrypt_entry(&e1, 2, &relabel).is_err());
    // splice the DEK wrap of v2 into v1
    let mut splice = s1.version.clone();
    splice.wrapped_dek = s1v2.version.wrapped_dek.clone();
    splice.dek_nonce = s1v2.version.dek_nonce;
    assert!(g.unlocked.decrypt_entry(&e1, 1, &splice).is_err());
    // splice ciphertext of v2 under v1's DEK
    let mut splice2 = s1.version.clone();
    splice2.ciphertext = s1v2.version.ciphertext.clone();
    splice2.nonce = s1v2.version.nonce;
    assert!(g.unlocked.decrypt_entry(&e1, 1, &splice2).is_err());
    // claim another key epoch
    let mut epoch = s1.version.clone();
    epoch.key_epoch = 2;
    assert!(g.unlocked.decrypt_entry(&e1, 1, &epoch).is_err());
    // the genuine objects still decrypt
    assert_eq!(g.unlocked.decrypt_entry(&e1, 1, &s1.version).unwrap(), p);
    assert_eq!(g.unlocked.decrypt_entry(&e1, 2, &s1v2.version).unwrap(), p);
    // Debug of everything involved stays redacted
    let dbg = format!(
        "{:?} {:?} {:?} {:?}",
        p, s1.version, g.unlocked, g.recovery_key
    );
    assert!(!dbg.contains("sk-test") && !dbg.contains("OpenAI"));
}

#[test]
fn manifest_rules_reject_malicious_transitions() {
    let g = genesis();
    let now = aipass_types::time::now();
    let view = g.view.clone();
    let e = EntryId::generate();
    let p = EntryPayload::new(EntryKind::SecureNote, "n");

    // a normal entry commit verifies, and its object verifies against the view
    let mut d = ManifestDraft::from_view(&view);
    let v = d.next_version(&e);
    let s = g.unlocked.encrypt_entry(&e, v, &p, &now).unwrap();
    d.set_current(&s, vec![]);
    let (c, staged) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    let v1 = verify_transition(&view, &c, &staged_member_records(&view, &c, &staged)).unwrap();
    verify_entry_object(&v1, &e, &s.bytes, true).unwrap();
    assert!(verify_entry_object(&v1, &e, &s.bytes[1..], true).is_err());

    // entry dropped without tombstone
    let mut d = ManifestDraft::from_view(&v1);
    d.entries.remove(&e);
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    assert!(verify_transition(&v1, &c, &staged_member_records(&v1, &c, &st)).is_err());

    // version going backwards
    let mut d = ManifestDraft::from_view(&v1);
    d.entries.get_mut(&e).unwrap().version = 0;
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    assert!(verify_transition(&v1, &c, &staged_member_records(&v1, &c, &st)).is_err());

    // wrong prev_hash: verify against the genesis view instead of v1
    let d = ManifestDraft::from_view(&v1);
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    assert!(verify_transition(&view, &c, &staged_member_records(&view, &c, &st)).is_err());

    // author not a member
    let stranger = DeviceIdentity::generate();
    let mut d = ManifestDraft::from_view(&v1);
    d.tombstone(&e, &now).unwrap();
    let (c, st) = d.finish(&stranger, &DeviceId::generate(), &now).unwrap();
    assert!(verify_transition(&v1, &c, &staged_member_records(&v1, &c, &st)).is_err());

    // a member cannot revoke without rotation, and an executor cannot author
    let exe_id = DeviceIdentity::generate();
    let exe_dev = DeviceId::generate();
    let exe = device_public(
        &exe_dev,
        &exe_id,
        "node",
        Platform::Node,
        MemberRole::Executor,
    );
    let mut d = ManifestDraft::from_view(&v1);
    stage_add_member(&g.unlocked, &v1, &mut d, &exe, &now).unwrap();
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    let v2 = verify_transition(&v1, &c, &staged_member_records(&v1, &c, &st)).unwrap();
    let mut d = ManifestDraft::from_view(&v2);
    d.tombstone(&e, &now).unwrap();
    let (c, st) = d.finish(&exe_id, &exe_dev, &now).unwrap();
    assert!(
        verify_transition(&v2, &c, &staged_member_records(&v2, &c, &st)).is_err(),
        "executors never author manifests"
    );

    // a rotation that forgets a member is rejected
    let phone_id = DeviceIdentity::generate();
    let phone_dev = DeviceId::generate();
    let phone = device_public(
        &phone_dev,
        &phone_id,
        "Phone",
        Platform::Ios,
        MemberRole::Member,
    );
    let mut d = ManifestDraft::from_view(&v2);
    stage_add_member(&g.unlocked, &v2, &mut d, &phone, &now).unwrap();
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    let v3 = verify_transition(&v2, &c, &staged_member_records(&v2, &c, &st)).unwrap();
    let mut d = ManifestDraft::from_view(&v3);
    stage_revocation(&g.unlocked, &v3, &mut d, &phone_dev, &now)
        .unwrap()
        .unwrap();
    // drop the re-sealed record of the recovery member from the draft
    let rec = aipass_vault::vault::recovery_member(&v3)
        .unwrap()
        .device_id
        .clone();
    d.members
        .insert(rec.clone(), v3.manifest.members[&rec].clone());
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    assert!(verify_transition(&v3, &c, &staged_member_records(&v3, &c, &st)).is_err());
    // the honest rotation verifies
    let mut d = ManifestDraft::from_view(&v3);
    stage_revocation(&g.unlocked, &v3, &mut d, &phone_dev, &now)
        .unwrap()
        .unwrap();
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    let v4 = verify_transition(&v3, &c, &staged_member_records(&v3, &c, &st)).unwrap();
    assert_eq!(v4.manifest.key_epoch, 2);
    // a revoked device can never be reinstated, even by an owner
    let rec4 = v4.member(&phone_dev).unwrap().clone();
    let mut d = ManifestDraft::from_view(&v4);
    let back = aipass_vault::member::build_member(
        g.unlocked.identity(),
        aipass_vault::member::MemberParams {
            vault_id: &g.vault_id,
            device: &rec4.device_public(),
            rev: rec4.rev + 1,
            status: aipass_types::vault::MemberStatus::Active,
            key_epoch: 2,
            wrapped_vmk: Some(
                aipass_vault::keys::seal_vmk(
                    &aipass_crypto::Key32::generate().unwrap(),
                    &g.vault_id,
                    &phone_dev,
                    2,
                    &rec4.kem_pk,
                )
                .unwrap(),
            ),
            added_by: &g.device_id,
            now: &now,
        },
    )
    .unwrap();
    d.put_member(&back);
    let (c, st) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
    assert!(verify_transition(&v4, &c, &staged_member_records(&v4, &c, &st)).is_err());
}

#[test]
fn generator_distribution_is_uniform() {
    let rules = PasswordRules {
        length: 64,
        symbols: false,
        ..Default::default()
    };
    let mut counts: BTreeMap<char, u64> = BTreeMap::new();
    let n_pw = 3000;
    for _ in 0..n_pw {
        for c in aipass_vault::generator::generate_password(&rules)
            .unwrap()
            .expose()
            .chars()
        {
            *counts.entry(c).or_default() += 1;
        }
    }
    assert_eq!(counts.len(), 62);
    let total: u64 = counts.values().sum();
    let expected = total as f64 / 62.0;
    // chi-square with 61 degrees of freedom; p ≈ 1e-6 critical value ≈ 125
    let chi: f64 = counts
        .values()
        .map(|&c| (c as f64 - expected).powi(2) / expected)
        .sum();
    assert!(chi < 125.0, "chi-square {chi} too large: {counts:?}");
    // first-position distribution is not skewed either
    let mut first: BTreeMap<char, u64> = BTreeMap::new();
    for _ in 0..6200 {
        let p = aipass_vault::generator::generate_password(&rules).unwrap();
        *first.entry(p.expose().chars().next().unwrap()).or_default() += 1;
    }
    assert!(first.values().all(|&c| c > 40 && c < 180), "{first:?}");
    // uniqueness
    let a = aipass_vault::generator::generate_password(&PasswordRules::default()).unwrap();
    let b = aipass_vault::generator::generate_password(&PasswordRules::default()).unwrap();
    assert_ne!(a, b);
}
