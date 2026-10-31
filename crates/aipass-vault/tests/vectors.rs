// SPDX-License-Identifier: Apache-2.0
//! Vault test vectors in `open-source/test-vectors/vault/` (fixed seeds). Deterministic
//! files are regenerated and compared on every run (`AIPASS_REGEN_VECTORS=1` rewrites
//! them); the HPKE file is generated once (HPKE uses a fresh ephemeral key) and verified
//! by opening it.

use aipass_crypto::{
    Argon2Params, DeviceIdentity, KemKeypair, Key32, SealedBox, SecretString, aead, b64u,
};
use aipass_types::canonical::to_jcs_bytes;
use aipass_types::ids::{DeviceId, EntryId, PairingId, VaultId};
use aipass_types::time::parse_rfc3339;
use aipass_types::vault::*;
use aipass_vault::RecoveryKey;
use aipass_vault::encoding::object_bytes;
use aipass_vault::entry::encrypt_entry_with;
use aipass_vault::keys::{recovery_kek, wrap_recovery_with_nonce};
use aipass_vault::member::{recovery_device_id, recovery_identity};
use aipass_vault::pairing::derive_pairing_secrets;
use serde_json::{Value, json};

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/vault")
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn check_generated(name: &str, generated: &Value) {
    std::fs::create_dir_all(dir()).unwrap();
    let path = dir().join(name);
    if std::env::var_os("AIPASS_REGEN_VECTORS").is_some() || !path.exists() {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        &on_disk, generated,
        "test-vectors/vault/{name} is stale (AIPASS_REGEN_VECTORS=1 to regenerate)"
    );
}

const VAULT: &str = "vlt_01jbz3k6w8a7m2q4t5v9x0y1z0";
const ENTRY: &str = "ent_01jbz3k6w8a7m2q4t5v9x0y1z5";
const DEVICE: &str = "dev_01jbz3k6w8a7m2q4t5v9x0y1z6";
const TS: &str = "2026-10-30T12:00:00Z";

fn device() -> DeviceIdentity {
    DeviceIdentity::from_parts(&seq::<32>(0x60), &seq::<32>(0x80))
}

fn payload() -> EntryPayload {
    let t = parse_rfc3339(TS).unwrap();
    let mut p = EntryPayload::new(EntryKind::Login, "Example");
    p.username = Some("alice@example.com".into());
    p.secret = Some(SecretString::from("correct horse battery staple"));
    p.urls = vec!["https://example.com/login".into()];
    p.lifecycle = Lifecycle::Verified;
    p.created_at = t;
    p.updated_at = t;
    p
}

#[test]
fn recovery_key_vector() {
    let secret = seq::<32>(0x40);
    let k = RecoveryKey::from_bytes(secret);
    let vault = VaultId::parse(VAULT).unwrap();
    let rid = recovery_identity(&secret, &vault);
    let kek = recovery_kek(&secret, &vault);
    let v = json!({
        "description": "Recovery key (CONTRACTS §2.4): secret ‖ sha256(secret)[0..2] → Crockford base32 → AIPR- + groups of 4. KEK = HKDF-SHA256(ikm=secret, salt=UTF-8(vault_id), info='aipass/v1/recovery-kek'). Recovery member identity: seed = HKDF(secret, vault_id, 'aipass/v1/recovery-sign'), kem = HKDF(secret, vault_id, 'aipass/v1/recovery-kem'); device id = dev_ + ULID(sha256('aipass/v1/recovery-device-id' ‖ sign_pk)[0..16]).",
        "secret": b64u::encode(secret),
        "vault_id": VAULT,
        "formatted": k.format().expose(),
        "parse_inputs_equivalent": [k.format().expose().to_lowercase().replace('-', " "), k.format().expose()[5..].replace('0', "O")],
        "kek": b64u::encode(kek.expose()),
        "recovery_sign_pk": b64u::encode(rid.public().sign_pk),
        "recovery_kem_pk": b64u::encode(rid.public().kem_pk),
        "recovery_device_id": recovery_device_id(&rid.public().sign_pk).to_string(),
    });
    for alt in v["parse_inputs_equivalent"].as_array().unwrap() {
        assert_eq!(RecoveryKey::parse(alt.as_str().unwrap()).unwrap(), k);
    }
    check_generated("recovery-key.json", &v);
}

#[test]
fn entry_encryption_vector() {
    let vault = VaultId::parse(VAULT).unwrap();
    let entry = EntryId::parse(ENTRY).unwrap();
    let dev = DeviceId::parse(DEVICE).unwrap();
    let vmk = Key32::from_bytes(seq(0xa0));
    let dek = Key32::from_bytes(seq(0xc0));
    let dek_nonce = seq::<24>(0x10);
    let nonce = seq::<24>(0x30);
    let p = payload();
    let t = parse_rfc3339(TS).unwrap();
    let s = encrypt_entry_with(
        &vault, 1, &vmk, &entry, 1, &p, &dev, &t, &dek, &dek_nonce, &nonce,
    )
    .unwrap();
    let pt = p.to_plaintext().unwrap();
    let v = json!({
        "description": "Entry version (CONTRACTS §2.3): wrapped_dek = XChaCha20Poly1305(VMK[epoch], dek_nonce, DEK, aad_dek); ciphertext = XChaCha20Poly1305(DEK, nonce, JCS(EntryPayload), aad_entry). Stored object bytes are JCS; manifest hash = b64u(sha256(object bytes)).",
        "vault_id": VAULT, "entry_id": ENTRY, "version": 1, "key_epoch": 1, "author_device_id": DEVICE, "created_at": TS,
        "vmk": b64u::encode(vmk.expose()),
        "dek": b64u::encode(dek.expose()),
        "dek_nonce": b64u::encode(dek_nonce),
        "nonce": b64u::encode(nonce),
        "aad_dek": aad::dek(&vault, &entry, 1, 1),
        "aad_entry": aad::entry(&vault, &entry, 1),
        "payload_jcs": String::from_utf8(pt.to_vec()).unwrap(),
        "object_jcs": String::from_utf8(s.bytes.clone()).unwrap(),
        "object_hash": s.hash,
    });
    // decrypting the vector with the contract formula
    let ev: EntryVersion = serde_json::from_slice(&s.bytes).unwrap();
    let dek2 = aead::unwrap_key(
        &vmk,
        &ev.dek_nonce,
        aad::dek(&vault, &entry, 1, 1).as_bytes(),
        &ev.wrapped_dek,
    )
    .unwrap();
    let back = aead::open(
        &dek2,
        &ev.nonce,
        aad::entry(&vault, &entry, 1).as_bytes(),
        &ev.ciphertext,
    )
    .unwrap();
    assert_eq!(back.expose(), &pt[..]);
    check_generated("entry-encryption.json", &v);
}

#[test]
fn recovery_wrap_vector() {
    let vault = VaultId::parse(VAULT).unwrap();
    let secret = seq::<32>(0x40);
    let kek = recovery_kek(&secret, &vault);
    let vmk = Key32::from_bytes(seq(0xa0));
    let w = wrap_recovery_with_nonce(
        &vmk,
        &vault,
        1,
        RecoveryKind::RecoveryKey,
        KdfSpec::HkdfSha256,
        &kek,
        &seq::<24>(0x50),
    )
    .unwrap();
    let v = json!({
        "description": "recovery/<epoch>-recovery_key.json: wrapped_vmk = XChaCha20Poly1305(KEK, nonce, VMK, aad = aipass:v1:recovery:{vault_id}:{epoch}:{kind}).",
        "recovery_secret": b64u::encode(secret),
        "kek": b64u::encode(kek.expose()),
        "vmk": b64u::encode(vmk.expose()),
        "aad": aad::recovery(&vault, 1, RecoveryKind::RecoveryKey),
        "object_jcs": String::from_utf8(object_bytes(&w).unwrap()).unwrap(),
    });
    assert_eq!(
        aipass_vault::keys::open_recovery(&w, &kek, &vault).unwrap(),
        vmk
    );
    check_generated("recovery-wrap.json", &v);
}

#[test]
fn signed_objects_vector() {
    let vault = VaultId::parse(VAULT).unwrap();
    let dev = DeviceId::parse(DEVICE).unwrap();
    let id = device();
    let t = parse_rfc3339(TS).unwrap();
    let mut header = VaultHeader {
        format: 1,
        vault_id: vault.clone(),
        created_at: t,
        genesis_device_id: dev.clone(),
        signature: String::new(),
    };
    header.sign_with(&id).unwrap();
    // wrapped_vmk is a fixed placeholder (real wraps are HPKE with a fresh ephemeral key)
    let placeholder = SealedBox {
        enc: seq::<32>(0x11).to_vec(),
        ct: seq::<48>(0x22).to_vec(),
    };
    let mut member = MemberRecord {
        format: 1,
        vault_id: vault.clone(),
        device_id: dev.clone(),
        rev: 1,
        name: "Laptop".into(),
        platform: Platform::Macos,
        role: MemberRole::Owner,
        sign_pk: id.public().sign_pk,
        kem_pk: id.public().kem_pk,
        status: MemberStatus::Active,
        key_epoch: 1,
        wrapped_vmk: Some(placeholder),
        added_by: dev.clone(),
        created_at: t,
        signature: String::new(),
    };
    member.sign_with(&id).unwrap();
    let member_bytes = object_bytes(&member).unwrap();
    let entry = EntryId::parse(ENTRY).unwrap();
    let mut manifest = Manifest {
        format: 1,
        vault_id: vault.clone(),
        seq: 1,
        prev_hash: String::new(),
        key_epoch: 1,
        entries: [(
            entry.clone(),
            ManifestEntry {
                version: 1,
                hash: "xR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE".into(),
                conflict_versions: vec![],
            },
        )]
        .into_iter()
        .collect(),
        tombstones: Default::default(),
        members: [(
            dev.clone(),
            ManifestMember {
                rev: 1,
                hash: object_hash(&member_bytes),
                status: MemberStatus::Active,
                role: MemberRole::Owner,
            },
        )]
        .into_iter()
        .collect(),
        author_device_id: dev.clone(),
        created_at: t,
        signature: String::new(),
    };
    manifest.sign_with(&id).unwrap();
    let v = json!({
        "description": "Signed objects: signature = Ed25519(device, JCS(object minus 'signature')). Device seed 0x60..0x7f, KEM secret 0x80..0x9f.",
        "device_sign_pk": b64u::encode(id.public().sign_pk),
        "device_kem_pk": b64u::encode(id.public().kem_pk),
        "vault_json": String::from_utf8(object_bytes(&header).unwrap()).unwrap(),
        "vault_json_signing_bytes": String::from_utf8(header.signing_bytes().unwrap()).unwrap(),
        "member_record": String::from_utf8(member_bytes.clone()).unwrap(),
        "member_record_hash": object_hash(&member_bytes),
        "manifest": String::from_utf8(object_bytes(&manifest).unwrap()).unwrap(),
        "manifest_signing_bytes": String::from_utf8(manifest.signing_bytes().unwrap()).unwrap(),
        "manifest_hash": object_hash(&object_bytes(&manifest).unwrap()),
        "storage_keys": {
            "member": keys::member(&dev, 1),
            "entry": keys::entry(&entry, 1),
            "manifest": keys::manifest(1),
            "recovery": keys::recovery(1, RecoveryKind::RecoveryKey),
            "keyring": keys::keyring(2)
        }
    });
    header.verify_signature(&id.public().sign_pk).unwrap();
    member.verify_signature(&id.public().sign_pk).unwrap();
    manifest.verify_signature(&id.public().sign_pk).unwrap();
    check_generated("signed-objects.json", &v);
}

#[test]
fn pairing_sas_vector() {
    let pid = PairingId::parse("pair_01jbz3k6w8a7m2q4t5v9x0y1z9").unwrap();
    let relay = "https://relay.aipass.example";
    let e_n = KemKeypair::from_secret_bytes(&seq::<32>(0x01));
    let e_o = KemKeypair::from_secret_bytes(&seq::<32>(0x21));
    let shared = e_o.diffie_hellman(&e_n.public_key()).unwrap();
    assert_eq!(shared, e_n.diffie_hellman(&e_o.public_key()).unwrap());
    let th =
        aipass_types::pairing::transcript_hash(&pid, &e_n.public_key(), &e_o.public_key(), relay)
            .unwrap();
    let secrets = derive_pairing_secrets(&shared, &th).unwrap();
    let k =
        aipass_crypto::kdf::hkdf_sha256(&th, shared.expose(), aipass_crypto::info::PAIRING_KEY, 32)
            .unwrap();
    let v = json!({
        "description": "Pairing (CONTRACTS §5): shared = X25519(eO, eN); th = SHA-256(JCS({pairing_id, eN, eO, relay})); K = HKDF(shared, salt=th, info='aipass/v1/pairing-key'); SAS = u32_be(HKDF(shared, salt=th, info='aipass/v1/pairing-sas', 4 bytes)) mod 1e6, zero-padded.",
        "pairing_id": pid.to_string(),
        "relay": relay,
        "eN_secret": b64u::encode(seq::<32>(0x01)), "eN": e_n.public_key_b64u(),
        "eO_secret": b64u::encode(seq::<32>(0x21)), "eO": e_o.public_key_b64u(),
        "transcript_jcs": String::from_utf8(to_jcs_bytes(&json!({"pairing_id": pid.to_string(), "eN": e_n.public_key_b64u(), "eO": e_o.public_key_b64u(), "relay": relay})).unwrap()).unwrap(),
        "th": b64u::encode(th),
        "shared": b64u::encode(shared.expose()),
        "k": b64u::encode(k.expose()),
        "sas": secrets.sas(),
        "aad_join": aipass_vault::pairing::join_aad(&pid),
    });
    assert_eq!(
        aipass_crypto::sha256(v["transcript_jcs"].as_str().unwrap().as_bytes()),
        th
    );
    check_generated("pairing-sas.json", &v);
}

#[test]
fn encrypted_export_vector() {
    let pw = "export-password-123";
    let salt = seq::<16>(0x00);
    let nonce = seq::<24>(0x70);
    let p = Argon2Params::CONTRACT_V1;
    let key = aipass_crypto::password::argon2id(pw.as_bytes(), &salt, p).unwrap();
    let body = aipass_vault::export::ExportBody {
        vault_id: VaultId::parse(VAULT).unwrap(),
        entries: vec![aipass_vault::export::ExportEntry {
            entry_id: EntryId::parse(ENTRY).unwrap(),
            version: 1,
            payload: payload(),
        }],
    };
    let pt = to_jcs_bytes(&body).unwrap();
    let ct = aead::seal_with_nonce(
        &key,
        &nonce,
        aipass_vault::export::EXPORT_AAD.as_bytes(),
        &pt,
    )
    .unwrap();
    let file = json!({
        "format": "aipass-export-1",
        "created_at": TS,
        "kdf": {"alg": "argon2id", "m": p.m, "t": p.t, "p": p.p, "salt": b64u::encode(salt)},
        "nonce": b64u::encode(nonce),
        "ciphertext": b64u::encode(&ct),
    });
    let file_bytes = to_jcs_bytes(&file).unwrap();
    let opened =
        aipass_vault::export::import_encrypted(&file_bytes, &SecretString::from(pw)).unwrap();
    assert_eq!(opened, body);
    let v = json!({
        "description": ".aipassx (CONTRACTS §2.5): ciphertext = XChaCha20Poly1305(Argon2id(password, salt, m=65536,t=3,p=1), nonce, JCS({vault_id, entries:[{entry_id, version, payload}]}), aad='aipass:v1:export:aipass-export-1').",
        "password": pw,
        "key": b64u::encode(key.expose()),
        "body_jcs": String::from_utf8(pt).unwrap(),
        "file_jcs": String::from_utf8(file_bytes).unwrap(),
    });
    check_generated("export.json", &v);
}

#[test]
fn vmk_wrap_roundtrip_vector() {
    std::fs::create_dir_all(dir()).unwrap();
    let path = dir().join("vmk-wrap-hpke.json");
    let vault = VaultId::parse(VAULT).unwrap();
    let dev = DeviceId::parse(DEVICE).unwrap();
    let id = device();
    let vmk = Key32::from_bytes(seq(0xa0));
    if std::env::var_os("AIPASS_REGEN_VECTORS").is_some() || !path.exists() {
        let sealed =
            aipass_vault::keys::seal_vmk(&vmk, &vault, &dev, 1, &id.public().kem_pk).unwrap();
        let v = json!({
            "description": "VMK sealed to a member device: HPKE RFC 9180 base mode DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305, info='aipass/v1/vmk-wrap', aad='aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}'. HPKE uses a fresh ephemeral key, so this file is a decrypt-only vector: open `sealed` with the recipient KEM secret.",
            "recipient_kem_secret": b64u::encode(seq::<32>(0x80)),
            "recipient_kem_pk": b64u::encode(id.public().kem_pk),
            "aad": aad::vmk_wrap(&vault, &dev, 1),
            "vmk": b64u::encode(vmk.expose()),
            "sealed": sealed,
        });
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let sealed: SealedBox = serde_json::from_value(v["sealed"].clone()).unwrap();
    let opened = aipass_vault::keys::open_vmk(id.kem_keypair(), &vault, &dev, 1, &sealed).unwrap();
    assert_eq!(b64u::encode(opened.expose()), v["vmk"].as_str().unwrap());
}
