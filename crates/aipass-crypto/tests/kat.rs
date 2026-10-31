// SPDX-License-Identifier: Apache-2.0
//! Known-answer tests against published vectors:
//! * draft-irtf-cfrg-xchacha-03 §A.3.1 (AEAD_XCHACHA20_POLY1305)
//! * RFC 8439 §2.8.2 (AEAD_CHACHA20_POLY1305 — the AEAD inside our HPKE suite)
//! * RFC 8032 §7.1 TEST 1–3 (Ed25519)
//! * RFC 5869 Appendix A.1–A.3 (HKDF-SHA256)
//! * RFC 9106 §5.3 (Argon2id)
//!
//! plus the repository vector file `test-vectors/xchacha.json`.

use aipass_crypto::{Key32, aead, identity, kdf, password};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s.replace([' ', '\n'], "")).expect("hex")
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    h(s).try_into().expect("length")
}

#[test]
fn xchacha20poly1305_draft_a31() {
    let pt = h(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
                73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
                6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
                637265656e20776f756c642062652069742e",
    );
    let aad = h("50515253c0c1c2c3c4c5c6c7");
    let key = Key32::from_bytes(arr(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    ));
    let nonce: [u8; 24] = arr("404142434445464748494a4b4c4d4e4f5051525354555657");
    let expected_ct = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
                       731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
                       2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
                       21f9664c97637da9768812f615c68b13b52e";
    let expected_tag = "c0875924c1c7987947deafd8780acf49";
    let out = aead::seal_with_nonce(&key, &nonce, &aad, &pt).unwrap();
    let (ct, tag) = out.split_at(out.len() - 16);
    assert_eq!(hex::encode(ct), expected_ct.replace(' ', ""));
    assert_eq!(hex::encode(tag), expected_tag);
    assert_eq!(
        aead::open(&key, &nonce, &aad, &out).unwrap().expose(),
        pt.as_slice()
    );
}

#[test]
fn chacha20poly1305_rfc8439_2_8_2() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let key: [u8; 32] = arr("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce: [u8; 12] = arr("070000004041424344454647");
    let aad = h("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let c = chacha20poly1305::ChaCha20Poly1305::new(&chacha20poly1305::Key::from(key));
    let out = c
        .encrypt(
            &chacha20poly1305::Nonce::from(nonce),
            Payload { msg: pt, aad: &aad },
        )
        .unwrap();
    let (ct, tag) = out.split_at(out.len() - 16);
    assert_eq!(
        hex::encode(ct),
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    );
    assert_eq!(hex::encode(tag), "1ae10b594f09e26a7e902ecbd0600691");
}

#[test]
fn ed25519_rfc8032_tests_1_to_3() {
    let cases = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    for (sk, pk, msg, sig) in cases {
        let kp = identity::Ed25519Keypair::from_seed(&arr(sk));
        assert_eq!(hex::encode(kp.public_key()), pk);
        let m = h(msg);
        let s = kp.sign(&m);
        assert_eq!(hex::encode(s), sig);
        identity::verify(&arr(pk), &m, &arr(sig)).unwrap();
        let mut wrong = m.clone();
        wrong.push(0);
        assert!(identity::verify(&arr(pk), &wrong, &arr(sig)).is_err());
    }
}

#[test]
fn hkdf_sha256_rfc5869() {
    // A.1
    let ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = h("000102030405060708090a0b0c");
    let info = h("f0f1f2f3f4f5f6f7f8f9");
    let prk = kdf::extract(&salt, &ikm);
    assert_eq!(
        hex::encode(prk.expose()),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let okm = kdf::hkdf_sha256(&salt, &ikm, &info, 42).unwrap();
    assert_eq!(
        hex::encode(okm.expose()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    assert_eq!(kdf::expand(prk.expose(), &info, 42).unwrap(), okm);

    // A.2
    let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
    let salt: Vec<u8> = (0x60u8..=0xaf).collect();
    let info: Vec<u8> = (0xb0u8..=0xff).collect();
    let prk = kdf::extract(&salt, &ikm);
    assert_eq!(
        hex::encode(prk.expose()),
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    );
    let okm = kdf::hkdf_sha256(&salt, &ikm, &info, 82).unwrap();
    assert_eq!(
        hex::encode(okm.expose()),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );

    // A.3 (zero-length salt and info)
    let ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let prk = kdf::extract(&[], &ikm);
    assert_eq!(
        hex::encode(prk.expose()),
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    );
    let okm = kdf::hkdf_sha256(&[], &ikm, &[], 42).unwrap();
    assert_eq!(
        hex::encode(okm.expose()),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn argon2id_rfc9106_5_3() {
    let pwd = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];
    let tag = password::argon2id_with_secret(
        &pwd,
        &salt,
        password::Argon2Params { m: 32, t: 3, p: 4 },
        Some(&secret),
        &ad,
    )
    .unwrap();
    assert_eq!(
        hex::encode(tag.expose()),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}

#[test]
fn argon2id_contract_parameters_run() {
    // The real contract parameters (64 MiB, t=3, p=1) — run once to prove they work.
    let k = password::argon2id(
        b"master password",
        &[9u8; 16],
        password::Argon2Params::CONTRACT_V1,
    )
    .unwrap();
    let k2 = password::argon2id(
        b"master password",
        &[9u8; 16],
        password::Argon2Params::CONTRACT_V1,
    )
    .unwrap();
    assert_eq!(k, k2);
}

// ----------------------------------------------------------------------------------------
// Repository vector file: test-vectors/xchacha.json
// ----------------------------------------------------------------------------------------

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn xchacha_vectors() -> serde_json::Value {
    // Vector 1: the draft A.3.1 vector. Vector 2: an AI Pass DEK wrap with the contract AAD.
    let draft_pt = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
    let draft_key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    let draft_nonce = "404142434445464748494a4b4c4d4e4f5051525354555657";
    let draft_aad = "50515253c0c1c2c3c4c5c6c7";
    let mk = |key: &str, nonce: &str, aad: &[u8], pt: &[u8]| {
        let k = Key32::from_bytes(arr(key));
        let n: [u8; 24] = arr(nonce);
        aead::seal_with_nonce(&k, &n, aad, pt).unwrap()
    };
    let v1 = mk(draft_key, draft_nonce, &h(draft_aad), &h(draft_pt));
    let vmk = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let dek = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    let dek_nonce = "0f0e0d0c0b0a09080706050403020100f0f1f2f3f4f5f6f7";
    let aad2 = "aipass:v1:dek:vlt_01jbz3k6w8a7m2q4t5v9x0y1z0:ent_01jbz3k6w8a7m2q4t5v9x0y1z5:1:1";
    let v2 = mk(vmk, dek_nonce, aad2.as_bytes(), &h(dek));
    serde_json::json!({
        "description": "XChaCha20-Poly1305 (AEAD_XCHACHA20_POLY1305, 24-byte nonce). `ciphertext` is ct||tag (16-byte tag appended), hex. Generated and verified by crates/aipass-crypto/tests/kat.rs.",
        "vectors": [
            {
                "name": "draft-irtf-cfrg-xchacha-03 A.3.1",
                "key": draft_key, "nonce": draft_nonce, "aad_hex": draft_aad, "plaintext": draft_pt,
                "ciphertext": hex::encode(&v1)
            },
            {
                "name": "aipass DEK wrap (CONTRACTS §2.3 wrapped_dek)",
                "key": vmk, "nonce": dek_nonce, "aad_utf8": aad2, "plaintext": dek,
                "ciphertext": hex::encode(&v2)
            }
        ]
    })
}

#[test]
fn xchacha_vector_file() {
    let path = vectors_dir().join("xchacha.json");
    let generated = xchacha_vectors();
    if std::env::var_os("AIPASS_REGEN_VECTORS").is_some() || !path.exists() {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(on_disk, generated, "test-vectors/xchacha.json is stale");
    // Independently check every vector decrypts.
    for v in on_disk["vectors"].as_array().unwrap() {
        let key = Key32::from_bytes(arr(v["key"].as_str().unwrap()));
        let nonce: [u8; 24] = arr(v["nonce"].as_str().unwrap());
        let aad = match (v.get("aad_hex"), v.get("aad_utf8")) {
            (Some(x), _) => h(x.as_str().unwrap()),
            (_, Some(x)) => x.as_str().unwrap().as_bytes().to_vec(),
            _ => vec![],
        };
        let pt = aead::open(&key, &nonce, &aad, &h(v["ciphertext"].as_str().unwrap())).unwrap();
        assert_eq!(hex::encode(pt.expose()), v["plaintext"].as_str().unwrap());
    }
    // Vector 1 must equal the draft's published ct||tag.
    assert!(
        on_disk["vectors"][0]["ciphertext"]
            .as_str()
            .unwrap()
            .ends_with("c0875924c1c7987947deafd8780acf49")
    );
}
