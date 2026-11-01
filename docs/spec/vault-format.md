<!-- SPDX-License-Identifier: Apache-2.0 -->
# AI 通行证 · 账号库格式 / AI Pass vault format v1

Status: implemented by `open-source/crates/aipass-vault` (Vault Core) and
`open-source/crates/aipass-sync` (sync engine). Refines CONTRACTS §2, §3.2, §5 and §7.
Test vectors: `open-source/test-vectors/vault/` (fixed seeds; cross-checked with Python
`cryptography`, libsodium/PyNaCl and argon2-cffi).

中文摘要：存储里只有密文、签名清单和成员记录。每个条目版本用独立的数据密钥（DEK）加密，DEK 由账号库主密钥（VMK）封装，VMK 分别用 HPKE 封装给每台可信设备。清单是唯一的提交点，采用"只能新建"的写入；每台设备保存已验证的检查点以识别回滚。恢复密钥额外派生一个"恢复成员"身份，使密钥轮换之后恢复仍然可用，而设备上从不保存恢复密钥本身。

---

## 1. Primitives

| purpose | algorithm | library |
| --- | --- | --- |
| AEAD | XChaCha20-Poly1305, 24-byte random nonce, mandatory AAD | `chacha20poly1305` |
| sealing to a key | HPKE RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 | `hpke` |
| signatures | Ed25519 (strict verification) | `ed25519-dalek` |
| KDF | HKDF-SHA256 | `hkdf` |
| password KDF | Argon2id m=65536 KiB, t=3, p=1, 16-byte salt, 32-byte output | `argon2` |
| canonical JSON | RFC 8785 JCS (no floats, \|n\| < 2^53) | `aipass_types::canonical` |
| randomness | OS CSPRNG only | `getrandom` |

Binary values in JSON are base64url without padding ("b64u"). Timestamps are RFC 3339 UTC
with `Z`, second precision. **Every object AI Pass writes is stored as JCS bytes**, so all
implementations produce identical bytes and hashes; readers hash bytes exactly as fetched.
`hash(x) = b64u(SHA-256(file bytes))`.

## 2. Storage layout (keys relative to the vault root)

| key | object | mutability |
| --- | --- | --- |
| `vault.json` | `VaultHeader` | immutable |
| `members/<device_id>/<rev>.json` | `MemberRecord` | immutable (new rev per change) |
| `recovery/<key_epoch>-<kind>.json` | `RecoveryWrap` | immutable |
| `keyring/<key_epoch>.json` | `KeyringRecord` | immutable |
| `entries/<entry_id>/<version>.json` | `EntryVersion` | immutable |
| `manifests/<seq:012>.json` | `Manifest` — create-only write = **commit point** | immutable |
| `HEAD` | decimal seq — untrusted hint | mutable |

Keys use only `[A-Za-z0-9._-]` segments (no `.`/`..`/empty segments). Backends write
immutable objects with `PutCondition::IfAbsent`. ETags are for concurrency control only.

## 3. Key hierarchy

```
recovery secret (32 B, user only) ──HKDF──► KEK_r ──XChaCha──► recovery/<e>-recovery_key.json
master password (optional) ──Argon2id──► KEK_p ──XChaCha──► recovery/<e>-master_password.json
VMK[e] (32 B random per key epoch) ──HPKE──► members/<dev>/<rev>.json .wrapped_vmk   (owner/member only)
VMK[e] ──XChaCha──► keyring/<e>.json  (all VMK[e' < e])
VMK[e] ──XChaCha──► DEK (32 B random per entry version) ──XChaCha──► entry ciphertext
```

* VMK wrap: `HPKE.seal(kem_pk, info="aipass/v1/vmk-wrap", aad="aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}", VMK)`.
* Recovery KEK: `HKDF-SHA256(ikm=secret, salt=UTF-8(vault_id), info="aipass/v1/recovery-kek", 32)`.
* Recovery wrap: `XChaCha20Poly1305(KEK, nonce, VMK, aad="aipass:v1:recovery:{vault_id}:{key_epoch}:{kind}")`,
  object `{format:1, vault_id, key_epoch, kind:"recovery_key"|"master_password", kdf, nonce, wrapped_vmk}`
  where `kdf` is `{"alg":"hkdf-sha256"}` or `{"alg":"argon2id","m","t","p","salt"}`.
* Keyring: `{format:1, vault_id, key_epoch, previous:[{key_epoch, nonce, wrapped_vmk}], author_device_id, created_at}`,
  every item `XChaCha20Poly1305(VMK[key_epoch], nonce, VMK[item.key_epoch], aad="aipass:v1:keyring:{vault_id}:{key_epoch}")`.
  The item epoch is outside the AEAD (contract AAD); relabelling items only makes decryption fail.
* Executors never receive a VMK (`wrapped_vmk: null`). Vault keys are never derived from
  subscription passwords, email logins or passkey ids.

## 4. Objects

### 4.1 `VaultHeader` (`vault.json`)
`{format:1, vault_id, created_at, genesis_device_id, signature}` — signature by the genesis
device over `JCS(header minus "signature")`.

### 4.2 `MemberRecord`
`{format:1, vault_id, device_id, rev, name, platform, role:"owner"|"member"|"executor", sign_pk, kem_pk, status:"active"|"revoked", key_epoch, wrapped_vmk:SealedBox|null, added_by, created_at, signature}`
signed by `added_by` over `JCS(record minus "signature")`; the genesis record (rev 1) is
self-signed and must be an active owner.

**Executor ids.** Member records use `dev_` ids. An executor node's broker / relay principal
is `exe_X` and its member id is `dev_X` (same ULID part).

**Recovery member.** At vault creation the genesis device enrols a recovery identity as an
active **owner**:
* `sign_seed = HKDF(ikm=secret, salt=UTF-8(vault_id), info="aipass/v1/recovery-sign")`,
  `kem_secret = HKDF(ikm=secret, salt=UTF-8(vault_id), info="aipass/v1/recovery-kem")`;
* `device_id = "dev_" + ULID(first 16 bytes of SHA-256("aipass/v1/recovery-device-id" ‖ sign_pk))`
  (lower-case Crockford, 26 chars) — clients recognise it by recomputing this id;
* name `恢复密钥 / Recovery key`, platform `cli`.
New VMK epochs are sealed to it like to any member, so the recovery key keeps working
after rotations although no device stores the secret. Clients exclude it from approver lists
shown to executors (`pairing.welcome.trusted_devices`).

### 4.3 `EntryVersion`
`{format:1, vault_id, entry_id, version, key_epoch, dek_nonce, wrapped_dek, nonce, ciphertext, author_device_id, created_at}`
* `wrapped_dek = XChaCha20Poly1305(VMK[key_epoch], dek_nonce, DEK, aad="aipass:v1:dek:{vault_id}:{entry_id}:{version}:{key_epoch}")`
* `ciphertext = XChaCha20Poly1305(DEK, nonce, JCS(EntryPayload), aad="aipass:v1:entry:{vault_id}:{entry_id}:{version}:1")`
* Decryption computes both AADs from the **expected location** (storage key / manifest),
  never from the object's own fields: moving a ciphertext to another entry, version or
  epoch fails authentication.
* Version numbers are unique per entry and increasing, but may have gaps (orphans of failed
  commits are skipped).

### 4.4 `EntryPayload` (plaintext only inside `ciphertext`)
As CONTRACTS §2.3. Secret-bearing fields: `secret`, `totp`, `fields[sensitive=true]`.
Titles, usernames, URLs, notes and tags are encrypted too.

### 4.5 `Manifest`
`{format:1, vault_id, seq, prev_hash, key_epoch, entries:{entry_id:{version, hash, conflict_versions:[]}}, tombstones:{entry_id:{version, deleted_at}}, members:{device_id:{rev, hash, status, role}}, author_device_id, created_at, signature}`
* `prev_hash` = hash of manifest `seq-1` (`""` for seq 1); `entries.hash` = hash of the
  current version object; `members.hash` = hash of the listed member record.
* `conflict_versions` reference additional version objects of the same entry (integrity
  through the location-bound AEAD; they are not hash-listed).
* signature by the author over `JCS(manifest minus "signature")`.

## 5. Manifest chain rules (verified by every device on pull)

For manifest `n` after verified view `p` (`p` = "genesis only" before seq 1):

1. `format == 1`, same `vault_id`, `seq == p.seq + 1`, `prev_hash == hash(p)`.
2. The author is an **active owner/member of `p`**; the signature verifies with its key.
   Executors and revoked devices never author manifests.
3. `key_epoch` never decreases; only owners bump it; a bump must re-seal the new VMK to
   every active owner/member (each gets a record with `key_epoch == n.key_epoch`).
4. Members are never dropped. A changed member must list a record that matches its hash,
   vault, id, rev, status and role, is signed by an active owner/member of `p`, keeps its
   `sign_pk`, `kem_pk` and platform, and has rev > previous rev. A revoked device can never
   become active again. Role or status changes and adding owners require an owner signer.
   Revoking an owner/member requires a key-epoch bump in the same manifest. Executors and
   revoked members carry no VMK; active owners/members carry one with `key_epoch ≤ n.key_epoch`.
   At least one active owner remains.
5. Entries never disappear without a tombstone; versions never decrease (same version ⇒
   same hash); a tombstone's version is ≥ the deleted entry's highest version; tombstones
   are permanent unless the entry is **restored with a version greater than the tombstone**;
   an id is never both live and deleted; conflict versions are distinct and ≠ current.
6. Every entry version first introduced by `n` must be encrypted under `n.key_epoch`
   (after a rotation, revoked devices cannot read new versions), its author must be an
   owner/member, and its hash must match.

## 6. Sync protocol (aipass-sync)

**Checkpoint.** Each device persists `{vault_id, seq, hash}` of its newest verified
manifest (`state.json`) and keeps the verified objects in its local cache.

**Pull.** (1) `manifests/<checkpoint.seq>` must still exist with the checkpoint hash —
otherwise `ROLLBACK_DETECTED` and the device refuses to write (flag persisted until storage
is consistent again). (2) List `manifests/` after the checkpoint, then probe `seq+1`
directly (listing lag). (3) Verify each manifest in order (§5); a gap is
`INTEGRITY_FAILED`. (4) Fetch and verify changed member records, entry versions and keyrings;
cache only verified objects. A fresh device without a checkpoint verifies the whole chain
from `vault.json`, but cannot detect a storage that was rolled back *as a whole* (design
doc §10.4 limitation; pairing passes the trusted device's checkpoint, which *is* checked).

**Commit.** On top of the freshly pulled view the planner stages objects; the engine
self-verifies the manifest, writes every object `IfAbsent` (an existing object with
different bytes is an orphan → the version / rev / epoch is skipped and the plan re-run),
then writes `manifests/<seq+1>` `IfAbsent`. `PreconditionFailed` → pull, re-plan, retry
(8 attempts). `HEAD` is updated best-effort.

**Offline edits.** Local changes are queued in `outbox.json`:
`{format:"aipass-outbox-1", nonce, ciphertext}` with
`ciphertext = XChaCha20Poly1305(local_key, nonce, JCS({changes, rejected}), aad="aipass:v1:outbox:{vault_id}:{device_id}")`;
`local_key` (32 random bytes) lives in the platform secret store. Several edits of one entry
are coalesced keeping the original `base_version`.

**3-way merge.** If the entry's current version ≠ the change's base version: per field
against the base payload — one-sided changes win; **secret-bearing** fields changed on both
sides to different values → the merged current keeps the remote secrets, the local payload
is written as an extra version and appended to `conflict_versions`; automatic use of the
entry pauses (`SYNC_CONFLICT` in broker, autofill and extension) until a trusted client
resolves it by keeping one version (written as a new current version, conflicts cleared,
refused if the entry changed meanwhile). Other fields: remote wins, except notes, which are
concatenated with `--- 冲突副本 / conflict copy ---`.

**Tombstones.** Edits of an entry tombstoned elsewhere are rejected and kept locally as
"rejected changes" for an explicit restore (new version above the tombstone) or discard.
A delete of an entry edited elsewhere is skipped (the edit wins, no data loss).

**Offline limit.** If the last membership verification is older than 90 days, the device
re-checks the pinned `vault.json` against storage and its own active membership before
pushing.

**Revocation.** An owner writes a revoked record (rev+1, no VMK), a new VMK epoch sealed to
every remaining owner/member (incl. the recovery member) and `keyring/<new>.json`. Future
versions use the new epoch. The client lists rotation tasks for long-term credentials the
revoked device could read; data it already had cannot be remotely erased. A revoked device
that syncs learns its status, drops keys, cache, outbox and secrets (best effort).

## 7. Recovery key & kit

`32 random bytes ‖ SHA-256(bytes)[0..2]` → upper-case Crockford base32 (55 chars, trailing
bits zero) → `AIPR-` + 13 groups of 4 + 1 group of 3, joined by `-`. Parsing ignores case,
whitespace and dashes, maps O→0 and I/L→1, rejects other characters, verifies the checksum.

Recovery on a fresh device: verify `vault.json` + the chain → derive the recovery identity
→ open the VMK from the recovery member's wrap (fallback: `recovery/<e>-recovery_key.json`)
→ as the recovery member, enrol the new device as an owner → open as the new device → the
user revokes the lost device. HTTP sync storage authenticates the recovery steps with the
recovery identity (it is an active member).

The kit (text, zh-CN + en) contains vault id, recovery key, creation time, the non-secret
storage profile and instructions; the storage access secret only when the user opts in. The
formatted key is kept in the secret store (`aipass.recovery-pending.<vault_id>`, user
presence) only until the user re-enters it (recovery verification); afterwards it exists only
on the user's kit. A new recovery key revokes the old recovery member with a key rotation.

Master password (optional): `recovery/<e>-master_password.json` with Argon2id; wraps are
immutable per epoch, so changing the password rotates the key epoch.

## 8. Pairing (CONTRACTS §5)

QR: `aipass://pair?v=1&p=<pairing_id>&s=<b64u 16B>&k=<b64u eN>&r=<relay>&n=<name>&t=<member|executor>&e=<unix expiry>` (TTL 600 s).

```
shared = X25519(eO, eN)
th     = SHA-256(JCS({"pairing_id", "eN", "eO", "relay"}))          (eN/eO b64u)
K      = HKDF-SHA256(ikm=shared, salt=th, info="aipass/v1/pairing-key", 32)
SAS    = u32_be(HKDF-SHA256(ikm=shared, salt=th, info="aipass/v1/pairing-sas", 4)) mod 1_000_000, 6 digits
```

All messages travel through the `pair_<id>` relay mailbox in signed `RelayEnvelope`s:

| step | envelope | K-sealed box AAD |
| --- | --- | --- |
| `pairing.hello` O→N | HPKE to `eN`, signed by O | `aipass:v1:pairing:hello:{pairing_id}:{b64u(SHA-256(JCS(o_device)))}` |
| `pairing.join` N→O | HPKE to O's `kem_pk`, signed by N (verified with the key inside the box) | `aipass:v1:pairing:join:{pairing_id}` |
| `pairing.welcome` O→N | HPKE to N's `kem_pk`, signed by O | `aipass:v1:pairing:welcome:{pairing_id}:{n_device_id}` |

The user confirms on O (ideally by typing the code shown on N; a mismatch cancels). Only
then O commits N's member record (owners enrol new trusted devices as owners; executors get
role `executor` and no VMK) and sends the welcome `{vault_id, member_rev, checkpoint,
storage_profile, storage_secret?, relay_base_url, trusted_devices}` (storage secrets never go
to executors). N verifies `vault.json`, the whole chain, that its chain contains the welcome
checkpoint (seq and hash), and its own active record before installing the vault.

## 9. Approvals (CONTRACTS §7)

The trusted client recomputes the digest from the displayed request through
`aipass_types::approval`, signs `aipass:v1:approval:<approve|deny>:<digest>` and, for
approvals, seals `CredentialMaterial {entry_id, version, kind, username?, secret, database?, expires_at}`
to the executor's `kem_pk` with `info="aipass/v1/credential"`,
`aad=JCS({approval_request_id, digest, executor_id})`. The executor key comes from a trusted
source: its vault member record (`exe_X` ⇔ `dev_X`, active, role executor) or an explicitly
registered in-process executor. Requests past `expires_at` are never approved; entries with
conflicts are refused; `storage_credential` entries are never delivered.

## 10. Exports

`.aipassx`: `{format:"aipass-export-1", created_at, kdf:{alg:"argon2id",m,t,p,salt}, nonce, ciphertext}`,
`ciphertext = XChaCha20Poly1305(Argon2id(password, salt), nonce, JCS({vault_id, entries:[{entry_id, version, payload}]}), aad="aipass:v1:export:aipass-export-1")`
(export password ≥ 10 characters). Importing creates unknown ids only; existing or deleted
ids are reported as duplicates (never resurrected).

CSV: `title,url,username,password,notes,totp,kind` (TOTP as `otpauth://` URI), CRLF; the
client re-authenticates and shows the plaintext warning. Never offered to AI.

## 11. Local device layout (aipass-sync `VaultClient`)

```
<data_dir>/device.json   {format, device_id, name, platform, role, sign_pk, kem_pk, created_at, app_version}
<data_dir>/state.json    {format, vault_id, storage, checkpoint, last_sync_at, membership_verified_at,
                          recovery_verified_at, rollback_detected, revoked, relay_base_url, last_error,
                          resource_bindings, known_executors, pending_objects, rotation_tasks, created_at}
<data_dir>/outbox.json   encrypted outbox (§6)
<data_dir>/cache/<key>   verified storage objects (same keys as storage)
```
Files are written atomically with mode 0600 (directories 0700). Secret-store keys:
`aipass.device.<device_id>` (64 B Ed25519 seed ‖ X25519 secret, user presence),
`aipass.local.<vault_id>`, `aipass.storage.<vault_id>`, `aipass.recovery-pending.<vault_id>`.

`FileSecretStore` file: `{format:"aipass-secrets-1", kdf:{alg:"argon2id",m,t,p,salt}, nonce, ciphertext}`
with `aad="aipass:v1:secret-store"` over the JSON map of entries.
