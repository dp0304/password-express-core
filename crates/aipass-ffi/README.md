<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-ffi — 移动端 FFI 层 / Mobile FFI layer

AI 通行证的 iOS / Android 原生 App 通过本 crate 调用同一个 Rust 核心（保险库、同步、配对、审批）。
绑定由 [uniffi](https://mozilla.github.io/uniffi-rs/) 0.32 proc-macro 生成：Swift 模块 `AIPassCore`，
Kotlin 包 `com.aipass.core`（CONTRACTS §12）。

The iOS / Android apps use this crate to reach the shared Rust core (vault, sync, pairing,
approvals). Bindings are generated with uniffi 0.32 proc-macros: Swift module `AIPassCore`,
Kotlin package `com.aipass.core` (CONTRACTS §12).

Only `reveal_secret`, `autofill_credential`, `generate_password`, `totp_now` and the one-time
recovery key of `create_vault` / `replace_recovery_key` return secret material. The native
app must require biometrics or the device passcode immediately before `reveal_secret` and
`autofill_credential`. Keep their results out of AI tools, logs, analytics and WebViews,
and drop them from memory after use.

## Architecture

```
native app ──uniffi──► AipassCore ──► aipass_sync::VaultClient ──► aipass-vault / aipass-storage
   │  ▲                    │
   │  └─ SecretStore ◄─────┤ (callback: Keychain / Keystore; device key with user presence)
   │                       ├─► relay: aipass_storage::RelayClient (HTTPS, AIPass-Sig as dev_…)
   │                       │          or LocalRelay (in-process, tests / demos)
   └─ PairingSession ◄─────┘ (SAS-confirmed device / executor pairing, §5)
```

| file | role |
| --- | --- |
| `src/core.rs` | `AipassCore` object: vault, items, import/export, sync, recovery, devices, storage, autofill, relay inbox, approvals, control, license |
| `src/secret_store.rs` | `SecretStore` callback interface (`#[uniffi::export(with_foreign)]`) + adapter to `aipass_vault::SecretStore`; remembers the device key handed to the core while unlocked so relay requests can be signed without a second biometric prompt (zeroized on `lock()`) |
| `src/pairing.rs` | `PairingSession` for both roles |
| `src/relay.rs` | relay selection (HTTPS `RelayClient` / `LocalRelay`) |
| `src/license.rs` | offline Ed25519 license verification (§13 token format) |
| `src/types.rs` | every record crossing the boundary + conversions |
| `src/error.rs` | `CoreError { code, message }`, `SecretStoreError` |
| `src/test_support.rs` | `TestExecutor` fake broker / executor — feature `test-support` only, **never shipped** |

Conventions: ids are prefixed strings (`ent_…`, `dev_…`, `apr_…`); enum values are the
snake_case strings of the JSON contract (`"login"`, `"sync_capable"`, `"approve"`);
timestamps are Unix seconds (`i64`). Async methods run on uniffi's tokio runtime.
Error messages are zh-CN by default; `set_locale("en")` switches to English.

The FFI layer keeps a small `ffi-state.json` (no secrets) in `data_dir`: relay URL, inbox
cursor, decrypted approval requests (metadata), resource → entry bindings, last snapshot,
revocation reports and the last valid license token.

## API (summary — full docs are in the generated bindings)

**Lifecycle** — `AipassCore(dataDir, secretStore, platform, appVersion)`, `setLocale`,
`hasVault`, `status() -> CoreStatus`, `createVault(deviceName, storage, storageSecret?)`,
`unlock()` (after native biometrics; offline OK), `lock()`, `isUnlocked()`.

**Items** — `listItems(query?, projectId?)`, `getItem(id)` (masked), `revealSecret(id, field)`
(`"secret"` | `"totp"` | `"field:<name>"`), `saveItem(ItemInputFfi)`, `deleteItem`,
`generatePassword(PasswordRulesFfi)` / `defaultPasswordRules()`, `totpNow(id)`.

**Import / export** — `importCsv(format, bytes)` (`chrome` `firefox` `safari` `bitwarden`
`1password` `lastpass` `generic`; remind the user to delete the CSV), `exportEncrypted(password)`,
`importEncrypted(bytes, password)`.

**Sync** — `sync() -> SyncReportFfi` (`ok` | `offline` | `conflict` | `rollback_detected` |
`error`; network trouble is `offline`, not an exception), `conflicts()`,
`resolveConflict(id, keepVersion)`.

**Recovery** — `verifyRecoveryKey(key)`, `recoveryKitText()`, `replaceRecoveryKey()`,
`setMasterPassword(pw)`, `recoverWithKey(vaultId, storage, storageSecret?, recoveryKey, deviceName)`.

**Devices** — `devices()`, `revokeDevice(id)` (rotates the key epoch; old copies may still
exist — show `note` and `rotationTasks`), `rotationTasks()`, `dismissRotationTask(id)`.

**Storage** — `testStorage(profile, secret?) -> CapabilityReportFfi` (`sync_capable` |
`backup_only`), `migrateStorage(profile, secret?)` (only to `sync_capable`; old copy kept).

**AutoFill** — `autofillCandidates(serviceIdentifier)`, `autofillCredential(id)` (user
presence first; `SYNC_CONFLICT` while conflicted), `allCredentialIdentities()` (for
`ASCredentialIdentityStore` / Android Autofill), `saveFromAutofill(origin, username?, password, formKind)`.

**Pairing** — new device: `pairingOffer(deviceName) -> PairingSession`, render
`qrPayload()`, `wait(0)` → stage `confirm_code` + `sas`, then `confirm()` (waits for the
trusted device's confirmation, verifies and installs the vault). Trusted device:
`pairingScan(qr)`, `wait(0)` → `confirm_code` + `sas`; after the user compared both codes,
`confirm()` (or `confirmCode(codeOnNewDevice)`). `cancel()` at any time. Scanning alone never
grants access; executors never receive the VMK or the storage secret.

**Relay, approvals & control** — `setRelay(baseUrl)` (https; http only for loopback) or
`setLocalRelay(LocalRelay)`; `bindResource(resourceId, entryId)`; `fetchInbox() ->
[ApprovalRequestFfi]` (decrypts `approval.request` addressed to this device, drops
unverifiable senders **and requests whose `executor.executor_id` is not the relay sender**;
a request id already pending is never replaced — a copy with different content keeps the
first one and sets `conflict = true`; `approval.cancelled` is honoured only from the
original sender); `pendingApprovals()`, `pendingConnections()`;
`approve(aprId, requestDigest, narrowed?)` / `approveWithEntry(aprId, requestDigest,
narrowed?, entryId)` — `requestDigest` is the `ApprovalRequestFfi.requestDigest` of the
request **shown on screen**; the stored request must still hash to it and must not be in
`conflict`, else `INTEGRITY_FAILED` (nothing is bound, signed or sent); then recompute the
§7 **v2** digest (binding `operationId` + `parametersDigest` for operation requests), sign,
seal the credential to the executor's member key and post `approval.decision`;
`deny(aprId, requestDigest)` (same digest check; a conflicting request can still be denied); `snapshot(executorId?)`, `lastSnapshot()`;
`revokeGrant(grantId, level)` (`stop_access` | `end_sessions` | `revoke_upstream`; when the
broker does not answer within 20 s the report has `confirmed = false` — show
"已发送，等待执行设备确认", never "已撤销"); `controlConnection(connectionId, action)`
(`pause` | `resume` | `remove` | `revoke_all`); `approveConnection(connectionId,
allowedProjects)` (`["*"]` = all), `denyConnection`. Nothing is ever approved on timeout.

**License** — `verifyLicense(token) -> LicenseStatusFfi` (offline; device-bound; grace
period aware), `setLicensePublicKey(b64u)`. The verifying key is the runtime key, else the
compile-time `AIPASS_LICENSE_PUBLIC_KEY` (b64u), else the built-in **development** key
(seed = SHA-256(`"aipass/dev/license-signing-key/v1"`), public → `devKey = true`). Production
builds must set `AIPASS_LICENSE_PUBLIC_KEY`. A failed check only disables premium features;
unlock, export, recovery and revocation never depend on a license.

**Errors** — Swift `CoreError.Failure(code:message:)`, Kotlin `CoreException.Failure`.
Codes are CONTRACTS §1.5 plus `LOCKED`, `NO_VAULT`.

### Swift example

```swift
import AIPassCore
import LocalAuthentication

final class KeychainStore: SecretStore, @unchecked Sendable {
    func get(key: String) throws -> Data? { /* SecItemCopyMatching, reuse the LAContext */ nil }
    func set(key: String, value: Data, requireUserPresence: Bool) throws {
        // kSecAttrAccessibleWhenUnlockedThisDeviceOnly; if requireUserPresence add
        // SecAccessControlCreateWithFlags(.userPresence)
    }
    func delete(key: String) throws { /* SecItemDelete */ }
}

let core = try AipassCore(dataDir: appSupport.path, secretStore: KeychainStore(),
                          platform: "ios", appVersion: "1.0.0")
if !core.hasVault() {
    let r = try await core.createVault(
        deviceName: "我的 iPhone",
        storage: StorageProfileFfi(kind: "official", endpoint: nil, region: nil, bucket: nil,
                                   prefix: nil, pathStyle: nil,
                                   baseUrl: "https://cloud.aipass.example",
                                   username: nil, path: nil),
        storageSecret: sessionToken)
    showRecoveryKit(r.recoveryKitText)          // once; never store it
} else {
    try await core.unlock()                     // after Face ID succeeded
}
try core.setRelay(baseUrl: "https://cloud.aipass.example")
for req in try await core.fetchInbox() {        // after a push {mid} arrives
    show(req)                                   // every digest field: connection (self-declared
}                                               // unless verified), resource, env, scope, limits…
let d = try await core.approve(approvalRequestId: req.approvalRequestId,
                              requestDigest: req.requestDigest,   // of the request on screen
                              narrowed: nil)
```

### Kotlin example

```kotlin
import com.aipass.core.*

class KeystoreStore(private val ctx: Context) : SecretStore {
    override fun get(key: String): ByteArray? = encryptedPrefs.read(key)   // your helper
    override fun set(key: String, value: ByteArray, requireUserPresence: Boolean) {
        // AES key in AndroidKeyStore; setUserAuthenticationRequired(requireUserPresence)
    }
    override fun delete(key: String) { /* remove */ }
}

val core = AipassCore(filesDir.path, KeystoreStore(this), "android", BuildConfig.VERSION_NAME)
lifecycleScope.launch {
    try {
        core.unlock()                                    // after BiometricPrompt
        val items = core.listItems(null, null)
        core.setRelay("https://cloud.aipass.example")
        val pending = core.fetchInbox()
    } catch (e: CoreException.Failure) {
        if (e.code == "LOCKED") promptBiometrics() else showError(e.message)
    }
}
```
(Kotlin needs `net.java.dev.jna:jna` (aar) and `kotlinx-coroutines`; the library is loaded
as `libaipass_ffi.so`.)

## Build / test / run

From `/Users/dp/code/dp/passw/open-source`:

```sh
cargo build -p aipass-ffi                                   # host lib + staticlib + cdylib
cargo test  -p aipass-ffi --features test-support           # Rust unit + end-to-end tests
cargo clippy -p aipass-ffi --features test-support --all-targets
crates/aipass-ffi/scripts/generate-bindings.sh              # refresh bindings/swift, bindings/kotlin
crates/aipass-ffi/scripts/swift-host-test.sh                # SwiftPM host test (swift build + swift test)
crates/aipass-ffi/scripts/build-apple.sh                    # XCFramework — needs Xcode
crates/aipass-ffi/scripts/build-android.sh                  # .so for 3 ABIs — needs NDK + cargo-ndk
```

* `bindings/swift/` (`AIPassCore.swift`, `AIPassCoreFFI.h`, `AIPassCoreFFI.modulemap`) and
  `bindings/kotlin/com/aipass/core/aipass_core.kt` are generated from the **production**
  build (no `TestExecutor`) and committed.
* `swift-host-test/` links `lib/libaipass_ffi.a` (copied by the script, git-ignored) and its
  own generated bindings built **with** `test-support`. Scenarios (swift-testing): create
  vault, save / list / reveal, password generator, TOTP, AutoFill, export, recovery verify,
  lock / unlock, error codes and locale; pairing between two cores and with an executor
  through a `LocalRelay`; approval request → narrowed approval → verified by the executor
  (`verify_decision`) and credential envelope opened; wrong displayed digest and a
  conflicting re-send refused (`INTEGRITY_FAILED`); deny; snapshot and revoke round trips;
  a license token signed by CryptoKit (independent Ed25519) verified by the core.
* With Command Line Tools only, swift-testing lives in
  `/Library/Developer/CommandLineTools/Library/Developer/Frameworks`; the script passes
  `-Xswiftc -F … -Xlinker -rpath …` globally (otherwise SwiftPM's generated runner compiles
  without `Testing` and silently runs zero tests) and fails if no passing test run is seen.
  Plain `swift test` works as-is with full Xcode.

## Limitations

* **Not built here:** iOS (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`)
  and Android targets — this machine has no Xcode / iOS SDK, no NDK and no JDK. Only the
  macOS host library, the generated bindings and the host tests are verified. The Kotlin
  bindings were generated but never compiled (no JDK; ktlint not installed, so unformatted).
* The HTTPS relay path (`setRelay` → `RelayClient` signed with the cached device key) is
  exercised against a **real in-process `aipass-node`** by `tests/real_relay.rs` (executor
  pairing over the node's relay, AI connection approved from the phone, sealed
  `approval.request` → `approveWithEntry` → operation succeeds against a temporary
  PostgreSQL, `revokeGrant` confirmed by `revoke.report`). It needs PostgreSQL 17 binaries
  and is skipped with a message without them. The cloud relay itself was not run.
* The native `SecretStore` decides how `requireUserPresence` is enforced; on iOS reuse the
  `LAContext` from the unlock prompt so `get` does not prompt twice.
* `fetchInbox` keeps decrypted approval **metadata** in `ffi-state.json` (no credentials).
* The host static library is built with the default macOS deployment target; linking it into
  the macOS 14 test package prints harmless "built for newer macOS" linker warnings.
* No independent security audit.

## Contract deviations

* Additive: `CoreStatus.deviceSignPk` / `deviceKemPk` and `DeviceFfi.signPk` / `kemPk`
  (b64u, public keys) — mobile apps send `deviceSignPk` as `sign_pk` in the cloud's
  `POST /v1/devices`.

* `pairingOffer` returns the `PairingSession` directly (`qrPayload()` on it) instead of a separate
  `PairingOffer {qr_payload}` record. `wait(timeoutSecs)` takes a timeout (`0` = until the link
  expires). Additive: `confirmCode`, `progress`, `setShareStorageSecret`, `isNewDevice`, `expiresAt`.
* `snapshot(executorId?)` takes an optional executor (default: last broker that messaged this
  device, else the single paired executor).
* **Approval binding (review fix):** `approve` / `approveWithEntry` / `deny` take the
  displayed request's `requestDigest` (`aipass_types::approval::request_digest` = SHA-256 of
  the JCS request minus `status`) as a required parameter and refuse with
  `INTEGRITY_FAILED` when the stored request no longer hashes to it; approving a
  `conflict`ing request is refused. `ApprovalRequestFfi` adds `requestDigest`, `conflict`
  and `parametersDigest`. Only requests whose `executor.executor_id` equals the relay sender
  are accepted (a broker relaying for several executors under one identity is not
  supported by mobile approvals). The §7 digest is v2.
* `approve` refuses with `NOT_FOUND` when the request's resource is not bound to a vault entry
  (a relay approval without a credential would be useless); `approveWithEntry` binds and
  approves. `ApprovedScopeFfi` is an alias of `AccessSpecFfi`.
* Additive methods: `setLocale`, `importEncrypted`, `replaceRecoveryKey`, `setMasterPassword`,
  `recoverWithKey`, `rotationTasks`, `dismissRotationTask`, `saveFromAutofill`,
  `setLocalRelay`, `bindResource`, `pendingApprovals`, `pendingConnections`, `lastSnapshot`,
  `denyConnection`, `setLicensePublicKey`; free functions `defaultPasswordRules`, `coreVersion`;
  object `LocalRelay`.
* Shapes: timestamps are Unix seconds; enums are snake_case strings; `CoreStatus` adds
  `rollback_detected`, `revoked`, `key_epoch`, `relay_configured`; `TotpCode` adds `period`;
  `LicenseStatusFfi` adds `grace_until`, `in_grace_period`, `dev_key`; `CoreError` is a uniffi
  error enum with the single variant `Failure { code, message }`.
* License: the signature is verified over the exact decoded payload bytes (the first token
  segment), then the JSON is parsed; `device_id` must equal this device; valid until
  `max(exp, grace_until)`.
* Feature `test-support` exposes `TestExecutor` for host tests only; production bindings do
  not contain it.
