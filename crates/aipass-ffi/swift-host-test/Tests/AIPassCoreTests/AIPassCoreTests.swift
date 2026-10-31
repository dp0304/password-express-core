// SPDX-License-Identifier: Apache-2.0
//
// Scenarios run through the real Rust core via the generated uniffi bindings.

import CryptoKit
import Foundation
import Testing

import AIPassCore

/// Keychain stand-in implementing the SecretStore callback interface in Swift.
final class MemorySecretStore: SecretStore, @unchecked Sendable {
    private var items: [String: (Data, Bool)] = [:]
    private let lock = NSLock()

    func get(key: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items[key]?.0
    }

    func set(key: String, value: Data, requireUserPresence: Bool) throws {
        lock.lock(); defer { lock.unlock() }
        items[key] = (value, requireUserPresence)
    }

    func delete(key: String) throws {
        lock.lock(); defer { lock.unlock() }
        items.removeValue(forKey: key)
    }

    func requiresUserPresence(_ key: String) -> Bool? {
        lock.lock(); defer { lock.unlock() }
        return items[key]?.1
    }
}

func tempDir() -> URL {
    let u = FileManager.default.temporaryDirectory
        .appendingPathComponent("aipass-swift-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

func localStorage(_ dir: URL) -> StorageProfileFfi {
    StorageProfileFfi(
        kind: "local", endpoint: nil, region: nil, bucket: nil, prefix: nil,
        pathStyle: nil, baseUrl: nil, username: nil,
        path: dir.appendingPathComponent("storage").path)
}

func login(_ title: String, _ user: String, _ secret: String) -> ItemInputFfi {
    ItemInputFfi(
        entryId: nil, kind: "login", title: title, username: user, secret: secret,
        clearSecret: false, urls: ["https://github.com/login"], notes: nil,
        totp: "JBSWY3DPEHPK3PXP", clearTotp: false, fields: [], database: nil,
        projectId: nil, tags: ["work"], lifecycle: nil, passwordRules: nil)
}

func makeCore(_ dir: URL, _ name: String, _ store: MemorySecretStore) throws -> AipassCore {
    try AipassCore(
        dataDir: dir.appendingPathComponent(name).path, secretStore: store,
        platform: "ios", appVersion: "0.1.0-swift-test")
}

/// Returns the CoreError code thrown by `body`, or nil.
func errorCode(_ body: () async throws -> Void) async -> String? {
    do {
        try await body()
        return nil
    } catch let CoreError.Failure(code, _) {
        return code
    } catch {
        return "UNEXPECTED"
    }
}

func b64u(_ d: Data) -> String {
    d.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

@Suite(.serialized)
struct AIPassCoreTests {
    @Test func vaultLifecycle() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = MemorySecretStore()
        let core = try makeCore(dir, "phone", store)
        #expect(!core.hasVault())
        #expect(await errorCode { _ = try core.listItems(query: nil, projectId: nil) } == "NO_VAULT")

        let created = try await core.createVault(
            deviceName: "iPhone", storage: localStorage(dir), storageSecret: nil)
        #expect(created.recoveryKey.hasPrefix("AIPR-"))
        #expect(store.requiresUserPresence("aipass.device.\(created.deviceId)") == true)
        #expect(core.status().unlocked)
        #expect(core.status().storageKind == "local")

        let id = try await core.saveItem(item: login("GitHub", "octo", "s3cret-pass-123"))
        let items = try core.listItems(query: "git", projectId: nil)
        #expect(items.count == 1 && items[0].kind == "login")
        let detail = try core.getItem(entryId: id)
        #expect(detail.hasSecret && detail.hasTotp)
        #expect(detail.secretMasked != "s3cret-pass-123")
        #expect(try core.revealSecret(entryId: id, field: "secret") == "s3cret-pass-123")

        let code = try core.totpNow(entryId: id)
        #expect(code.code.count == 6 && code.period == 30)

        var rules = defaultPasswordRules()
        rules.length = 32
        #expect(try core.generatePassword(rules: rules).count == 32)

        let candidates = try core.autofillCandidates(serviceIdentifier: "https://github.com/x")
        #expect(candidates.first?.matchKind == "exact_origin")
        #expect(try core.autofillCredential(entryId: id).password == "s3cret-pass-123")

        let export = try core.exportEncrypted(password: "export-password-1")
        #expect(export.count > 64)

        #expect(try core.verifyRecoveryKey(key: created.recoveryKey))
        #expect(core.status().recoveryVerified)
        #expect(try await core.sync().status == "ok")
        #expect(try core.devices().contains { $0.isThisDevice && $0.role == "owner" })

        core.lock()
        #expect(!core.isUnlocked())
        #expect(await errorCode { _ = try core.listItems(query: nil, projectId: nil) } == "LOCKED")
        try await core.unlock()
        #expect(try core.listItems(query: nil, projectId: nil).count == 1)

        #expect(await errorCode { _ = try core.getItem(entryId: "nope") } == "INVALID_REQUEST")
        core.setLocale(locale: "en")
        do {
            _ = try core.getItem(entryId: "nope")
        } catch let CoreError.Failure(_, message) {
            #expect(message == "invalid entry_id")
        }
        core.setLocale(locale: "zh-CN")
    }

    @Test func pairingApprovalSnapshotRevoke() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let relay = LocalRelay()
        let phone = try makeCore(dir, "phone", MemorySecretStore())
        phone.setLocalRelay(relay: relay)
        let created = try await phone.createVault(
            deviceName: "Phone", storage: localStorage(dir), storageSecret: nil)
        let entry = try await phone.saveItem(item: login("Orders DB", "readonly", "db-pass-xyz"))

        // a second device joins: it shows the QR, the phone scans and confirms
        let tablet = try makeCore(dir, "tablet", MemorySecretStore())
        tablet.setLocalRelay(relay: relay)
        let offer = try await tablet.pairingOffer(deviceName: "Tablet")
        #expect(offer.isNewDevice())
        let scan = try await phone.pairingScan(qrPayload: offer.qrPayload())
        #expect(await scan.peerName() == "Tablet")
        async let waitB = offer.wait(timeoutSecs: 30)
        async let waitA = scan.wait(timeoutSecs: 30)
        let (pb, pa) = try await (waitB, waitA)
        #expect(pa.stage == "confirm_code" && pb.stage == "confirm_code")
        #expect(pa.sas != nil && pa.sas == pb.sas)
        async let doneB = offer.confirm()
        async let doneA = scan.confirm()
        let (rb, ra) = try await (doneB, doneA)
        #expect(ra.stage == "completed" && rb.stage == "completed")
        #expect(tablet.status().vaultId == created.vaultId)
        if !tablet.isUnlocked() { try await tablet.unlock() }
        #expect(try tablet.listItems(query: nil, projectId: nil).count == 1)

        // an executor pairs
        let exe = try TestExecutor(relay: relay, name: "Home node")
        let scanExe = try await phone.pairingScan(qrPayload: exe.qrPayload())
        #expect(await scanExe.peerRole() == "executor")
        async let sasExe = exe.waitForHello(timeoutSecs: 30)
        async let waitP = scanExe.wait(timeoutSecs: 30)
        let (s1, p1) = try await (sasExe, waitP)
        #expect(s1 == p1.sas)
        let enrolled = try await scanExe.confirm()
        #expect(enrolled.device?.role == "executor")
        #expect(try await exe.waitForWelcome(timeoutSecs: 30) >= 2)

        // approval request → phone inbox → narrowed approval → verified by the executor
        let res = "res_01jc0000000000000000000000"
        let apr = try await exe.sendApprovalRequest(
            deviceId: created.deviceId, resourceId: res, operations: ["query"])
        let inbox = try await phone.fetchInbox()
        #expect(inbox.count == 1)
        let req = try #require(inbox.first)
        #expect(req.approvalRequestId == apr)
        #expect(req.requested.scope.postgresViews.first?.view == "public.orders_summary")
        #expect(req.excludedFields.first?.fields == ["customer_email"])
        #expect(!req.credentialBound)
        #expect(!req.conflict && !req.requestDigest.isEmpty)
        #expect(await errorCode { _ = try await phone.approve(approvalRequestId: apr, requestDigest: req.requestDigest, narrowed: nil) } == "NOT_FOUND")
        // a digest that is not the displayed request's is refused
        #expect(await errorCode { _ = try await phone.approveWithEntry(approvalRequestId: apr, requestDigest: "AAAA", narrowed: nil, entryId: entry) } == "INTEGRITY_FAILED")

        var narrowed = req.requested
        narrowed.limits.maxRowsPerGrant = 100
        narrowed.durationSeconds = 300
        let decision = try await phone.approveWithEntry(
            approvalRequestId: apr, requestDigest: req.requestDigest, narrowed: narrowed, entryId: entry)
        #expect(decision.decision == "approve" && decision.credentialSealed)
        let verified = try await exe.receiveDecision(timeoutSecs: 30)
        #expect(verified.verified, "\(verified.verifyError ?? "")")
        #expect(verified.credentialOpened)
        #expect(verified.credentialUsername == "readonly")
        #expect(verified.credentialSecretLen == 11)

        // deny path
        let apr2 = try await exe.sendApprovalRequest(
            deviceId: created.deviceId, resourceId: res, operations: ["query"])
        let inbox2 = try await phone.fetchInbox()
        #expect(inbox2.first?.credentialBound == true)
        let shown2 = try #require(inbox2.first)
        // same id re-sent with different content: first copy kept, approving blocked
        _ = try await exe.sendApprovalRequestVariant(
            deviceId: created.deviceId, resourceId: res, operations: ["query", "export"], kind: "access",
            reuseId: apr2, summaryEn: "Export everything", claimedExecutorId: nil)
        let again = try #require(try await phone.fetchInbox().first { $0.approvalRequestId == apr2 })
        #expect(again.conflict && again.requestDigest == shown2.requestDigest)
        #expect(await errorCode { _ = try await phone.approve(approvalRequestId: apr2, requestDigest: shown2.requestDigest, narrowed: nil) } == "INTEGRITY_FAILED")
        let denied = try await phone.deny(approvalRequestId: apr2, requestDigest: shown2.requestDigest)
        #expect(denied.decision == "deny")
        let gotDeny = try await exe.receiveDecision(timeoutSecs: 30)
        #expect(gotDeny.decision == "deny" && gotDeny.verified && !gotDeny.credentialOpened)

        // snapshot + revoke round trips
        async let snap = phone.snapshot(executorId: nil)
        async let served = exe.serveOnce(timeoutSecs: 30)
        let (s, kind) = try await (snap, served)
        #expect(kind == "state.request" && s.executorId == exe.executorId())
        async let rep = phone.revokeGrant(grantId: "grt_01jc0000000000000000000000", level: "end_sessions")
        async let served2 = exe.serveOnce(timeoutSecs: 30)
        let (r, kind2) = try await (rep, served2)
        #expect(kind2 == "grant.revoke" && r.confirmed && r.fullyRevoked)
    }

    @Test func licenseSignedWithCryptoKit() async throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try makeCore(dir, "lic", MemorySecretStore())
        let created = try await core.createVault(
            deviceName: "iPhone", storage: localStorage(dir), storageSecret: nil)
        // independent Ed25519 implementation (CryptoKit) signs with the public dev seed
        let seed = Data(SHA256.hash(data: Data("aipass/dev/license-signing-key/v1".utf8)))
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let now = Int(Date().timeIntervalSince1970)
        let payload = """
        {"device_id":"\(created.deviceId)","exp":\(now + 3600),"features":["official_sync","push"],"grace_until":\(now + 7200),"iat":\(now),"plan_id":"personal_yearly","sub":"usr_swift","v":1}
        """
        let p = Data(payload.utf8)
        let token = b64u(p) + "." + b64u(try key.signature(for: p))
        let ok = core.verifyLicense(token: token)
        #expect(ok.valid && ok.devKey && ok.planId == "personal_yearly")
        #expect(ok.features == ["official_sync", "push"])
        #expect(core.status().license?.valid == true)
        // tampering is rejected; a broken license never blocks the vault
        let bad = core.verifyLicense(token: b64u(Data(payload.replacingOccurrences(of: "personal_yearly", with: "team_monthly").utf8)) + "." + b64u(try key.signature(for: p)))
        #expect(!bad.valid && bad.reason == "bad_signature")
        #expect(core.verifyLicense(token: "garbage").reason == "bad_format")
        core.lock()
        try await core.unlock()
        #expect(core.isUnlocked())
    }
}
