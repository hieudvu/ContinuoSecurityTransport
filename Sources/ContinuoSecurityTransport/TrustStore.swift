import CryptoKit
import Darwin
import Foundation
import Security
import os

// MARK: - Fingerprint & pins (pure, unit-tested)

public struct TLSFingerprint: Sendable, Equatable, Hashable {
    public let bytes: [UInt8]
    public init(bytes: [UInt8]) { self.bytes = bytes }
    public static func ofSPKI(_ spkiDER: [UInt8]) -> TLSFingerprint { TLSFingerprint(bytes: Array(SHA256.hash(data: Data(spkiDER)))) }
}

public struct PinnedPeer: Sendable, Equatable {
    public var machineID: String
    public var fingerprint: TLSFingerprint
    /// The peer's device name, learned from the commitment+SAS-bound reveal at
    /// pairing time. Empty for pins written before this existed (fall back to a
    /// derived label). Stored locally with the pin — never broadcast.
    public var deviceName: String
    public init(machineID: String, fingerprint: TLSFingerprint, deviceName: String = "") {
        self.machineID = machineID; self.fingerprint = fingerprint; self.deviceName = deviceName
    }
}

public protocol PinStore: Sendable {
    func load() -> [PinnedPeer]
    func pinnedPeer(machineID: String) -> PinnedPeer?
    func machineID(matching fingerprint: TLSFingerprint) -> String?
    func add(_ peer: PinnedPeer)
    /// Persist and publish `peer`, reporting whether the store durably accepted it.
    /// The default preserves source compatibility for lightweight/custom stores.
    func addPersisting(_ peer: PinnedPeer) -> Bool
    func remove(machineID: String)
}

public extension PinStore {
    func pinnedPeer(machineID: String) -> PinnedPeer? {
        load().first { $0.machineID == machineID }
    }

    func machineID(matching fingerprint: TLSFingerprint) -> String? {
        load().first { $0.fingerprint == fingerprint }?.machineID
    }

    func addPersisting(_ peer: PinnedPeer) -> Bool {
        add(peer)
        return pinnedPeer(machineID: peer.machineID) == peer
    }
}

public final class InMemoryPinStore: PinStore, @unchecked Sendable {
    private let lock = NSLock(); private var peers: [String: PinnedPeer] = [:]
    public init() {}
    public func load() -> [PinnedPeer] { lock.lock(); defer { lock.unlock() }; return Array(peers.values) }
    public func pinnedPeer(machineID: String) -> PinnedPeer? {
        lock.lock(); defer { lock.unlock() }; return peers[machineID]
    }
    public func machineID(matching fingerprint: TLSFingerprint) -> String? {
        lock.lock(); defer { lock.unlock() }
        return peers.values.first { $0.fingerprint == fingerprint }?.machineID
    }
    public func add(_ peer: PinnedPeer) { lock.lock(); peers[peer.machineID] = peer; lock.unlock() }
    public func addPersisting(_ peer: PinnedPeer) -> Bool {
        add(peer)
        return true
    }
    public func remove(machineID: String) { lock.lock(); peers[machineID] = nil; lock.unlock() }
}

public enum TrustDecision: Sendable, Equatable { case trusted(machineID: String), unknown, mismatch(machineID: String) }

public struct TrustStore: Sendable {
    private let pins: PinStore
    public init(pins: PinStore) { self.pins = pins }
    @discardableResult
    public func pin(_ peer: PinnedPeer) -> Bool { pins.addPersisting(peer) }
    public func unpair(machineID: String) { pins.remove(machineID: machineID) }
    public func evaluate(presented: TLSFingerprint, claimedMachineID: String) -> TrustDecision {
        guard let pinned = pins.pinnedPeer(machineID: claimedMachineID) else { return .unknown }
        return pinned.fingerprint == presented ? .trusted(machineID: claimedMachineID) : .mismatch(machineID: claimedMachineID)
    }
}

// MARK: - Errors

public enum TrustStoreError: Error, Equatable, Sendable {
    case identityCreationFailed(OSStatus)
    case keyGenerationFailed(OSStatus)
    case publicKeyExportFailed
    case detachedKeyMismatch
    case signingFailed
    case certificateParseFailed
}

// MARK: - Keychain pin store (real; not unit-tested — Task 18 loopback validates)

/// Persists each `PinnedPeer` as a `kSecClassGenericPassword` item keyed by machineID.
/// Value layout: `machineID.utf8 ‖ 0x00 ‖ fingerprint.bytes` (split on the first 0x00 to parse back).
public final class KeychainPinStore: PinStore, @unchecked Sendable {
    private static let log = Logger(subsystem: "app.continuo.net", category: "pinstore")
    /// Keychain service. Overridable so two dev instances on ONE Mac (which share a
    /// login keychain) can use SEPARATE stores and not see each other's pins.
    private let service: String
    /// Older service name this app wrote pins under before a bundle-id rename. On
    /// `load`, any pin found ONLY under this name is migrated to `service` (copied,
    /// then the legacy item deleted) so existing pairings survive the rename with no
    /// re-pair and no stale `app.continuo.*` leftovers in Keychain Access. nil = none.
    private let legacyService: String?
    /// Keychain is a persistence boundary, not a read-through store. All session
    /// lifecycle lookups hit this process-local cache after the one bootstrap read.
    private let cache = OSAllocatedUnfairLock(initialState: [String: PinnedPeer]())
    /// Serialize add/remove plus their cache publication so readers never observe a
    /// write that lost a race with a concurrent unpair.
    private let persistenceLock = NSLock()

    public init(service: String = "dev.hieuvd.continuo.pin", legacyService: String? = nil) {
        self.service = service
        self.legacyService = legacyService
        bootstrap()
    }

    // Format: machineID.utf8 ‖ 0x00 ‖ deviceName.utf8 ‖ 0x00 ‖ fingerprint.bytes.
    // The fingerprint (raw, may contain 0x00) is LAST so it needs no delimiter;
    // the two leading strings are NUL-delimited (a NUL in a computer name — never
    // in practice — is stripped so it can't corrupt the framing).
    private func value(for peer: PinnedPeer) -> Data {
        var d = Data(peer.machineID.utf8)
        d.append(0x00)
        d.append(Data(peer.deviceName.replacingOccurrences(of: "\u{0}", with: "").utf8))
        d.append(0x00)
        d.append(contentsOf: peer.fingerprint.bytes)
        return d
    }

    public func load() -> [PinnedPeer] {
        cache.withLock { Array($0.values) }
    }

    public func pinnedPeer(machineID: String) -> PinnedPeer? {
        cache.withLock { $0[machineID] }
    }

    public func machineID(matching fingerprint: TLSFingerprint) -> String? {
        cache.withLock { peers in
            peers.values.first { $0.fingerprint == fingerprint }?.machineID
        }
    }

    /// Read and perform the bundle-id rename migration exactly once. Scoping the
    /// legacy queries inside an autorelease pool ensures their file-database
    /// temporaries do not survive into network/discovery startup.
    private func bootstrap() {
        let loaded: [PinnedPeer] = autoreleasepool {
            var peers = loadFrom(service: service)
        // Bundle-id-rename migration: pull in any pin stored only under the old
        // service, copy it to the new service, and delete the legacy item so the
        // rename is transparent (no re-pair) and leaves nothing behind.
            if let legacyService {
                var known = Set(peers.map(\.machineID))
                for legacy in loadFrom(service: legacyService) where !known.contains(legacy.machineID) {
                    if persist(legacy, to: service) {
                        removeFrom(service: legacyService, machineID: legacy.machineID)
                        peers.append(legacy)
                        known.insert(legacy.machineID)
                        Self.log.notice("pin migrated from legacy keychain service")
                    }
                }
            }
            return peers
        }
        cache.withLock { state in
            state = Dictionary(uniqueKeysWithValues: loaded.map { ($0.machineID, $0) })
        }
    }

    private func loadFrom(service: String) -> [PinnedPeer] {
        // CRITICAL: on the LEGACY macOS keychain (what a non-sandboxed Developer-ID
        // app WITHOUT a keychain-access-groups entitlement uses), a single query with
        // `kSecMatchLimitAll` + `kSecReturnData` returns errSecParam (-50) — with OR
        // without kSecReturnAttributes. That silently hid EVERY pin: the app read
        // back zero pins, so it treated already-paired peers as unpaired (re-SAS on
        // reconnect) and pin-verified reconnect had no pin to check → no session.
        // The supported form is two-step: list accounts (attributes only), then fetch
        // each item's data with matchLimitOne.
        let listQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        var listResult: CFTypeRef?
        let listStatus = SecItemCopyMatching(listQuery as CFDictionary, &listResult)
        // errSecItemNotFound (no pins yet) is normal → empty. Any OTHER non-success
        // is a real Keychain failure that silently hides pins; surface it.
        if listStatus != errSecSuccess && listStatus != errSecItemNotFound {
            Self.log.error("pinstore load(list) failed: OSStatus \(listStatus, privacy: .public)")
        }
        guard listStatus == errSecSuccess, let items = listResult as? [[String: Any]] else { return [] }
        var peers: [PinnedPeer] = []
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else { continue }
            let dataQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecReturnData as String: true,
            ]
            var dataResult: CFTypeRef?
            guard SecItemCopyMatching(dataQuery as CFDictionary, &dataResult) == errSecSuccess,
                  let data = dataResult as? Data else { continue }
            guard let sep1 = data.firstIndex(of: 0x00) else { continue }
            let idBytes = data[data.startIndex..<sep1]
            guard let machineID = String(data: idBytes, encoding: .utf8) else { continue }
            let afterID = data[data.index(after: sep1)...]
            if let sep2 = afterID.firstIndex(of: 0x00) {
                let nameBytes = afterID[afterID.startIndex..<sep2]
                let fpBytes = afterID[afterID.index(after: sep2)...]
                let deviceName = String(data: nameBytes, encoding: .utf8) ?? ""
                peers.append(PinnedPeer(machineID: machineID,
                                        fingerprint: TLSFingerprint(bytes: Array(fpBytes)),
                                        deviceName: deviceName))
            } else {
                // Legacy single-delimiter pin (no device name).
                peers.append(PinnedPeer(machineID: machineID, fingerprint: TLSFingerprint(bytes: Array(afterID))))
            }
        }
        return peers
    }

    public func add(_ peer: PinnedPeer) {
        _ = addPersisting(peer)
    }

    public func addPersisting(_ peer: PinnedPeer) -> Bool {
        persistenceLock.lock()
        defer { persistenceLock.unlock() }
        guard persist(peer, to: service) else {
            // Update failure leaves the old durable item intact. Keep the matching
            // old cache entry rather than publishing the unpersisted replacement.
            return false
        }
        cache.withLock { $0[peer.machineID] = peer }
        return true
    }

    /// Atomic update-or-add. A transient update failure must never destroy an
    /// existing durable pin; only a genuine not-found result takes the add path.
    private func persist(_ peer: PinnedPeer, to service: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: peer.machineID
        ]
        let updates: [String: Any] = [
            kSecValueData as String: value(for: peer),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
        if updateStatus == errSecSuccess { return true }
        guard updateStatus == errSecItemNotFound else {
            Self.log.error("pinstore update failed: OSStatus \(updateStatus, privacy: .public)")
            return false
        }

        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: peer.machineID,
            kSecValueData as String: value(for: peer),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let addStatus = SecItemAdd(attrs as CFDictionary, nil)
        if addStatus == errSecSuccess { return true }

        // Another process/store instance may have inserted the same account
        // between our update miss and add. Retry the non-destructive update once;
        // never delete the winner and create a durability gap.
        if addStatus == errSecDuplicateItem {
            let retryStatus = SecItemUpdate(query as CFDictionary, updates as CFDictionary)
            if retryStatus == errSecSuccess { return true }
            Self.log.error("pinstore duplicate retry failed: OSStatus \(retryStatus, privacy: .public)")
            return false
        }
        Self.log.error("pinstore add failed: OSStatus \(addStatus, privacy: .public)")
        return false
    }

    public func remove(machineID: String) {
        persistenceLock.lock()
        defer { persistenceLock.unlock() }
        // Trust must disappear immediately in this process even if disk deletion
        // later reports a Keychain fault.
        cache.withLock { $0[machineID] = nil }
        removeFrom(service: service, machineID: machineID)
        if let legacyService { removeFrom(service: legacyService, machineID: machineID) }
    }

    private func removeFrom(service: String, machineID: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: machineID
        ]
        let status = SecItemDelete(query as CFDictionary)
        // `errSecItemNotFound` is fine (nothing to delete). Any other fault means the
        // pin survived on disk: since bootstrap now rebuilds trust solely from the
        // Keychain, a failed delete would resurrect a revoked peer on next launch.
        // Surface it so the durability gap is observable rather than silent.
        if status != errSecSuccess && status != errSecItemNotFound {
            Self.log.error("pinstore revoke delete failed: service=\(service, privacy: .public) OSStatus=\(status, privacy: .public) — revoked peer may reappear after restart")
        }
    }
}

// MARK: - ASN.1 DER builder (minimal)

enum DER {
    /// DER definite length: short form < 128, else long form (0x80|n ‖ big-endian length).
    static func length(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(truncatingIfNeeded: v), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { [tag] + length(content.count) + content }

    static func sequence(_ elements: [[UInt8]]) -> [UInt8] { tlv(0x30, elements.flatMap { $0 }) }
    static func set(_ elements: [[UInt8]]) -> [UInt8] { tlv(0x31, elements.flatMap { $0 }) }

    /// INTEGER — prepends 0x00 when the high bit is set so the value stays positive.
    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        var m = magnitude
        while m.count > 1 && m.first == 0x00 && (m[1] & 0x80) == 0 { m.removeFirst() } // strip redundant leading zeros
        if let first = m.first, first & 0x80 != 0 { m.insert(0x00, at: 0) }
        if m.isEmpty { m = [0x00] }
        return tlv(0x02, m)
    }

    /// BIT STRING with 0 unused bits (leading 0x00 octet).
    static func bitString(_ bytes: [UInt8]) -> [UInt8] { tlv(0x03, [0x00] + bytes) }

    /// OID from pre-encoded content octets (excludes tag/length).
    static func oid(_ content: [UInt8]) -> [UInt8] { tlv(0x06, content) }

    static func utf8String(_ s: String) -> [UInt8] { tlv(0x0C, Array(s.utf8)) }
    static func utcTime(_ s: String) -> [UInt8] { tlv(0x17, Array(s.utf8)) }

    /// Context-specific EXPLICIT [n] constructed wrapper.
    static func explicit(_ tagNumber: UInt8, _ content: [UInt8]) -> [UInt8] { tlv(0xA0 | tagNumber, content) }
}

// Pre-encoded OID content octets (tag/length added by DER.oid).
private enum OID {
    static let ecdsaWithSHA256: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] // 1.2.840.10045.4.3.2
    static let idEcPublicKey: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]          // 1.2.840.10045.2.1
    static let prime256v1: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]       // 1.2.840.10045.3.1.7
    static let commonName: [UInt8] = [0x55, 0x04, 0x03]                                       // 2.5.4.3
}

// MARK: - SPKI wrapper (SHARED with Task 12 — both sides must produce identical bytes)

public enum SPKI {
    /// Wraps a raw EC point (0x04 ‖ X ‖ Y) into a full SubjectPublicKeyInfo DER with the
    /// id-ecPublicKey + prime256v1 AlgorithmIdentifier. Task 12 calls this on a received peer
    /// cert's EC point so its fingerprint matches the one built here by construction.
    public static func der(fromECPoint point: [UInt8]) -> [UInt8] {
        let algorithm = DER.sequence([
            DER.oid(OID.idEcPublicKey),
            DER.oid(OID.prime256v1)
        ])
        return DER.sequence([
            algorithm,
            DER.bitString(point)
        ])
    }
}

// MARK: - Identity factory (real; not unit-tested — Task 18 loopback validates)

public enum IdentityFactory {
    /// Loads (or creates) a permanent P-256 key in the Keychain and hand-builds a minimal
    /// self-signed X.509 v3 certificate over it. Returns the identity and the SPKI DER used
    /// for pinning. No third-party dependency — the DER is assembled by hand.
    /// - Parameter legacyLabels: older keychain labels this app used before a
    ///   bundle-id rename. If the key isn't found under `label` but IS under a
    ///   legacy label, the SAME key is re-labelled to `label` (not regenerated), so
    ///   the SPKI-derived pin fingerprint — and therefore every existing pairing —
    ///   is preserved across the rename. No re-pair required.
    public static func loadOrCreateSelfSigned(label: String, legacyLabels: [String] = []) throws
        -> (identity: SecIdentity, spkiDER: [UInt8]) {
        let result = try loadOrCreateSelfSignedWithDisposition(label: label, legacyLabels: legacyLabels)
        return (result.identity, result.spkiDER)
    }

    /// Same production path with an internal disposition bit so regression tests
    /// can fail if a future change silently returns to a legacy-keychain identity.
    static func loadOrCreateSelfSignedWithDisposition(
        label: String,
        legacyLabels: [String] = []
    ) throws -> (identity: SecIdentity, spkiDER: [UInt8], detached: Bool) {
        // A SecKey returned by the legacy file-based keychain keeps that database's
        // large AtomicBufferedFile backing allocation alive for as long as the key
        // reference survives. Export the app-created (exportable) P-256 key and
        // recreate an equivalent non-permanent SecKey before constructing the TLS
        // identity. The persistent key remains the source of truth in Keychain, but
        // the process-lifetime identity no longer retains the whole login keychain.
        //
        // Keep every legacy object inside its own autorelease scope. On a rare
        // export/import failure we deliberately fall back to the SAME persistent
        // key rather than generating a new fingerprint and breaking every pairing.
        let loaded: (key: SecKey, detached: Bool) = try autoreleasepool {
            let persistent = try loadOrCreateKey(label: label, legacyLabels: legacyLabels)
            if let detached = try detachedCopy(of: persistent) {
                return (detached, true)
            }
            return (persistent, false)
        }

        let built = try makeSelfSigned(label: label, privateKey: loaded.key)
        return (built.identity, built.spkiDER, loaded.detached)
    }

    /// Test/integration identity that never touches Keychain. Production must use
    /// `loadOrCreateSelfSigned` so its SPKI remains stable across launches.
    static func makeEphemeralSelfSigned(label: String) throws
        -> (identity: SecIdentity, spkiDER: [UInt8]) {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var createError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &createError) else {
            let status = createError.map { OSStatus(CFErrorGetCode($0.takeRetainedValue())) } ?? errSecParam
            throw TrustStoreError.keyGenerationFailed(status)
        }
        return try makeSelfSigned(label: label, privateKey: privateKey)
    }

    private static func makeSelfSigned(label: String, privateKey: SecKey) throws
        -> (identity: SecIdentity, spkiDER: [UInt8]) {

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { throw TrustStoreError.publicKeyExportFailed }
        var exportError: Unmanaged<CFError>?
        guard let ecPointCF = SecKeyCopyExternalRepresentation(publicKey, &exportError) else {
            throw TrustStoreError.publicKeyExportFailed
        }
        let ecPoint = [UInt8](ecPointCF as Data)
        let spkiDER = SPKI.der(fromECPoint: ecPoint)

        // ---- TBSCertificate ----
        let version = DER.explicit(0, DER.integer([0x02]))                       // [0] EXPLICIT v3 (== 2)
        let serial = DER.integer(randomSerial())                                 // positive serial
        let sigAlg = DER.sequence([DER.oid(OID.ecdsaWithSHA256)])                // ECDSA: no parameters
        let name = DER.sequence([                                                // Name: RDNSequence
            DER.set([
                DER.sequence([DER.oid(OID.commonName), DER.utf8String(label)])
            ])
        ])
        let (notBefore, notAfter) = validityWindowUTC(years: 20)
        let validity = DER.sequence([DER.utcTime(notBefore), DER.utcTime(notAfter)])

        let tbs = DER.sequence([
            version,
            serial,
            sigAlg,
            name,       // issuer
            validity,
            name,       // subject == issuer (self-signed)
            spkiDER
        ])

        // ---- Sign TBS (message algorithm hashes with SHA-256 internally) ----
        var signError: Unmanaged<CFError>?
        guard let signatureCF = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, Data(tbs) as CFData, &signError) else {
            throw TrustStoreError.signingFailed
        }
        let signature = [UInt8](signatureCF as Data)

        // ---- Certificate ----
        let certDER = DER.sequence([
            tbs,
            sigAlg,
            DER.bitString(signature)
        ])

        guard let certificate = SecCertificateCreateWithData(nil, Data(certDER) as CFData) else {
            throw TrustStoreError.certificateParseFailed
        }

        // Pair the certificate with the exact key we already hold. Unlike
        // SecIdentityCreateWithCertificate, this does not search the default
        // legacy keychain (and therefore does not re-read/retain its database).
        guard let identity = SecIdentityCreate(nil, certificate, privateKey) else {
            throw TrustStoreError.identityCreationFailed(errSecInvalidItemRef)
        }
        return (identity, spkiDER)
    }

    // MARK: private helpers

    /// Serializes keychain-mutating identity creation across threads in one
    /// process. `SecKeyCreateRandomKey` with `kSecAttrIsPermanent` writes to the
    /// keychain, and concurrent writers intermittently fault with `errSecParam`
    /// (-50) — surfaced by the Task 18 loopback suite running key-creating tests
    /// in parallel. Serializing the lookup-then-create removes that race.
    private static let keychainLock = NSLock()
    private static let log = Logger(subsystem: "app.continuo.net", category: "identity")

    /// Recreate an exportable legacy-keychain key as an in-memory SecKey. Returns
    /// nil only for an export/import failure, in which case the caller safely keeps
    /// using the original persistent key. A recreated key whose public point does
    /// not match is a hard integrity failure and is never accepted.
    private static func detachedCopy(of persistent: SecKey) throws -> SecKey? {
        guard var privateBytes = exportedPrivateBytes(from: persistent) else { return nil }
        defer { zeroize(&privateBytes) }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
            // macOS's legacy Security backend may otherwise inherit the source
            // key's permanent bit from the external representation and resolve
            // the import back to a keychain-backed SecKey. Explicit false is the
            // load-bearing part of detaching the process-lifetime TLS identity.
            kSecAttrIsPermanent as String: false
        ]
        var error: Unmanaged<CFError>?
        let detached: SecKey? = privateBytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return nil }
            // No second immutable Data copy: this short-lived CFData borrows the
            // uniquely-owned mutable array, which is explicitly wiped immediately
            // after SecKeyCreateWithData has imported the key material.
            guard let data = CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                base.assumingMemoryBound(to: UInt8.self),
                raw.count,
                kCFAllocatorNull
            ) else { return nil }
            return SecKeyCreateWithData(data, attrs as CFDictionary, &error)
        }
        guard let detached else {
            let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? Int(errSecParam)
            Self.log.error("identity key detach import failed; using legacy reference: code=\(code, privacy: .public)")
            return nil
        }

        // A transient failure to READ either public key is not an integrity
        // violation — degrade gracefully to the persistent key (as the export/import
        // paths above do) rather than bricking networking for the whole launch. Only
        // a successful comparison that DISAGREES is a hard integrity failure.
        guard let persistentPublic = SecKeyCopyPublicKey(persistent),
              let detachedPublic = SecKeyCopyPublicKey(detached) else {
            Self.log.error("identity key detach: public-key copy failed; using legacy reference")
            return nil
        }
        error = nil
        guard let persistentBytes = SecKeyCopyExternalRepresentation(persistentPublic, &error) as Data? else {
            Self.log.error("identity key detach: persistent public export failed; using legacy reference")
            return nil
        }
        error = nil
        guard let detachedBytes = SecKeyCopyExternalRepresentation(detachedPublic, &error) as Data? else {
            Self.log.error("identity key detach: detached public export failed; using legacy reference")
            return nil
        }
        guard persistentBytes == detachedBytes else { throw TrustStoreError.detachedKeyMismatch }
        return detached
    }

    /// Copy Security's immutable export into a uniquely-owned mutable buffer and
    /// release the CFData immediately. The Security-owned immutable buffer cannot
    /// be legally mutated; minimizing its scope plus wiping our import buffer is
    /// the strongest safe guarantee the API permits.
    private static func exportedPrivateBytes(from persistent: SecKey) -> [UInt8]? {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(persistent, &error) else {
            let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? Int(errSecParam)
            Self.log.error("identity key detach export failed; using legacy reference: code=\(code, privacy: .public)")
            return nil
        }
        let count = CFDataGetLength(data)
        guard count > 0, let base = CFDataGetBytePtr(data) else { return nil }
        return Array(UnsafeBufferPointer(start: base, count: count))
    }

    /// Internal for a direct zeroization regression test.
    static func zeroize(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress, raw.count > 0 else { return }
            _ = memset_s(base, raw.count, 0, raw.count)
        }
    }

    /// Copy the permanent P-256 key stored under `label`, or nil if none exists.
    private static func copyKey(label: String) -> SecKey? {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true
        ]
        var existing: CFTypeRef?
        guard SecItemCopyMatching(lookup as CFDictionary, &existing) == errSecSuccess,
              let ref = existing else { return nil }
        return (ref as! SecKey)  // matched class kSecClassKey → guaranteed SecKey
    }

    private static func loadOrCreateKey(label: String, legacyLabels: [String] = []) throws -> SecKey {
        keychainLock.lock()
        defer { keychainLock.unlock() }

        // Try to reuse an existing key so the fingerprint (over the SPKI) stays stable.
        if let key = copyKey(label: label) { return key }

        // Bundle-id-rename migration: the same key under an OLD label is re-labelled
        // to the current one (SecItemUpdate — NOT regenerated), keeping the public
        // key (hence the pin fingerprint) identical so pairings survive the rename.
        for legacy in legacyLabels where legacy != label {
            guard copyKey(label: legacy) != nil else { continue }
            let update = SecItemUpdate(
                [kSecClass as String: kSecClassKey,
                 kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                 kSecAttrLabel as String: legacy] as CFDictionary,
                [kSecAttrLabel as String: label] as CFDictionary)
            if update == errSecSuccess, let migrated = copyKey(label: label) {
                Self.log.notice("identity key migrated from legacy keychain label")
                return migrated
            }
            Self.log.error("identity key migration failed: OSStatus \(update, privacy: .public)")
        }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrLabel as String: label,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            ]
        ]
        // Bounded retry on a transient keychain fault; surface the REAL error
        // code on give-up (the previous code discarded `createError` and always
        // reported a hardcoded `errSecParam`, masking the true cause).
        var lastStatus: OSStatus = errSecParam
        for attempt in 0..<4 {
            var createError: Unmanaged<CFError>?
            if let key = SecKeyCreateRandomKey(attrs as CFDictionary, &createError) {
                return key
            }
            if let err = createError?.takeRetainedValue() {
                lastStatus = OSStatus(CFErrorGetCode(err))
            }
            if attempt < 3 { usleep(20_000) }
        }
        throw TrustStoreError.keyGenerationFailed(lastStatus)
    }

    private static func randomSerial() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 16)
        for i in bytes.indices { bytes[i] = UInt8.random(in: 0...255) }
        bytes[0] &= 0x7F   // keep positive (clear sign bit)
        if bytes[0] == 0 { bytes[0] = 0x01 } // avoid leading zero
        return bytes
    }

    /// UTCTime strings "YYMMDDHHMMSSZ". notBefore = now, notAfter = now + `years` (< 2050 so UTCTime is valid).
    private static func validityWindowUTC(years: Int) -> (String, String) {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let now = Date()
        let end = cal.date(byAdding: .year, value: years, to: now) ?? now
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = TimeZone(identifier: "UTC")!
        fmt.dateFormat = "yyMMddHHmmss'Z'"
        return (fmt.string(from: now), fmt.string(from: end))
    }
}
