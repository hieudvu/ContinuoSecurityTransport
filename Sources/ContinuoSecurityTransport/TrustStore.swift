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

// MARK: - Keychain pin store

/// One generic-password item as a listing returns it: attributes only, never
/// its data. Attributes come back without any keychain prompt; data does not
/// when the item is not ours, which is why a listing never includes it.
struct PinKeychainItem: Equatable, Sendable {
    let account: String
    /// `kSecAttrGeneric`: where a signed pin keeps its signature.
    let signature: Data?
}

enum PinKeychainListing: Equatable, Sendable {
    /// `errSecItemNotFound` is an empty list, not a failure.
    case items([PinKeychainItem])
    case failed(OSStatus)
}

/// The keychain calls a pin store makes. Internal so tests can stage any
/// keychain state in memory; `SystemPinKeychain` is the only real one.
protocol PinKeychain: Sendable {
    func list(service: String) -> PinKeychainListing
    func data(service: String, account: String) -> Data?
    /// A nil `data` or `signature` leaves that part of the item as it is, so
    /// writing a signature never rewrites the record an older release reads.
    func update(service: String, account: String, data: Data?, signature: Data?) -> OSStatus
    func add(service: String, account: String, data: Data, signature: Data?) -> OSStatus
    func delete(service: String, account: String) -> OSStatus
}

/// Signs and checks pin records. The real one is this Mac's TLS identity key
/// (`PinSigningIdentity`): the very key peers pin, so nothing new is stored.
protocol PinRecordKey: Sendable {
    func sign(_ message: Data) -> Data?
    func isValidSignature(_ signature: Data, for message: Data) -> Bool
}

/// Which key signs a pin store's records: the identity key stored under
/// `label`, resolved through `IdentityFactory` exactly as the TLS identity is,
/// so the key that signs pins is always the key this process presents in TLS
/// (see `IdentityFactory.processKey`).
public struct PinSigningIdentity: Sendable, Equatable {
    public let label: String
    public let legacyLabels: [String]
    public init(label: String, legacyLabels: [String] = []) {
        self.label = label
        self.legacyLabels = legacyLabels
    }

    func resolveKey() -> PinRecordKey? {
        guard let loaded = try? IdentityFactory.processKey(label: label, legacyLabels: legacyLabels) else {
            return nil
        }
        return SecKeyPinRecordKey(privateKey: loaded.key)
    }
}

/// ECDSA P-256 over SHA-256 with the identity key. Verifying needs only the
/// public half, derived in memory from the key the process already holds, so
/// checking pins never asks the keychain for anything.
final class SecKeyPinRecordKey: PinRecordKey, @unchecked Sendable {
    private let privateKey: SecKey
    private let publicKey: SecKey

    init?(privateKey: SecKey) {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        self.privateKey = privateKey
        self.publicKey = publicKey
    }

    func sign(_ message: Data) -> Data? {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256,
                                                    message as CFData, &error) else {
            _ = error?.takeRetainedValue()
            return nil
        }
        return signature as Data
    }

    func isValidSignature(_ signature: Data, for message: Data) -> Bool {
        SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
                              message as CFData, signature as CFData, nil)
    }
}

/// The legacy (file-based) login keychain, which is what a Developer ID app
/// without a keychain-access-groups entitlement gets.
struct SystemPinKeychain: PinKeychain {
    private func query(_ service: String, _ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func list(service: String) -> PinKeychainListing {
        // CRITICAL: on the LEGACY macOS keychain, a single query with
        // `kSecMatchLimitAll` + `kSecReturnData` returns errSecParam (-50) —
        // with OR without kSecReturnAttributes. That silently hid EVERY pin: the
        // app read back zero pins, so it treated already-paired peers as
        // unpaired (re-SAS on reconnect) and pin-verified reconnect had no pin to
        // check → no session. The supported form is two-step: list accounts
        // (attributes only, here), then fetch each item's data with
        // matchLimitOne (`data(service:account:)`).
        let listQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(listQuery as CFDictionary, &result)
        if status == errSecItemNotFound { return .items([]) }
        guard status == errSecSuccess, let rows = result as? [[String: Any]] else {
            return .failed(status == errSecSuccess ? errSecInternalError : status)
        }
        return .items(rows.compactMap { row in
            guard let account = row[kSecAttrAccount as String] as? String else { return nil }
            return PinKeychainItem(account: account, signature: row[kSecAttrGeneric as String] as? Data)
        })
    }

    func data(service: String, account: String) -> Data? {
        var q = query(service, account)
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecReturnData as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    func update(service: String, account: String, data: Data?, signature: Data?) -> OSStatus {
        var updates: [String: Any] = [:]
        if let data {
            updates[kSecValueData as String] = data
            updates[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        if let signature { updates[kSecAttrGeneric as String] = signature }
        guard !updates.isEmpty else { return errSecSuccess }
        return SecItemUpdate(query(service, account) as CFDictionary, updates as CFDictionary)
    }

    func add(service: String, account: String, data: Data, signature: Data?) -> OSStatus {
        var attrs = query(service, account)
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        if let signature { attrs[kSecAttrGeneric as String] = signature }
        return SecItemAdd(attrs as CFDictionary, nil)
    }

    func delete(service: String, account: String) -> OSStatus {
        SecItemDelete(query(service, account) as CFDictionary)
    }
}

/// Persists each `PinnedPeer` as a `kSecClassGenericPassword` item keyed by machineID.
/// Value layout: `machineID.utf8 ‖ 0x00 ‖ deviceName.utf8 ‖ 0x00 ‖ fingerprint.bytes`
/// (pins from before 2026-07-03 have no device name and one separator); see
/// `parseRecord`, which reads the fingerprint from the end.
///
/// SIGNED PINS (review finding H7, 2026-10-17). Nothing used to authenticate an
/// item: any program running as the user may add an item under this service,
/// and with one approved keychain prompt rewrite ours, and Continuo then
/// trusted whatever Mac that item named. Each pin's record bytes stay exactly
/// what every earlier release wrote (they must keep reading them after a
/// downgrade); its signature rides in the SAME item's `kSecAttrGeneric`, which
/// earlier releases never read, written in the same `SecItemAdd`/`SecItemUpdate`
/// as the data. See `recordMessage` for what is signed and `bootstrap` for the
/// one-time, silent migration that signs the pins already there.
public final class KeychainPinStore: PinStore, @unchecked Sendable {
    private static let log = Logger(subsystem: "app.continuo.net", category: "pinstore")
    /// Keychain service. Overridable so two dev instances on ONE Mac (which share a
    /// login keychain) can use SEPARATE stores and not see each other's pins.
    private let service: String
    /// Older service name this app wrote pins under before a bundle-id rename. On
    /// `load`, any pin found ONLY under this name is migrated to `service` (copied,
    /// then the legacy item deleted) so existing pairings survive the rename with no
    /// re-pair and no stale `app.continuo.*` leftovers in Keychain Access. nil = none.
    /// Only before signing starts: see `bootstrap`.
    private let legacyService: String?
    private let keychain: PinKeychain
    /// Resolved at every bootstrap and write, never cached here: a key that is
    /// unreadable at one launch must be picked up at the next.
    private let keyProvider: @Sendable () -> PinRecordKey?
    /// Keychain is a persistence boundary, not a read-through store. All session
    /// lifecycle lookups hit this process-local cache after the one bootstrap read.
    private let cache = OSAllocatedUnfairLock(initialState: [String: PinnedPeer]())
    /// Serializes every store's bootstrap, add and remove, process-wide. The app
    /// holds two long-lived stores and builds short-lived ones for diagnostics
    /// and the login-screen pane, all over the same items; one lock means a
    /// migration in one can never interleave with a write in another, and a
    /// writer never publishes a pin that lost a race with a concurrent unpair.
    private static let keychainLock = NSLock()
    /// Whether this store has seen its signature anchor, so every pin it trusts
    /// or writes must carry a valid signature. Guarded by `keychainLock`.
    private var requiresSignatures = false

    /// - Parameter signingIdentity: the identity key that signs this store's
    ///   records. nil means no key: such a store reads pins exactly as earlier
    ///   releases did until a signing store has migrated the service, and
    ///   trusts none afterwards (it could not tell ours from planted ones).
    public convenience init(service: String = "dev.hieuvd.continuo.pin", legacyService: String? = nil,
                            signingIdentity: PinSigningIdentity? = nil) {
        self.init(service: service, legacyService: legacyService, keychain: SystemPinKeychain(),
                  key: { signingIdentity?.resolveKey() })
    }

    init(service: String, legacyService: String?, keychain: PinKeychain,
         key: @escaping @Sendable () -> PinRecordKey?) {
        self.service = service
        self.legacyService = legacyService
        self.keychain = keychain
        self.keyProvider = key
        bootstrap()
    }

    // MARK: Record format

    // Format: machineID.utf8 ‖ 0x00 ‖ deviceName.utf8 ‖ 0x00 ‖ fingerprint.bytes.
    // The fingerprint (raw, may contain 0x00) is LAST so it needs no delimiter;
    // the two leading strings are NUL-delimited (a NUL in a computer name — never
    // in practice — is stripped so it can't corrupt the framing). Byte-for-byte
    // what every release has written since 9e87cbc4; a golden test holds it there.
    static func recordData(for peer: PinnedPeer) -> Data {
        var d = Data(peer.machineID.utf8)
        d.append(0x00)
        d.append(Data(peer.deviceName.replacingOccurrences(of: "\u{0}", with: "").utf8))
        d.append(0x00)
        d.append(contentsOf: peer.fingerprint.bytes)
        return d
    }

    /// The pin store's signature anchor lives in a service of its own: earlier
    /// releases list only `service` and so never see it, and it never shows up
    /// as a pin here.
    static func anchorService(for service: String) -> String { service + ".signed-anchor" }
    static let anchorAccount = "anchor"
    /// The anchor's data is never read back (its signature covers everything
    /// that matters, in attributes), so it is just a recognizable tag.
    private static let anchorData = Data("continuo.pin-anchor.v1".utf8)

    private static let recordDomain = Data("continuo.pin-record.v1".utf8)
    private static let anchorDomain = Data("continuo.pin-anchor.v1".utf8)
    private static let signatureFormat: UInt8 = 0x01

    /// What a pin's signature covers:
    ///
    ///     "continuo.pin-record.v1" ‖ 0x00 ‖ lp(service) ‖ lp(account) ‖ lp(record)
    ///
    /// where lp(x) is x's byte count as a big-endian UInt32 followed by x, and
    /// `record` is the item's data exactly as stored (it holds the machine ID,
    /// the device name and the fingerprint, in either layout ever written, so
    /// signing the bytes signs all three without re-encoding anything). The
    /// service is in it so a pin copied into the login-window store, or into
    /// another dev instance's store, does not verify there; the account so a
    /// signature copied onto another Mac's item does not verify either.
    static func recordMessage(service: String, account: String, data: Data) -> Data {
        var m = recordDomain
        m.append(0x00)
        appendLengthPrefixed(Data(service.utf8), to: &m)
        appendLengthPrefixed(Data(account.utf8), to: &m)
        appendLengthPrefixed(data, to: &m)
        return m
    }

    /// What the anchor's signature covers:
    ///
    ///     "continuo.pin-anchor.v1" ‖ 0x00 ‖ lp(service) ‖ lp(anchor service) ‖ lp(account) ‖ lp(manifest)
    ///
    /// `manifest` lists the pins a migration set out to sign (`manifestEntry`
    /// of each, sorted), so a migration cut short can be finished without ever
    /// adopting a pin that was not there when it started; it is emptied once
    /// every one of them is signed.
    static func anchorMessage(service: String, manifest: Data) -> Data {
        var m = anchorDomain
        m.append(0x00)
        appendLengthPrefixed(Data(service.utf8), to: &m)
        appendLengthPrefixed(Data(anchorService(for: service).utf8), to: &m)
        appendLengthPrefixed(Data(anchorAccount.utf8), to: &m)
        appendLengthPrefixed(manifest, to: &m)
        return m
    }

    /// SHA-256 of the pin's `recordMessage`: binds service, account and bytes.
    static func manifestEntry(service: String, account: String, data: Data) -> Data {
        Data(SHA256.hash(data: recordMessage(service: service, account: account, data: data)))
    }

    private static func appendLengthPrefixed(_ field: Data, to message: inout Data) {
        let n = UInt32(clamping: field.count)
        message.append(contentsOf: [UInt8(n >> 24), UInt8(truncatingIfNeeded: n >> 16),
                                    UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)])
        message.append(field)
    }

    /// A pin's `kSecAttrGeneric`: format byte 0x01 ‖ the X9.62 DER signature.
    static func signatureBlob(_ signature: Data) -> Data { Data([signatureFormat]) + signature }

    /// The signature in a pin's `kSecAttrGeneric`, or nil when the attribute is
    /// not even shaped like one. Checked BEFORE the item's data is read: an
    /// item someone else planted would make the keychain ask the user to let
    /// Continuo read it, and an item that cannot verify is not worth a prompt.
    static func rawSignature(fromBlob blob: Data) -> Data? {
        // A P-256 DER signature is a SEQUENCE of 8 to 72 bytes.
        guard blob.count >= 9, blob.count <= 73, blob.first == signatureFormat else { return nil }
        let signature = Data(blob.dropFirst())
        guard signature.first == 0x30 else { return nil }
        return signature
    }

    /// The anchor's `kSecAttrGeneric`: 0x01 ‖ signature length (one byte) ‖
    /// signature ‖ manifest (32 bytes per pin).
    static func anchorBlob(signature: Data, manifest: Data) -> Data {
        Data([signatureFormat, UInt8(clamping: signature.count)]) + signature + manifest
    }

    static func anchorParts(fromBlob blob: Data) -> (signature: Data, manifest: Data)? {
        let bytes = [UInt8](blob)
        guard bytes.count >= 2, bytes[0] == signatureFormat else { return nil }
        let length = Int(bytes[1])
        guard length >= 8, bytes.count >= 2 + length, (bytes.count - 2 - length) % 32 == 0 else { return nil }
        return (Data(bytes[2..<(2 + length)]), Data(bytes[(2 + length)...]))
    }

    static func anchorManifest(fromBlob blob: Data) -> Data? { anchorParts(fromBlob: blob)?.manifest }

    // MARK: PinStore

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

    // MARK: Bootstrap and migration

    /// Read, verify, and migrate exactly once per launch. Scoping the keychain
    /// work inside an autorelease pool ensures the file-database temporaries do
    /// not survive into network/discovery startup.
    ///
    /// Three states, told apart by the anchor (`anchorService(for:)`), an item
    /// Continuo writes once and nobody else can sign:
    ///
    /// - No anchor, no pin with a valid signature: this Mac has not run a
    ///   release that signs. Every pin there is trusted exactly as before (the
    ///   owner's decision: pins present at the upgrade are ours), and, if the
    ///   identity key is readable, signed in place. Without the key nothing is
    ///   written and the next launch tries again; until then pins work as today.
    /// - Anchor present: only pins whose signature verifies are trusted; any
    ///   other item is ignored, never deleted, and its data is not even read
    ///   unless an interrupted migration still names it (see `anchorMessage`).
    /// - No anchor but signed pins: the anchor was deleted. That never happens
    ///   on its own, so it is not taken as permission to adopt unsigned pins
    ///   again; the signed ones stand and the anchor is put back.
    private func bootstrap() {
        let trusted: [PinnedPeer] = autoreleasepool {
            Self.keychainLock.lock()
            defer { Self.keychainLock.unlock() }
            return loadTrusted(key: keyProvider(), retryOnAnchorRace: true)
        }
        cache.withLock { state in
            state = Self.cacheIndex(trusted)
        }
    }

    private struct Record { let account: String; let data: Data; let signature: Data?; let peer: PinnedPeer }

    private func loadTrusted(key: PinRecordKey?, retryOnAnchorRace: Bool) -> [PinnedPeer] {
        let anchorService = Self.anchorService(for: service)
        switch keychain.list(service: anchorService) {
        case .failed(let status):
            // Unknown is not "absent": adopting unsigned pins on a read error
            // would hand anyone who can make that read fail the old trust.
            Self.log.error("pinstore could not read its signature anchor: OSStatus \(status, privacy: .public); trusting signed pins only")
            requiresSignatures = true
            return verifiedPins(key: key, manifest: nil)
        case .items(let anchors) where !anchors.isEmpty:
            requiresSignatures = true
            guard let key else { return verifiedPins(key: nil, manifest: nil) }
            let manifest = validManifest(anchors, key: key)
            if manifest == nil {
                Self.log.error("pinstore signature anchor does not verify; adopting no unsigned pin")
            }
            return verifiedPins(key: key, manifest: manifest)
        case .items:
            return unanchoredLoad(key: key, retryOnAnchorRace: retryOnAnchorRace)
        }
    }

    /// The manifest of a valid anchor (possibly empty), or nil when no anchor
    /// item verifies.
    private func validManifest(_ anchors: [PinKeychainItem], key: PinRecordKey) -> Data? {
        for anchor in anchors where anchor.account == Self.anchorAccount {
            guard let blob = anchor.signature, let parts = Self.anchorParts(fromBlob: blob) else { continue }
            if key.isValidSignature(parts.signature, for: Self.anchorMessage(service: service, manifest: parts.manifest)) {
                return parts.manifest
            }
        }
        return nil
    }

    private func signedAnchor(manifest: Data, key: PinRecordKey) -> Data? {
        guard let signature = key.sign(Self.anchorMessage(service: service, manifest: manifest)) else { return nil }
        return Self.anchorBlob(signature: signature, manifest: manifest)
    }

    /// No anchor yet. Mirrors every earlier release's load (including the
    /// bundle-id rename import), then signs what it read.
    private func unanchoredLoad(key: PinRecordKey?, retryOnAnchorRace: Bool) -> [PinnedPeer] {
        // A list failure hid every pin in earlier releases too; nothing to
        // sign, and nothing is written, so the next launch starts afresh.
        guard let items = listedPins() else { return [] }
        var records = items.compactMap(readRecord)

        if let key {
            let signed = records.filter { isValidlySigned($0, key: key) }
            if !signed.isEmpty {
                Self.log.error("pinstore found signed pins but no signature anchor; adopting no unsigned pin")
                requiresSignatures = true
                if let blob = signedAnchor(manifest: Data(), key: key) {
                    _ = keychain.add(service: Self.anchorService(for: service), account: Self.anchorAccount,
                                     data: Self.anchorData, signature: blob)
                }
                logIgnored(records.count - signed.count)
                return signed.map(\.peer)
            }
        }

        // Bundle-id-rename migration: pull in any pin stored only under the old
        // service, copy it to the new service, and delete the legacy item so the
        // rename is transparent (no re-pair) and leaves nothing behind.
        if let legacyService, case .items(let legacyItems) = keychain.list(service: legacyService) {
            var known = Set(records.map(\.account))
            for item in legacyItems where !known.contains(item.account) {
                guard let data = keychain.data(service: legacyService, account: item.account),
                      let legacy = Self.parseRecord(account: item.account, data: data) else { continue }
                let record = Self.recordData(for: legacy)
                if persist(account: legacy.machineID, data: record, signature: nil) {
                    removeFrom(service: legacyService, machineID: legacy.machineID)
                    records.append(Record(account: legacy.machineID, data: record, signature: nil, peer: legacy))
                    known.insert(legacy.machineID)
                    Self.log.notice("pin migrated from legacy keychain service")
                }
            }
        }
        let peers = records.map(\.peer)
        guard let key else {
            Self.log.notice("pinstore cannot reach this Mac's identity key; \(peers.count, privacy: .public) pin(s) kept unsigned until a later launch")
            return peers
        }

        // Anchor FIRST, naming every pin about to be signed. A launch that dies
        // between two pins leaves an anchor whose manifest still names the
        // rest, and the next launch signs exactly those (`verifiedPins`). Were
        // the anchor written last, that same crash would leave signed pins and
        // no anchor, which must read as tampering, and the unsigned rest would
        // be dropped: a lost pairing for a crash.
        let unsigned = records.filter { !isValidlySigned($0, key: key) }
        let manifest = Self.sortedManifest(unsigned.map { entry(for: $0) })
        guard let anchor = signedAnchor(manifest: manifest, key: key) else {
            Self.log.error("pinstore could not sign its signature anchor; pins kept unsigned until a later launch")
            return peers
        }
        let anchorStatus = keychain.add(service: Self.anchorService(for: service), account: Self.anchorAccount,
                                        data: Self.anchorData, signature: anchor)
        if anchorStatus == errSecDuplicateItem, retryOnAnchorRace {
            // Another process wrote it between our list and add: read it as is.
            return loadTrusted(key: key, retryOnAnchorRace: false)
        }
        guard anchorStatus == errSecSuccess else {
            Self.log.error("pinstore could not write its signature anchor: OSStatus \(anchorStatus, privacy: .public); pins kept unsigned until a later launch")
            return peers
        }
        requiresSignatures = true

        var left: [Data] = []
        for record in unsigned where !writeSignature(for: record, key: key) {
            left.append(entry(for: record))
        }
        if !manifest.isEmpty { rewriteAnchorIfChanged(from: manifest, to: Self.sortedManifest(left), key: key) }
        Self.log.notice("pinstore signed \(unsigned.count - left.count, privacy: .public) existing pin(s); \(left.count, privacy: .public) left for a later launch")
        return peers
    }

    /// Anchor present (or unreadable): trust only what verifies.
    private func verifiedPins(key: PinRecordKey?, manifest: Data?) -> [PinnedPeer] {
        guard let key else {
            Self.log.error("pinstore cannot reach this Mac's identity key; no pin can be verified at this launch")
            return []
        }
        guard let items = listedPins() else { return [] }
        var peers: [PinnedPeer] = []
        var ignored = 0
        var unsigned: [PinKeychainItem] = []
        var pending = Set(Self.manifestEntries(manifest ?? Data()))
        let wasPending = !pending.isEmpty

        for item in items {
            guard item.signature.flatMap(Self.rawSignature(fromBlob:)) != nil else {
                unsigned.append(item)
                continue
            }
            guard let record = readRecord(item), isValidlySigned(record, key: key) else {
                ignored += 1
                continue
            }
            pending.remove(entry(for: record))
            peers.append(record.peer)
        }
        // Only an interrupted migration reads an unsigned item at all, and it
        // adopts one only if its exact bytes are in the signed manifest.
        var stillPending: [Data] = []
        for item in unsigned {
            guard !pending.isEmpty, let record = readRecord(item), pending.contains(entry(for: record)) else {
                ignored += 1
                continue
            }
            let e = entry(for: record)
            pending.remove(e)
            if !writeSignature(for: record, key: key) { stillPending.append(e) }
            peers.append(record.peer)
        }
        if wasPending, let manifest {
            // Entries no item matches any more (a Mac unpaired before its pin
            // was signed) are dropped with the rest.
            rewriteAnchorIfChanged(from: manifest, to: Self.sortedManifest(stillPending), key: key)
        }
        logIgnored(ignored)
        return peers
    }

    private func readRecord(_ item: PinKeychainItem) -> Record? {
        guard let data = keychain.data(service: service, account: item.account),
              let peer = Self.parseRecord(account: item.account, data: data) else { return nil }
        return Record(account: item.account, data: data, signature: item.signature, peer: peer)
    }

    private func isValidlySigned(_ record: Record, key: PinRecordKey) -> Bool {
        guard let blob = record.signature, let signature = Self.rawSignature(fromBlob: blob) else { return false }
        return key.isValidSignature(signature, for: Self.recordMessage(service: service, account: record.account,
                                                                       data: record.data))
    }

    private func entry(for record: Record) -> Data {
        Self.manifestEntry(service: service, account: record.account, data: record.data)
    }

    /// Signs one pin in place: the signature only, its data untouched.
    private func writeSignature(for record: Record, key: PinRecordKey) -> Bool {
        guard let signature = key.sign(Self.recordMessage(service: service, account: record.account, data: record.data)) else {
            return false
        }
        let status = keychain.update(service: service, account: record.account, data: nil,
                                     signature: Self.signatureBlob(signature))
        if status != errSecSuccess {
            Self.log.error("pinstore could not sign an existing pin: OSStatus \(status, privacy: .public)")
        }
        return status == errSecSuccess
    }

    private func rewriteAnchorIfChanged(from old: Data, to new: Data, key: PinRecordKey) {
        guard new != old, let blob = signedAnchor(manifest: new, key: key) else { return }
        let status = keychain.update(service: Self.anchorService(for: service), account: Self.anchorAccount,
                                     data: nil, signature: blob)
        if status != errSecSuccess {
            Self.log.error("pinstore could not update its signature anchor: OSStatus \(status, privacy: .public)")
        }
    }

    private static func sortedManifest(_ entries: [Data]) -> Data {
        entries.sorted { $0.lexicographicallyPrecedes($1) }.reduce(into: Data()) { $0.append($1) }
    }

    private static func manifestEntries(_ manifest: Data) -> [Data] {
        stride(from: 0, to: manifest.count - manifest.count % 32, by: 32).map {
            manifest.subdata(in: (manifest.startIndex + $0)..<(manifest.startIndex + $0 + 32))
        }
    }

    private func listedPins() -> [PinKeychainItem]? {
        switch keychain.list(service: service) {
        case .items(let items): return items
        case .failed(let status):
            // errSecItemNotFound (no pins yet) is normal and never reaches here.
            // Any OTHER non-success is a real Keychain failure that silently
            // hides pins; surface it.
            Self.log.error("pinstore load(list) failed: OSStatus \(status, privacy: .public)")
            return nil
        }
    }

    private func logIgnored(_ count: Int) {
        guard count > 0 else { return }
        Self.log.error("pinstore ignored \(count, privacy: .public) pin item(s) without a valid signature")
    }

    /// One Keychain item → one pin, or nil when the item is not a pin Continuo
    /// wrote.
    ///
    /// Every pin written since `0f6a9d05` uses the machine ID as the item's
    /// account, and `persist`/`removeFrom` address it that way. An item whose data
    /// names a different Mac than its account was therefore not written by
    /// Continuo: something else created it under our service. Two such items
    /// naming one Mac trapped the app on EVERY launch in
    /// `Dictionary(uniqueKeysWithValues:)`, and one alone could never be unpaired,
    /// because unpair deletes by account. Skip it, and say so.
    static func parseRecord(account: String, data: Data) -> PinnedPeer? {
        guard let sep1 = data.firstIndex(of: 0x00) else { return nil }
        let idBytes = data[data.startIndex..<sep1]
        guard let machineID = String(data: idBytes, encoding: .utf8) else { return nil }
        guard !machineID.isEmpty, machineID == account else {
            log.error("pinstore skipped an item whose data does not match its account")
            return nil
        }
        // The fingerprint is ALWAYS the last `fingerprintLength` bytes, in both
        // layouts ever written:
        //   0f6a9d05  machineID ‖ 0x00 ‖ fingerprint
        //   9e87cbc4  machineID ‖ 0x00 ‖ deviceName ‖ 0x00 ‖ fingerprint
        // It is raw SHA-256 output and may itself contain 0x00, so it is read from
        // the end and never split on a separator. Until 2026-10-16 the first
        // layout was split on the first 0x00 AFTER the machine ID, so any
        // fingerprint holding a zero byte (about 12% of them) lost its head to a
        // "device name" and read back short: the pin mismatched forever and the
        // Mac had to be paired again.
        guard data.count >= idBytes.count + 1 + Self.fingerprintLength else { return nil }
        let fpStart = data.endIndex - Self.fingerprintLength
        let separatorBeforeFP = data.index(before: fpStart)
        guard data[separatorBeforeFP] == 0x00 else { return nil }
        let fingerprint = TLSFingerprint(bytes: Array(data[fpStart...]))
        // First layout: the machine ID's separator IS the one before the
        // fingerprint. Otherwise the device name sits between the two (it was
        // written with NULs stripped, and may be empty).
        guard separatorBeforeFP > sep1 else {
            return PinnedPeer(machineID: machineID, fingerprint: fingerprint)
        }
        let nameBytes = data[data.index(after: sep1)..<separatorBeforeFP]
        let deviceName = String(data: nameBytes, encoding: .utf8) ?? ""
        return PinnedPeer(machineID: machineID, fingerprint: fingerprint, deviceName: deviceName)
    }

    /// SHA-256 of the peer's SPKI (`TLSFingerprint.ofSPKI`).
    static let fingerprintLength = 32

    /// The cache, keyed by machine ID. `parseRecord` already allows one pin per
    /// account within a service, and `bootstrap` adds a legacy pin only for a Mac
    /// the current service lacks, so a duplicate here means a bug upstream. It
    /// must still never trap: the FIRST pin wins (the current service is read
    /// before the legacy one), and the collision is logged.
    static func cacheIndex(_ peers: [PinnedPeer]) -> [String: PinnedPeer] {
        Dictionary(peers.map { ($0.machineID, $0) }) { first, _ in
            log.error("pinstore found two pins for one Mac; keeping the first")
            return first
        }
    }

    // MARK: Writes

    public func add(_ peer: PinnedPeer) {
        _ = addPersisting(peer)
    }

    /// Signs the pin whenever this store requires signatures, and refuses to
    /// write one it cannot sign then: an unsigned pin written after migration
    /// would be ignored at the next launch, so the Mac would silently fall off
    /// the paired list a day after pairing. Before migration (no anchor), pins
    /// are written unsigned exactly as earlier releases wrote them and are
    /// signed by the migration; signing them now would leave signed pins with
    /// no anchor if the anchor never gets written, which reads as tampering.
    public func addPersisting(_ peer: PinnedPeer) -> Bool {
        Self.keychainLock.lock()
        defer { Self.keychainLock.unlock() }
        if !requiresSignatures {
            // Another store in this process (or a later launch's) may have
            // migrated since this one bootstrapped.
            switch keychain.list(service: Self.anchorService(for: service)) {
            case .items(let anchors): if !anchors.isEmpty { requiresSignatures = true }
            case .failed(let status):
                Self.log.error("pinstore could not read its signature anchor before a write: OSStatus \(status, privacy: .public)")
                return false
            }
        }
        let data = Self.recordData(for: peer)
        var signature: Data?
        if requiresSignatures {
            guard let key = keyProvider(),
                  let raw = key.sign(Self.recordMessage(service: service, account: peer.machineID, data: data)) else {
                Self.log.error("pinstore cannot sign a new pin, so it is not saved")
                return false
            }
            signature = Self.signatureBlob(raw)
        }
        guard persist(account: peer.machineID, data: data, signature: signature) else {
            // Update failure leaves the old durable item intact. Keep the matching
            // old cache entry rather than publishing the unpersisted replacement.
            return false
        }
        cache.withLock { $0[peer.machineID] = peer }
        return true
    }

    /// Atomic update-or-add. A transient update failure must never destroy an
    /// existing durable pin; only a genuine not-found result takes the add path.
    /// Data and signature go in ONE call, so no reader ever sees one without the
    /// other.
    private func persist(account: String, data: Data, signature: Data?) -> Bool {
        let updateStatus = keychain.update(service: service, account: account, data: data, signature: signature)
        if updateStatus == errSecSuccess { return true }
        guard updateStatus == errSecItemNotFound else {
            Self.log.error("pinstore update failed: OSStatus \(updateStatus, privacy: .public)")
            return false
        }
        let addStatus = keychain.add(service: service, account: account, data: data, signature: signature)
        if addStatus == errSecSuccess { return true }

        // Another process/store instance may have inserted the same account
        // between our update miss and add. Retry the non-destructive update once;
        // never delete the winner and create a durability gap.
        if addStatus == errSecDuplicateItem {
            let retryStatus = keychain.update(service: service, account: account, data: data, signature: signature)
            if retryStatus == errSecSuccess { return true }
            Self.log.error("pinstore duplicate retry failed: OSStatus \(retryStatus, privacy: .public)")
            return false
        }
        Self.log.error("pinstore add failed: OSStatus \(addStatus, privacy: .public)")
        return false
    }

    public func remove(machineID: String) {
        Self.keychainLock.lock()
        defer { Self.keychainLock.unlock() }
        // Trust must disappear immediately in this process even if disk deletion
        // later reports a Keychain fault.
        cache.withLock { $0[machineID] = nil }
        removeFrom(service: service, machineID: machineID)
        if let legacyService { removeFrom(service: legacyService, machineID: machineID) }
    }

    private func removeFrom(service: String, machineID: String) {
        let status = keychain.delete(service: service, account: machineID)
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
    /// RFC 5280 §4.1.2.5 validity time: UTCTime ("YYMMDDHHMMSSZ") through 2049,
    /// GeneralizedTime ("YYYYMMDDHHMMSSZ") from 2050. UTCTime's two-digit year
    /// reads "50"–"99" as 1950–1999, so until 2026-10-16, when every notAfter was
    /// UTCTime, a certificate made in 2030 or later claimed to have expired 80
    /// years before it was issued (pin verification ignores expiry, which is the
    /// only reason that never broke a handshake).
    static func time(_ date: Date) -> [UInt8] {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        let year = cal.component(.year, from: date)
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = TimeZone(identifier: "UTC")!
        if (1950...2049).contains(year) {
            fmt.dateFormat = "yyMMddHHmmss'Z'"
            return tlv(0x17, Array(fmt.string(from: date).utf8))
        }
        fmt.dateFormat = "yyyyMMddHHmmss'Z'"
        return tlv(0x18, Array(fmt.string(from: date).utf8))
    }

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
        let loaded = try processKey(label: label, legacyLabels: legacyLabels)
        let built = try makeSelfSigned(label: label, privateKey: loaded.key)
        return (built.identity, built.spkiDER, loaded.detached)
    }

    /// The identity key stored under `label`, loaded ONCE per process and then
    /// shared by everything that needs it: the TLS identity, and the pin store,
    /// which signs and verifies pins with it (`PinSigningIdentity`). Sharing the
    /// one resolution is what makes "the key that signs pins" and "the key this
    /// Mac presents in TLS" the same key by construction. Resolving it twice
    /// could, with a second key planted under the same label, give two answers.
    ///
    /// Which key a label resolves to is unchanged (`copyKey`: the keychain's
    /// first match). Changing it would change this Mac's fingerprint on any
    /// keychain that holds duplicates, breaking every pairing it has.
    static func processKey(label: String, legacyLabels: [String] = []) throws -> (key: SecKey, detached: Bool) {
        processKeyLock.lock()
        defer { processKeyLock.unlock() }
        if let loaded = processKeys[label] { return loaded }
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
        processKeys[label] = loaded
        return loaded
    }

    /// Guards `processKeys`; held across the load so two first callers (the
    /// pin store's bootstrap and the TLS identity) never load twice.
    private static let processKeyLock = NSLock()
    nonisolated(unsafe) private static var processKeys: [String: (key: SecKey, detached: Bool)] = [:]

    /// Tests only: make the next `processKey` read the keychain again.
    static func forgetProcessKeys() {
        processKeyLock.lock()
        processKeys = [:]
        processKeyLock.unlock()
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

    /// Hand-builds a self-signed certificate over `privateKey` and pairs the two.
    public static func makeSelfSigned(label: String, privateKey: SecKey) throws
        -> (identity: SecIdentity, spkiDER: [UInt8]) {
        try makeSelfSigned(label: label, privateKey: privateKey, now: Date())
    }

    /// `now` is injectable so the validity encoding can be tested for any year.
    static func makeSelfSigned(label: String, privateKey: SecKey, now: Date) throws
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
        let (notBefore, notAfter) = validityWindow(years: 20, now: now)
        let validity = DER.sequence([DER.time(notBefore), DER.time(notAfter)])

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
    ///
    /// With more than one key under the label this returns the keychain's first
    /// match, which on the legacy keychain is the earliest inserted (probed
    /// 2026-10-17: three keys added in turn under one label, a single-match
    /// lookup returned the first every time; keys carry no creation date to
    /// choose by). A key another program plants under our label later is
    /// therefore never the one returned; the count is logged so the case is
    /// visible.
    private static func copyKey(label: String) -> SecKey? {
        logIfLabelIsShared(label)
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

    private static func logIfLabelIsShared(_ label: String) {
        let count: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrLabel as String: label,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var rows: CFTypeRef?
        guard SecItemCopyMatching(count as CFDictionary, &rows) == errSecSuccess,
              let n = (rows as? [[String: Any]])?.count, n > 1 else { return }
        Self.log.error("identity: \(n, privacy: .public) keys share the identity label; using the first")
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

    /// notBefore = now, notAfter = now + `years`. The certificate is rebuilt at
    /// every launch, so from 2030 on notAfter lands in 2050 or later, which
    /// `DER.time` must encode as GeneralizedTime (see there).
    private static func validityWindow(years: Int, now: Date) -> (Date, Date) {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return (now, cal.date(byAdding: .year, value: years, to: now) ?? now)
    }
}
