import CryptoKit
import Foundation
import Security
import Testing
@testable import ContinuoSecurityTransport

/// Signed pins (review finding H7). Every scenario runs against an in-memory
/// keychain and a CryptoKit P-256 key, so each one can stage exactly the
/// keychain state it is about: a release that never signed, a launch that
/// died half way through signing, an item another program overwrote.
@Suite struct SignedPinStoreTests {

    // MARK: - Fakes

    /// One generic-password item: its data, and its `kSecAttrGeneric`.
    struct Item: Equatable { var data: Data; var signature: Data? }

    /// The legacy keychain as the pin store sees it: items per service, kept
    /// in insertion order, plus switches for the failures under test.
    final class FakeKeychain: PinKeychain, @unchecked Sendable {
        private let lock = NSLock()
        private var services: [String: [(account: String, item: Item)]] = [:]
        private var dataReads: [String: Int] = [:]
        var failingSignatureWrites: Set<String> = []
        var failingListServices: Set<String> = []
        var failingAdds: Set<String> = []

        func items(_ service: String) -> [String: Item] {
            lock.lock(); defer { lock.unlock() }
            return Dictionary(uniqueKeysWithValues: (services[service] ?? []).map { ($0.account, $0.item) })
        }
        func reads(_ service: String, _ account: String) -> Int {
            lock.lock(); defer { lock.unlock() }
            return dataReads["\(service)|\(account)"] ?? 0
        }
        /// What any program running as the user may do: write an item outright.
        func plant(_ service: String, _ account: String, data: Data, signature: Data?) {
            lock.lock(); defer { lock.unlock() }
            var list = services[service] ?? []
            if let i = list.firstIndex(where: { $0.account == account }) {
                list[i].item = Item(data: data, signature: signature)
            } else {
                list.append((account, Item(data: data, signature: signature)))
            }
            services[service] = list
        }
        func erase(_ service: String, _ account: String) {
            lock.lock(); defer { lock.unlock() }
            services[service]?.removeAll { $0.account == account }
        }

        func list(service: String) -> PinKeychainListing {
            lock.lock(); defer { lock.unlock() }
            if failingListServices.contains(service) { return .failed(errSecInteractionNotAllowed) }
            return .items((services[service] ?? []).map { PinKeychainItem(account: $0.account, signature: $0.item.signature) })
        }
        func data(service: String, account: String) -> Data? {
            lock.lock(); defer { lock.unlock() }
            dataReads["\(service)|\(account)", default: 0] += 1
            return services[service]?.first { $0.account == account }?.item.data
        }
        func update(service: String, account: String, data: Data?, signature: Data?) -> OSStatus {
            lock.lock(); defer { lock.unlock() }
            guard let i = services[service]?.firstIndex(where: { $0.account == account }) else { return errSecItemNotFound }
            if signature != nil, failingSignatureWrites.contains(account) { return errSecInteractionNotAllowed }
            if let data { services[service]![i].item.data = data }
            if let signature { services[service]![i].item.signature = signature }
            return errSecSuccess
        }
        func add(service: String, account: String, data: Data, signature: Data?) -> OSStatus {
            lock.lock(); defer { lock.unlock() }
            if failingAdds.contains(service) { return errSecInteractionNotAllowed }
            if services[service]?.contains(where: { $0.account == account }) == true { return errSecDuplicateItem }
            if signature != nil, failingSignatureWrites.contains(account) { return errSecInteractionNotAllowed }
            services[service, default: []].append((account, Item(data: data, signature: signature)))
            return errSecSuccess
        }
        func delete(service: String, account: String) -> OSStatus {
            lock.lock(); defer { lock.unlock() }
            guard services[service]?.contains(where: { $0.account == account }) == true else { return errSecItemNotFound }
            services[service]!.removeAll { $0.account == account }
            return errSecSuccess
        }
    }

    struct FakeKey: PinRecordKey {
        let key = P256.Signing.PrivateKey()
        func sign(_ message: Data) -> Data? { try? key.signature(for: message).derRepresentation }
        func isValidSignature(_ signature: Data, for message: Data) -> Bool {
            guard let s = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            return key.publicKey.isValidSignature(s, for: message)
        }
    }

    /// A key the test can withhold, as a locked keychain withholds the real one.
    final class KeySlot: @unchecked Sendable {
        private let lock = NSLock()
        private var key: PinRecordKey?
        init(_ key: PinRecordKey?) { self.key = key }
        var current: PinRecordKey? { get { lock.lock(); defer { lock.unlock() }; return key }
                                     set { lock.lock(); key = newValue; lock.unlock() } }
    }

    // MARK: - Helpers

    static let service = "test.pin"
    var anchorService: String { KeychainPinStore.anchorService(for: Self.service) }

    func fp(_ b: UInt8) -> TLSFingerprint { TLSFingerprint(bytes: Array(repeating: b, count: 32)) }
    func peer(_ id: String, _ b: UInt8, _ name: String = "Mac") -> PinnedPeer {
        PinnedPeer(machineID: id, fingerprint: fp(b), deviceName: name)
    }

    /// The encoder every release up to v26.10.16-beta-443 shipped, copied from
    /// its `KeychainPinStore.value(for:)`. Older releases must keep reading what
    /// this release writes, so the record bytes must stay exactly these.
    func previousReleaseRecord(_ peer: PinnedPeer) -> Data {
        var d = Data(peer.machineID.utf8)
        d.append(0x00)
        d.append(Data(peer.deviceName.replacingOccurrences(of: "\u{0}", with: "").utf8))
        d.append(0x00)
        d.append(contentsOf: peer.fingerprint.bytes)
        return d
    }

    /// What an older release leaves behind: data only, no signature.
    func plantUnsigned(_ kc: FakeKeychain, _ p: PinnedPeer, service: String = SignedPinStoreTests.service) {
        kc.plant(service, p.machineID, data: previousReleaseRecord(p), signature: nil)
    }

    func store(_ kc: FakeKeychain, _ key: PinRecordKey?, service: String = SignedPinStoreTests.service,
               legacy: String? = nil) -> KeychainPinStore {
        KeychainPinStore(service: service, legacyService: legacy, keychain: kc, key: { key })
    }
    func store(_ kc: FakeKeychain, slot: KeySlot) -> KeychainPinStore {
        KeychainPinStore(service: Self.service, legacyService: nil, keychain: kc, key: { slot.current })
    }

    func ids(_ s: KeychainPinStore) -> Set<String> { Set(s.load().map(\.machineID)) }

    func isSigned(_ kc: FakeKeychain, _ key: PinRecordKey, _ account: String,
                  service: String = SignedPinStoreTests.service) -> Bool {
        guard let item = kc.items(service)[account], let blob = item.signature,
              let raw = KeychainPinStore.rawSignature(fromBlob: blob) else { return false }
        return key.isValidSignature(raw, for: KeychainPinStore.recordMessage(service: service, account: account,
                                                                             data: item.data))
    }

    // MARK: - Format

    @Test func recordBytesAreExactlyWhatThePreviousReleaseWrote() {
        let kc = FakeKeychain(); let key = FakeKey()
        let s = store(kc, key)
        let peers = [peer("m-1", 0xAB, "Desk Mac"), peer("m-2", 0x00, ""), peer("m-3", 0x11, "Na\u{0}me")]
        for p in peers { #expect(s.addPersisting(p)) }
        for p in peers {
            #expect(kc.items(Self.service)[p.machineID]?.data == previousReleaseRecord(p))
            #expect(KeychainPinStore.recordData(for: p) == previousReleaseRecord(p))
        }
    }

    @Test func signatureCoversServiceAccountAndRecord() {
        let data = previousReleaseRecord(peer("m-1", 1))
        let base = KeychainPinStore.recordMessage(service: "a", account: "m-1", data: data)
        #expect(base != KeychainPinStore.recordMessage(service: "b", account: "m-1", data: data))
        #expect(base != KeychainPinStore.recordMessage(service: "a", account: "m-2", data: data))
        #expect(base != KeychainPinStore.recordMessage(service: "a", account: "m-1", data: data + Data([0])))
        // Length-prefixed, so moving bytes between fields cannot keep the message.
        #expect(KeychainPinStore.recordMessage(service: "ab", account: "c", data: data)
                != KeychainPinStore.recordMessage(service: "a", account: "bc", data: data))
    }

    // MARK: - (a) first install

    @Test func firstInstallWritesTheAnchorAndSignsEveryNewPin() {
        let kc = FakeKeychain(); let key = FakeKey()
        let s = store(kc, key)
        #expect(s.load().isEmpty)
        #expect(kc.items(anchorService)[KeychainPinStore.anchorAccount] != nil)
        #expect(s.addPersisting(peer("m-1", 1)))
        #expect(isSigned(kc, key, "m-1"))
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    // MARK: - (b) upgrade with pins

    @Test func upgradeSignsEveryExistingPinInPlaceWithoutChangingItsBytes() {
        let kc = FakeKeychain(); let key = FakeKey()
        let peers = [peer("m-1", 1, "One"), peer("m-2", 2, ""), peer("m-3", 0, "Three")]
        for p in peers { plantUnsigned(kc, p) }
        // The very first layout (no device name, one separator) is signed as is.
        var first = Data("m-4".utf8); first.append(0x00); first.append(contentsOf: fp(4).bytes)
        kc.plant(Self.service, "m-4", data: first, signature: nil)
        let before = kc.items(Self.service).mapValues(\.data)

        let s = store(kc, key)
        #expect(ids(s) == ["m-1", "m-2", "m-3", "m-4"])
        #expect(kc.items(Self.service).mapValues(\.data) == before)
        for id in ["m-1", "m-2", "m-3", "m-4"] { #expect(isSigned(kc, key, id)) }
        #expect(kc.items(anchorService)[KeychainPinStore.anchorAccount] != nil)
        #expect(ids(store(kc, key)) == ["m-1", "m-2", "m-3", "m-4"])
    }

    @Test func pinsFoundOnlyUnderTheRenamedServiceAreBroughtAcrossAndSigned() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("old-1", 1), service: "legacy.pin")
        let s = store(kc, key, legacy: "legacy.pin")
        #expect(ids(s) == ["old-1"])
        #expect(isSigned(kc, key, "old-1"))
        #expect(kc.items("legacy.pin").isEmpty)
    }

    @Test func afterMigrationTheRenamedServiceIsNoLongerImported() {
        let kc = FakeKeychain(); let key = FakeKey()
        _ = store(kc, key, legacy: "legacy.pin")
        plantUnsigned(kc, peer("planted", 9), service: "legacy.pin")
        #expect(store(kc, key, legacy: "legacy.pin").load().isEmpty)
        #expect(kc.reads("legacy.pin", "planted") == 0)
    }

    // MARK: - (c) key not readable right now

    @Test func withoutTheKeyPinsWorkAsTodayAndMigrationWaitsForTheNextLaunch() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1)); plantUnsigned(kc, peer("m-2", 2))
        let slot = KeySlot(nil)
        let s = store(kc, slot: slot)
        #expect(ids(s) == ["m-1", "m-2"])
        #expect(kc.items(anchorService).isEmpty)
        #expect(kc.items(Self.service).values.allSatisfy { $0.signature == nil })
        // A pairing made meanwhile is kept the old way and swept up later.
        #expect(s.addPersisting(peer("m-3", 3)))
        #expect(ids(s) == ["m-1", "m-2", "m-3"])

        slot.current = key
        let next = store(kc, slot: slot)
        #expect(ids(next) == ["m-1", "m-2", "m-3"])
        for id in ["m-1", "m-2", "m-3"] { #expect(isSigned(kc, key, id)) }
    }

    @Test func afterMigrationAMissingKeyTrustsNothingAndRefusesToWrite() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1))
        _ = store(kc, key)
        let blind = store(kc, nil)
        #expect(blind.load().isEmpty)
        #expect(!blind.addPersisting(peer("m-2", 2)))
        #expect(kc.items(Self.service)["m-2"] == nil)
        // Nothing was lost: with the key back, the pin is there again.
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    @Test func aWriteChecksForAnAnchorAnotherStoreCreatedMeanwhile() {
        let kc = FakeKeychain(); let key = FakeKey()
        let slot = KeySlot(nil)
        let early = store(kc, slot: slot)          // grandfathered: no key yet
        slot.current = key
        _ = store(kc, slot: slot)                  // another store migrates
        #expect(early.addPersisting(peer("m-1", 1)))
        #expect(isSigned(kc, key, "m-1"))
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    // MARK: - (d) a launch that died half way

    @Test func aMigrationInterruptedAfterThreePinsFinishesOnTheNextLaunch() {
        let kc = FakeKeychain(); let key = FakeKey()
        for (i, id) in ["m-1", "m-2", "m-3", "m-4", "m-5"].enumerated() { plantUnsigned(kc, peer(id, UInt8(i + 1))) }
        kc.failingSignatureWrites = ["m-4", "m-5"]
        let s = store(kc, key)
        #expect(ids(s) == ["m-1", "m-2", "m-3", "m-4", "m-5"])
        #expect(!isSigned(kc, key, "m-4"))

        kc.failingSignatureWrites = []
        let next = store(kc, key)
        #expect(ids(next) == ["m-1", "m-2", "m-3", "m-4", "m-5"])
        for id in ["m-1", "m-2", "m-3", "m-4", "m-5"] { #expect(isSigned(kc, key, id)) }
        // Finished: the anchor no longer lists anything left to sign.
        #expect(KeychainPinStore.anchorManifest(fromBlob: kc.items(anchorService)[KeychainPinStore.anchorAccount]!.signature!)?.isEmpty == true)
    }

    @Test func anInterruptedMigrationNeverAdoptsAPinThatWasNotThereWhenItStarted() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1)); plantUnsigned(kc, peer("m-2", 2))
        kc.failingSignatureWrites = ["m-2"]
        _ = store(kc, key)
        kc.failingSignatureWrites = []
        // Between the two launches another program adds a pin and rewrites m-2.
        plantUnsigned(kc, peer("planted", 9))
        plantUnsigned(kc, peer("m-2", 0xEE, "Attacker"))
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    @Test func anAnchorThatCannotBeWrittenLeavesEverythingAsTodayForTheNextLaunch() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1))
        kc.failingAdds = [anchorService]
        let s = store(kc, key)
        #expect(ids(s) == ["m-1"])
        #expect(!isSigned(kc, key, "m-1"))
        #expect(s.addPersisting(peer("m-2", 2)))
        kc.failingAdds = []
        let next = store(kc, key)
        #expect(ids(next) == ["m-1", "m-2"])
        #expect(isSigned(kc, key, "m-1") && isSigned(kc, key, "m-2"))
    }

    // MARK: - (e)/(f) downgrade, then upgrade again

    @Test func aPinAnOlderReleaseAddedAfterMigrationIsIgnoredAndNeverRead() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1))
        _ = store(kc, key)
        plantUnsigned(kc, peer("m-2", 2))          // paired while downgraded
        let s = store(kc, key)
        #expect(ids(s) == ["m-1"])
        #expect(kc.reads(Self.service, "m-2") == 0)
        // Pairing that Mac again signs its item and it is back.
        #expect(s.addPersisting(peer("m-2", 2)))
        #expect(ids(store(kc, key)) == ["m-1", "m-2"])
    }

    @Test func aPinAnOlderReleaseRewroteKeepsAStaleSignatureAndIsIgnored() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1, "Old Name"))
        _ = store(kc, key)
        let sig = kc.items(Self.service)["m-1"]!.signature
        kc.plant(Self.service, "m-1", data: previousReleaseRecord(peer("m-1", 1, "New Name")), signature: sig)
        #expect(store(kc, key).load().isEmpty)
    }

    // MARK: - (g)/(h) other services

    @Test func twoInstancesOnOneMacKeepSeparateStoresAndKeys() {
        let kc = FakeKeychain(); let keyA = FakeKey(); let keyB = FakeKey()
        let a = store(kc, keyA, service: "pin.A"); let b = store(kc, keyB, service: "pin.B")
        #expect(a.addPersisting(peer("m-1", 1))); #expect(b.addPersisting(peer("m-2", 2)))
        let copied = kc.items("pin.A")["m-1"]!
        kc.plant("pin.B", "m-1", data: copied.data, signature: copied.signature)
        #expect(ids(store(kc, keyA, service: "pin.A")) == ["m-1"])
        #expect(ids(store(kc, keyB, service: "pin.B")) == ["m-2"])
    }

    @Test func aMainPinCopiedIntoTheLoginWindowServiceDoesNotVerify() {
        let kc = FakeKeychain(); let key = FakeKey()
        let login = Self.service + ".login-window"
        let main = store(kc, key); let lw = store(kc, key, service: login)
        #expect(main.addPersisting(peer("m-1", 1))); #expect(lw.addPersisting(peer("m-2", 2)))
        #expect(isSigned(kc, key, "m-2", service: login))
        let copied = kc.items(Self.service)["m-1"]!
        kc.plant(login, "m-1", data: copied.data, signature: copied.signature)
        #expect(ids(store(kc, key, service: login)) == ["m-2"])
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    // MARK: - (i) unpair

    @Test func unpairRemovesSignedAndIgnoredItemsAlike() {
        let kc = FakeKeychain(); let key = FakeKey()
        let s = store(kc, key)
        #expect(s.addPersisting(peer("m-1", 1)))
        plantUnsigned(kc, peer("m-2", 2))
        s.remove(machineID: "m-1"); s.remove(machineID: "m-2")
        #expect(kc.items(Self.service).isEmpty)
        #expect(store(kc, key).load().isEmpty)
        #expect(kc.items(anchorService)[KeychainPinStore.anchorAccount] != nil)
    }

    // MARK: - (j) concurrent stores in one process

    @Test func concurrentStoresMigrateOnceAndAgree() {
        let kc = FakeKeychain(); let key = FakeKey()
        for i in 0..<8 { plantUnsigned(kc, peer("m-\(i)", UInt8(i + 1))) }
        DispatchQueue.concurrentPerform(iterations: 16) { i in
            let s = store(kc, key)
            _ = s.load()
            if i % 2 == 0 { _ = s.addPersisting(peer("n-\(i)", UInt8(100 + i))) }
        }
        #expect(kc.items(anchorService).count == 1)
        let all = ids(store(kc, key))
        #expect(all.count == 16)
        for id in all { #expect(isSigned(kc, key, id)) }
    }

    // MARK: - Tampering

    @Test func anotherPinsSignatureCopiedOntoAnItemDoesNotVerify() {
        let kc = FakeKeychain(); let key = FakeKey()
        let s = store(kc, key)
        #expect(s.addPersisting(peer("m-1", 1))); #expect(s.addPersisting(peer("m-2", 2)))
        let m1 = kc.items(Self.service)["m-1"]!
        kc.plant(Self.service, "m-2", data: previousReleaseRecord(peer("m-2", 0xEE)), signature: m1.signature)
        kc.plant(Self.service, "m-3", data: previousReleaseRecord(peer("m-3", 0xEE)), signature: m1.signature)
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    @Test func dataOverwrittenUnderAValidSignatureDoesNotVerify() {
        let kc = FakeKeychain(); let key = FakeKey()
        let s = store(kc, key)
        #expect(s.addPersisting(peer("m-1", 1)))
        let sig = kc.items(Self.service)["m-1"]!.signature
        kc.plant(Self.service, "m-1", data: previousReleaseRecord(peer("m-1", 0xEE)), signature: sig)
        #expect(store(kc, key).load().isEmpty)
    }

    @Test func garbageSignatureIsIgnoredWithoutReadingTheItem() {
        let kc = FakeKeychain(); let key = FakeKey()
        _ = store(kc, key)
        kc.plant(Self.service, "m-9", data: previousReleaseRecord(peer("m-9", 9)), signature: Data("garbage".utf8))
        #expect(store(kc, key).load().isEmpty)
        #expect(kc.reads(Self.service, "m-9") == 0)
    }

    @Test func aWellFormedForgedSignatureIsIgnored() {
        let kc = FakeKeychain(); let key = FakeKey(); let attacker = FakeKey()
        _ = store(kc, key)
        let data = previousReleaseRecord(peer("m-9", 9))
        let forged = attacker.sign(KeychainPinStore.recordMessage(service: Self.service, account: "m-9", data: data))!
        kc.plant(Self.service, "m-9", data: data, signature: KeychainPinStore.signatureBlob(forged))
        #expect(store(kc, key).load().isEmpty)
    }

    @Test func aDeletedAnchorDoesNotReopenAdoptionOfUnsignedPins() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1))
        _ = store(kc, key)
        kc.erase(anchorService, KeychainPinStore.anchorAccount)
        plantUnsigned(kc, peer("planted", 9))
        let s = store(kc, key)
        #expect(ids(s) == ["m-1"])
        // The anchor is put back, so the condition cannot recur once m-1 is unpaired.
        #expect(kc.items(anchorService)[KeychainPinStore.anchorAccount] != nil)
        s.remove(machineID: "m-1")
        #expect(store(kc, key).load().isEmpty)
    }

    @Test func aForgedOrDamagedAnchorStopsAdoptionOfUnsignedPins() {
        for damaged in [Data("garbage".utf8), Data()] {
            let kc = FakeKeychain(); let key = FakeKey()
            plantUnsigned(kc, peer("m-1", 1))
            kc.plant(anchorService, KeychainPinStore.anchorAccount, data: Data("x".utf8), signature: damaged)
            #expect(store(kc, key).load().isEmpty)
            #expect(kc.items(Self.service)["m-1"]?.signature == nil)
        }
    }

    @Test func anAnchorSignedByAnotherKeyAdoptsNothing() {
        let kc = FakeKeychain(); let key = FakeKey(); let attacker = FakeKey()
        plantUnsigned(kc, peer("m-1", 1))
        // A well-formed anchor whose manifest names m-1, signed by the wrong key.
        _ = store(kc, attacker)
        #expect(store(kc, key).load().isEmpty)
    }

    @Test func anUnreadableAnchorServiceFailsClosed() {
        let kc = FakeKeychain(); let key = FakeKey()
        plantUnsigned(kc, peer("m-1", 1))
        kc.failingListServices = [anchorService]
        #expect(store(kc, key).load().isEmpty)
        #expect(kc.items(anchorService).isEmpty)
        kc.failingListServices = []
        #expect(ids(store(kc, key)) == ["m-1"])
    }

    @Test func aPinSignedByAPlantedSecondKeyDoesNotVerify() {
        // The verifier only ever uses the key this process presents in TLS;
        // a second key under the same label signs nothing it will accept.
        let kc = FakeKeychain(); let ours = FakeKey(); let planted = FakeKey()
        _ = store(kc, ours)
        let data = previousReleaseRecord(peer("m-9", 9))
        let sig = planted.sign(KeychainPinStore.recordMessage(service: Self.service, account: "m-9", data: data))!
        kc.plant(Self.service, "m-9", data: data, signature: KeychainPinStore.signatureBlob(sig))
        #expect(store(kc, ours).load().isEmpty)
    }

    @Test func twoItemsNamingOneMacStillNeverTrap() {
        let kc = FakeKeychain(); let key = FakeKey()
        let s = store(kc, key)
        #expect(s.addPersisting(peer("m-1", 1)))
        let m1 = kc.items(Self.service)["m-1"]!
        kc.plant(Self.service, "m-1-copy", data: m1.data, signature: m1.signature)
        #expect(ids(store(kc, key)) == ["m-1"])
    }
}
