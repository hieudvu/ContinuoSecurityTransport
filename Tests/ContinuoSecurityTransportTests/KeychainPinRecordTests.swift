import Foundation
import Testing
@testable import ContinuoSecurityTransport

/// The pure half of `KeychainPinStore`: turning one Keychain item (its account
/// plus its data) into a pin, and turning the items one bootstrap read into the
/// cache. The Keychain calls themselves are covered by a real-keychain round
/// trip in the network layer's test suite.
@Suite struct KeychainPinRecordTests {
    private func fingerprint(zeroAt positions: [Int], fill: UInt8 = 0xAB) -> TLSFingerprint {
        var bytes = [UInt8](repeating: fill, count: 32)
        for p in positions { bytes[p] = 0x00 }
        return TLSFingerprint(bytes: bytes)
    }

    /// The layout written from 2026-07-03 (`9e87cbc4`) to today.
    private func currentLayout(_ id: String, _ name: String, _ fp: TLSFingerprint) -> Data {
        var d = Data(id.utf8); d.append(0x00); d.append(Data(name.utf8)); d.append(0x00)
        d.append(contentsOf: fp.bytes)
        return d
    }

    /// The first layout (`0f6a9d05`): no device name, one separator.
    private func firstLayout(_ id: String, _ fp: TLSFingerprint) -> Data {
        var d = Data(id.utf8); d.append(0x00); d.append(contentsOf: fp.bytes)
        return d
    }

    // MARK: - Layouts (M15)

    @Test(arguments: [[], [0], [12], [31], [0, 1, 2], [5, 17, 30, 31]])
    func currentLayoutRoundTripsWhateverBytesTheFingerprintHolds(zeros: [Int]) {
        let fp = fingerprint(zeroAt: zeros)
        let peer = KeychainPinStore.parseRecord(account: "m-1", data: currentLayout("m-1", "Desk Mac", fp))
        #expect(peer == PinnedPeer(machineID: "m-1", fingerprint: fp, deviceName: "Desk Mac"))
    }

    /// 2026-10-16: the single-separator layout was split on the FIRST 0x00 after
    /// the machine ID, so a fingerprint holding a zero byte (about 12% of SHA-256
    /// outputs) lost everything before that zero to a "device name" and read back
    /// short. The pin then mismatched forever and the Mac had to be paired again.
    @Test(arguments: [[], [0], [12], [31], [3, 19]])
    func firstLayoutKeepsAll32FingerprintBytes(zeros: [Int]) {
        let fp = fingerprint(zeroAt: zeros)
        let peer = KeychainPinStore.parseRecord(account: "m-1", data: firstLayout("m-1", fp))
        #expect(peer == PinnedPeer(machineID: "m-1", fingerprint: fp, deviceName: ""))
    }

    @Test func emptyDeviceNameInCurrentLayout() {
        let fp = fingerprint(zeroAt: [0])
        let peer = KeychainPinStore.parseRecord(account: "m-1", data: currentLayout("m-1", "", fp))
        #expect(peer == PinnedPeer(machineID: "m-1", fingerprint: fp, deviceName: ""))
    }

    @Test func recordsTooShortOrWithoutTheSeparatorAreSkipped() {
        let fp = fingerprint(zeroAt: [])
        #expect(KeychainPinStore.parseRecord(account: "m-1", data: Data()) == nil)
        #expect(KeychainPinStore.parseRecord(account: "m-1", data: Data(fp.bytes)) == nil)
        var noSeparator = Data("m-1".utf8); noSeparator.append(contentsOf: fp.bytes)
        #expect(KeychainPinStore.parseRecord(account: "m-1", data: noSeparator) == nil)
        var emptyID = Data([0x00]); emptyID.append(contentsOf: fp.bytes)
        #expect(KeychainPinStore.parseRecord(account: "", data: emptyID) == nil)
    }

    // MARK: - Duplicates (crash)

    /// Every pin Continuo has ever written uses the machine ID as the item's
    /// account. An item whose data names a different Mac than its account was not
    /// written by Continuo, and two such items naming one Mac used to trap the app
    /// on every launch in `Dictionary(uniqueKeysWithValues:)`.
    @Test func recordWhoseDataNamesAnotherMacThanItsAccountIsSkipped() {
        let data = currentLayout("m-1", "Desk Mac", fingerprint(zeroAt: []))
        #expect(KeychainPinStore.parseRecord(account: "m-2", data: data) == nil)
    }

    @Test func indexingTwoPinsForOneMacKeepsTheFirstInsteadOfTrapping() {
        let first = PinnedPeer(machineID: "m-1", fingerprint: fingerprint(zeroAt: [], fill: 0x11))
        let second = PinnedPeer(machineID: "m-1", fingerprint: fingerprint(zeroAt: [], fill: 0x22))
        let other = PinnedPeer(machineID: "m-2", fingerprint: fingerprint(zeroAt: [], fill: 0x33))
        let index = KeychainPinStore.cacheIndex([first, other, second])
        #expect(index == ["m-1": first, "m-2": other])
    }
}
