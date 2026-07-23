import Testing
@testable import ContinuoSecurityTransport

@Suite struct TrustStorePureTests {
    private final class RejectingPinStore: PinStore, @unchecked Sendable {
        func load() -> [PinnedPeer] { [] }
        func add(_ peer: PinnedPeer) {}
        func remove(machineID: String) {}
    }

    private func fingerprint(_ byte: UInt8) -> TLSFingerprint {
        TLSFingerprint(bytes: Array(repeating: byte, count: 32))
    }

    @Test func matchingPinIsTrustedAndMismatchFailsClosed() {
        let store = InMemoryPinStore()
        let trust = TrustStore(pins: store)
        #expect(trust.pin(PinnedPeer(machineID: "A", fingerprint: fingerprint(0x11))))

        #expect(trust.evaluate(
            presented: fingerprint(0x11),
            claimedMachineID: "A"
        ) == .trusted(machineID: "A"))
        #expect(trust.evaluate(
            presented: fingerprint(0x22),
            claimedMachineID: "A"
        ) == .mismatch(machineID: "A"))
    }

    @Test func unknownAndUnpairedPeersAreNotTrusted() {
        let trust = TrustStore(pins: InMemoryPinStore())
        #expect(trust.evaluate(
            presented: fingerprint(0x33),
            claimedMachineID: "unknown"
        ) == .unknown)

        #expect(trust.pin(PinnedPeer(machineID: "A", fingerprint: fingerprint(0x11))))
        trust.unpair(machineID: "A")
        #expect(trust.evaluate(
            presented: fingerprint(0x11),
            claimedMachineID: "A"
        ) == .unknown)
    }

    @Test func persistenceFailureIsReported() {
        let trust = TrustStore(pins: RejectingPinStore())
        #expect(!trust.pin(PinnedPeer(machineID: "A", fingerprint: fingerprint(0x11))))
    }
}
