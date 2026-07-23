import Testing
@testable import ContinuoSecurityTransport

private struct MockTLSPeerPublicKeyMetadata: TLSPeerPublicKeyMetadata {
    let rawPublicKey: [UInt8]?

    func copyPeerPublicKeyBytes() -> [UInt8]? {
        rawPublicKey
    }
}

@Suite struct PeerConnectionFingerprintTests {
    @Test func derivesTheExistingSPKIFingerprintFromCompleteP256Metadata() {
        let point = Self.uncompressedPoint(seed: 1)
        let metadata = MockTLSPeerPublicKeyMetadata(rawPublicKey: point)

        let actual = PeerConnectionFingerprint.make(from: metadata)

        #expect(actual == TLSFingerprint.ofSPKI(SPKI.der(fromECPoint: point)))
    }

    @Test func rejectsMissingOrMalformedMetadataFailClosed() {
        #expect(PeerConnectionFingerprint.make(
            from: MockTLSPeerPublicKeyMetadata(rawPublicKey: nil)
        ) == nil)
        #expect(PeerConnectionFingerprint.make(
            from: MockTLSPeerPublicKeyMetadata(rawPublicKey: [])
        ) == nil)
        #expect(PeerConnectionFingerprint.make(
            from: MockTLSPeerPublicKeyMetadata(rawPublicKey: [0x04] + Array(repeating: 0x11, count: 63))
        ) == nil)
        #expect(PeerConnectionFingerprint.make(
            from: MockTLSPeerPublicKeyMetadata(rawPublicKey: [0x02] + Array(repeating: 0x11, count: 64))
        ) == nil)
    }

    @Test func concurrentConnectionsKeepDistinctPerConnectionFingerprints() async {
        let pointA = Self.uncompressedPoint(seed: 7)
        let pointB = Self.uncompressedPoint(seed: 91)
        let sourceA = MockTLSPeerPublicKeyMetadata(rawPublicKey: pointA)
        let sourceB = MockTLSPeerPublicKeyMetadata(rawPublicKey: pointB)

        async let fingerprintA = Task.detached {
            PeerConnectionFingerprint.make(from: sourceA)
        }.value
        async let fingerprintB = Task.detached {
            PeerConnectionFingerprint.make(from: sourceB)
        }.value

        let (actualA, actualB) = await (fingerprintA, fingerprintB)
        let expectedA = TLSFingerprint.ofSPKI(SPKI.der(fromECPoint: pointA))
        let expectedB = TLSFingerprint.ofSPKI(SPKI.der(fromECPoint: pointB))

        #expect(actualA == expectedA)
        #expect(actualB == expectedB)
        #expect(actualA != actualB)
    }

    @Test func admissionProvidersStayBoundToTheirOwnMetadata() {
        let first = MockTLSPeerPublicKeyMetadata(rawPublicKey: Self.uncompressedPoint(seed: 11))
        let second = MockTLSPeerPublicKeyMetadata(rawPublicKey: Self.uncompressedPoint(seed: 29))

        let firstProvider = SecureInboundTLSAdmission.fingerprintProvider(metadata: first)
        let secondProvider = SecureInboundTLSAdmission.fingerprintProvider(metadata: second)

        #expect(firstProvider() == PeerConnectionFingerprint.make(from: first))
        #expect(secondProvider() == PeerConnectionFingerprint.make(from: second))
        #expect(firstProvider() != secondProvider())
    }

    private static func uncompressedPoint(seed: UInt8) -> [UInt8] {
        [0x04] + (0 ..< 64).map { seed &+ UInt8($0) }
    }
}
