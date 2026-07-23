import Testing
@testable import ContinuoSecurityTransport

@Suite struct PairingSessionTests {
    private struct Transcript {
        var sasA: UInt32?
        var sasB: UInt32?
        var pinA: PinnedPeer?
        var pinB: PinnedPeer?
        var failed = false
    }

    @Test func bothSidesNegotiateThenReachSameSASAndPinEachOther() {
        var (a, b) = Self.makePair()
        var transcript = Transcript()

        var fromA = a.start()
        var fromB = b.start()

        #expect(fromA.count == 2)
        #expect(fromB.count == 1)
        if case let .send(.negotiate(version)) = fromA[0] {
            #expect(version == SecurityHandshakeProtocol.version)
        } else {
            Issue.record("host must negotiate before committing")
        }
        if case .send(.pairCommit) = fromA[1] {} else {
            Issue.record("host must commit after negotiation")
        }
        if case let .send(.negotiate(version)) = fromB[0] {
            #expect(version == SecurityHandshakeProtocol.version)
        } else {
            Issue.record("responder must negotiate when started")
        }

        for _ in 0 ..< 8 {
            let nextFromB = Self.deliver(
                fromA,
                ownerSAS: &transcript.sasA,
                ownerPin: &transcript.pinA,
                ownerFailed: &transcript.failed,
                into: &b
            )
            let nextFromA = Self.deliver(
                fromB,
                ownerSAS: &transcript.sasB,
                ownerPin: &transcript.pinB,
                ownerFailed: &transcript.failed,
                into: &a
            )
            fromA = nextFromA
            fromB = nextFromB
        }

        let aConfirmation = a.userConfirmed()
        #expect(Self.pinsBeforeConfirm(aConfirmation))
        _ = Self.deliver(
            aConfirmation,
            ownerSAS: &transcript.sasA,
            ownerPin: &transcript.pinA,
            ownerFailed: &transcript.failed,
            into: &b
        )
        let bConfirmation = b.userConfirmed()
        #expect(Self.pinsBeforeConfirm(bConfirmation))
        _ = Self.deliver(
            bConfirmation,
            ownerSAS: &transcript.sasB,
            ownerPin: &transcript.pinB,
            ownerFailed: &transcript.failed,
            into: &a
        )

        #expect(!transcript.failed)
        #expect(transcript.sasA != nil && transcript.sasA == transcript.sasB)
        #expect(transcript.pinA?.machineID == "B")
        #expect(transcript.pinB?.machineID == "A")
        #expect(a.userConfirmed().isEmpty)
        #expect(b.userConfirmed().isEmpty)
    }

    @Test func unsupportedVersionFailsClosedBeforeSAS() {
        var (host, _) = Self.makePair()

        let events = host.handle(.negotiate(version: SecurityHandshakeProtocol.version &+ 1))

        #expect(events == [.failed(.unsupportedProtocolVersion)])
        #expect(host.pairedPeerMachineID == nil)
    }

    @Test func commitmentBeforeNegotiationFailsClosed() {
        var (host, _) = Self.makePair()

        let events = host.handle(.pairCommit(commitment: Array(repeating: 0xAB, count: 32)))

        #expect(events == [.failed(.unexpectedMessage)])
        #expect(host.pairedPeerMachineID == nil)
    }

    @Test func confirmationBeforeVerifiedSASFailsClosed() {
        var (host, _) = Self.makePair()
        _ = host.start()
        _ = host.handle(.negotiate(version: SecurityHandshakeProtocol.version))

        let events = host.handle(.pairSasConfirm(accepted: true))

        #expect(events == [.failed(.unexpectedMessage)])
        #expect(host.pairedPeerMachineID == nil)
    }

    @Test func fingerprintMismatchFailsClosed() {
        let aKP = PairingKeyPair()
        let bKP = PairingKeyPair()
        let fpA = TLSFingerprint(bytes: Array(repeating: 1, count: 32))
        let fpB = TLSFingerprint(bytes: Array(repeating: 2, count: 32))
        let wrong = TLSFingerprint(bytes: Array(repeating: 9, count: 32))
        var a = PairingSession(
            role: .host,
            selfMachineID: "A",
            selfDeviceName: "Mac A",
            selfFingerprint: fpA,
            localKeyPair: aKP,
            presentedPeerFingerprint: wrong
        )
        var b = PairingSession(
            role: .client,
            selfMachineID: "B",
            selfDeviceName: "Mac B",
            selfFingerprint: fpB,
            localKeyPair: bKP,
            presentedPeerFingerprint: fpA
        )
        var transcript = Transcript()
        var fromA = a.start()
        var fromB = b.start()

        for _ in 0 ..< 8 {
            let nextFromB = Self.deliver(
                fromA,
                ownerSAS: &transcript.sasA,
                ownerPin: &transcript.pinA,
                ownerFailed: &transcript.failed,
                into: &b
            )
            let nextFromA = Self.deliver(
                fromB,
                ownerSAS: &transcript.sasB,
                ownerPin: &transcript.pinB,
                ownerFailed: &transcript.failed,
                into: &a
            )
            fromA = nextFromA
            fromB = nextFromB
        }

        #expect(transcript.failed)
        #expect(transcript.sasA == nil)
        #expect(transcript.pinA == nil)
    }

    @Test func ingressRoutesOnlyPairingMessagesWhilePairingIsActive() {
        #expect(PairingIngress.decide(.negotiate(version: 1), pairingActive: true) == .drive)
        #expect(PairingIngress.decide(.pairCommit(commitment: []), pairingActive: true) == .drive)
        #expect(PairingIngress.decide(.failure(.authenticationFailed), pairingActive: true) == .drive)
        #expect(PairingIngress.decide(.pairSasConfirm(accepted: true), pairingActive: true) == .peerConfirmation(true))
        #expect(PairingIngress.decide(.pairSasConfirm(accepted: false), pairingActive: true) == .reject)
        #expect(PairingIngress.decide(.sessionKeyOffer(ephPublicKey: []), pairingActive: true) == .reject)
        #expect(PairingIngress.decide(.complete, pairingActive: true) == .reject)
        #expect(PairingIngress.decide(.negotiate(version: 1), pairingActive: false) == .reject)
    }

    private static func makePair() -> (PairingSession, PairingSession) {
        let aKP = PairingKeyPair()
        let bKP = PairingKeyPair()
        let fpA = TLSFingerprint(bytes: Array(repeating: 1, count: 32))
        let fpB = TLSFingerprint(bytes: Array(repeating: 2, count: 32))
        return (
            PairingSession(
                role: .host,
                selfMachineID: "A",
                selfDeviceName: "Mac A",
                selfFingerprint: fpA,
                localKeyPair: aKP,
                presentedPeerFingerprint: fpB
            ),
            PairingSession(
                role: .client,
                selfMachineID: "B",
                selfDeviceName: "Mac B",
                selfFingerprint: fpB,
                localKeyPair: bKP,
                presentedPeerFingerprint: fpA
            )
        )
    }

    private static func deliver(
        _ events: [PairingEvent],
        ownerSAS: inout UInt32?,
        ownerPin: inout PinnedPeer?,
        ownerFailed: inout Bool,
        into peer: inout PairingSession
    ) -> [PairingEvent] {
        var response: [PairingEvent] = []
        for event in events {
            switch event {
            case let .send(message):
                response += peer.handle(message)
            case let .displaySAS(value):
                ownerSAS = value
            case let .pinPeer(peer):
                ownerPin = peer
            case .failed:
                ownerFailed = true
            }
        }
        return response
    }

    private static func pinsBeforeConfirm(_ events: [PairingEvent]) -> Bool {
        guard events.count == 2 else { return false }
        guard case .pinPeer = events[0] else { return false }
        guard case .send(.pairSasConfirm(accepted: true)) = events[1] else { return false }
        return true
    }
}
