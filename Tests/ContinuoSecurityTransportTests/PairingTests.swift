import Testing
@testable import ContinuoSecurityTransport

struct PairingTests {
    // Deterministic RNG so PIN generation is reproducible in tests.
    struct CountingRNG: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            return state
        }
    }

    @Test func pinValidation() throws {
        #expect(throws: PairingError.invalidPIN) { _ = try PairingPIN(digits: "12345") }
        #expect(throws: PairingError.invalidPIN) { _ = try PairingPIN(digits: "1234567") }
        #expect(throws: PairingError.invalidPIN) { _ = try PairingPIN(digits: "12a456") }
        let pin = try PairingPIN(digits: "007042")
        #expect(pin.digits == "007042")
    }

    @Test func randomPinIsSixDigits() {
        var rng = CountingRNG(state: 42)
        for _ in 0..<100 {
            let pin = PairingPIN.random(using: &rng)
            let allDigits = pin.digits.allSatisfy(\.isNumber)
            #expect(pin.digits.count == 6)
            #expect(allDigits)
        }
    }

    @Test func matchingPinAndKeysConfirm() throws {
        let host = PairingKeyPair()
        let target = PairingKeyPair()
        let pin = try PairingPIN(digits: "314159")

        let hostShared = try host.sharedSecret(with: target.publicKeyRawRepresentation)
        let targetShared = try target.sharedSecret(with: host.publicKeyRawRepresentation)

        let hostTag = Pairing.confirmationTag(
            sharedSecret: hostShared, pin: pin,
            hostPublicKey: host.publicKeyRawRepresentation,
            targetPublicKey: target.publicKeyRawRepresentation
        )
        let targetTag = Pairing.confirmationTag(
            sharedSecret: targetShared, pin: pin,
            hostPublicKey: host.publicKeyRawRepresentation,
            targetPublicKey: target.publicKeyRawRepresentation
        )

        #expect(hostTag == targetTag)
        #expect(Pairing.verify(receivedTag: hostTag, expectedTag: targetTag))
    }

    @Test func wrongPinFailsConfirmation() throws {
        let host = PairingKeyPair()
        let target = PairingKeyPair()

        let hostShared = try host.sharedSecret(with: target.publicKeyRawRepresentation)
        let targetShared = try target.sharedSecret(with: host.publicKeyRawRepresentation)

        let hostTag = Pairing.confirmationTag(
            sharedSecret: hostShared, pin: try PairingPIN(digits: "111111"),
            hostPublicKey: host.publicKeyRawRepresentation,
            targetPublicKey: target.publicKeyRawRepresentation
        )
        let targetTag = Pairing.confirmationTag(
            sharedSecret: targetShared, pin: try PairingPIN(digits: "222222"),
            hostPublicKey: host.publicKeyRawRepresentation,
            targetPublicKey: target.publicKeyRawRepresentation
        )

        #expect(hostTag != targetTag)
        #expect(!Pairing.verify(receivedTag: hostTag, expectedTag: targetTag))
    }

    @Test func mitmDifferentKeysFailsConfirmation() throws {
        // Attacker sits in the middle: host agrees with attacker, target agrees
        // with attacker, but each computes the transcript with the *real* peer's
        // advertised key. Tags diverge → detected.
        let host = PairingKeyPair()
        let target = PairingKeyPair()
        let attacker = PairingKeyPair()
        let pin = try PairingPIN(digits: "654321")

        let hostShared = try host.sharedSecret(with: attacker.publicKeyRawRepresentation)
        let targetShared = try target.sharedSecret(with: attacker.publicKeyRawRepresentation)

        let hostTag = Pairing.confirmationTag(
            sharedSecret: hostShared, pin: pin,
            hostPublicKey: host.publicKeyRawRepresentation,
            targetPublicKey: target.publicKeyRawRepresentation
        )
        let targetTag = Pairing.confirmationTag(
            sharedSecret: targetShared, pin: pin,
            hostPublicKey: host.publicKeyRawRepresentation,
            targetPublicKey: target.publicKeyRawRepresentation
        )

        #expect(!Pairing.verify(receivedTag: hostTag, expectedTag: targetTag))
    }

    @Test func invalidPublicKeyThrows() {
        let host = PairingKeyPair()
        #expect(throws: PairingError.invalidPublicKey) {
            _ = try host.sharedSecret(with: [1, 2, 3])   // not 32 bytes
        }
    }

    @Test func keyPairRoundTripsThroughRawRepresentation() throws {
        let original = PairingKeyPair()
        let restored = try PairingKeyPair(rawPrivateKey: original.privateKeyRawRepresentation)
        #expect(restored.publicKeyRawRepresentation == original.publicKeyRawRepresentation)
    }
}
