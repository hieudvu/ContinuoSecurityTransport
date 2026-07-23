import Testing
import CryptoKit
@testable import ContinuoSecurityTransport

@Suite struct PairingSASTests {
    private func reveal(_ kp: PairingKeyPair, nonce: [UInt8], fp: [UInt8], id: String, role: DeviceRole, name: String = "Dev Mac") -> PairingReveal {
        PairingReveal(ephPublicKey: kp.publicKeyRawRepresentation, nonce: nonce, tlsFingerprint: fp, machineID: id, deviceName: name, role: role)
    }

    @Test func commitmentVerifies() {
        let kp = PairingKeyPair()
        let r = reveal(kp, nonce: PairingSAS.randomNonce(), fp: Array(0..<32), id: "A", role: .host)
        #expect(PairingSAS.verifyCommitment(PairingSAS.commitment(for: r), against: r))
    }

    @Test func tamperedRevealFailsCommitment() {
        let kp = PairingKeyPair()
        let r = reveal(kp, nonce: PairingSAS.randomNonce(), fp: Array(0..<32), id: "A", role: .host)
        let c = PairingSAS.commitment(for: r)
        var bad = r; bad.tlsFingerprint[0] ^= 0xFF
        #expect(!PairingSAS.verifyCommitment(c, against: bad))   // fingerprint late-binding blocked
    }

    @Test func bothSidesDeriveSameSAS() throws {
        let a = PairingKeyPair(); let b = PairingKeyPair()
        let ra = reveal(a, nonce: [1,2,3,4], fp: Array(0..<32), id: "A", role: .host)
        let rb = reveal(b, nonce: [5,6,7,8], fp: Array(32..<64), id: "B", role: .client)
        let sasA = try PairingSAS.sasValue(localKeyPair: a, peerEphPublicKey: b.publicKeyRawRepresentation, initiatorReveal: ra, responderReveal: rb, protocolVersion: SecurityHandshakeProtocol.version)
        let sasB = try PairingSAS.sasValue(localKeyPair: b, peerEphPublicKey: a.publicKeyRawRepresentation, initiatorReveal: ra, responderReveal: rb, protocolVersion: SecurityHandshakeProtocol.version)
        #expect(sasA == sasB)
        #expect(PairingSAS.words(from: sasA).count == 3)
        #expect(PairingSAS.digits(from: sasA).count == 8)
    }

    @Test func digitsRenderTheSameValueLosslessly() {
        // Both renderings must carry the WHOLE SAS; a shorter one would silently
        // merge distinct channels into one displayed code.
        for v in [UInt32(0), 1, 123_456, PairingSAS.sasSpace - 1] {
            #expect(UInt32(PairingSAS.digits(from: v)) == v)
        }
    }

    // ---- SAS strength: the displayed words ARE the whole MITM defense ----

    @Test func wordlistIsExactly256UniqueWords() {
        #expect(PairingSAS.wordlist.count == PairingSAS.wordBase)
        #expect(PairingSAS.wordBase == 256)
        #expect(Set(PairingSAS.wordlist).count == PairingSAS.wordlist.count, "duplicate word collapses two SAS values")
    }

    @Test func sasSpaceIsAPowerOfTwoWithNoModuloBias() {
        // raw % sasSpace is uniform only when sasSpace divides 2^32 — i.e. is a power of two.
        #expect(PairingSAS.sasSpace == 1 << 24)
        #expect(PairingSAS.sasSpace.nonzeroBitCount == 1)
    }

    @Test func threeWordsRenderTheFullSasSpaceWithoutTruncation() {
        // Every distinct SAS must render to distinct words; if the words carried fewer
        // bits than the SAS, two different channels would display the same phrase.
        #expect(PairingSAS.wordBase * PairingSAS.wordBase * PairingSAS.wordBase == Int(PairingSAS.sasSpace))
        for v in [UInt32(0), 1, 255, 256, 65_535, 65_536, PairingSAS.sasSpace - 1] {
            #expect(PairingSAS.value(fromWords: PairingSAS.words(from: v)) == v)
        }
        var seen = Set<[String]>()
        for _ in 0..<2_000 {
            let v = UInt32.random(in: 0..<PairingSAS.sasSpace)
            #expect(PairingSAS.value(fromWords: PairingSAS.words(from: v)) == v)
            seen.insert(PairingSAS.words(from: v))
        }
        #expect(seen.count > 1_900, "words must not collide across the SAS space")
    }

    @Test func derivedSASAlwaysFitsTheDisplayedSpace() throws {
        for i in 0..<200 {
            let a = PairingKeyPair(); let b = PairingKeyPair()
            let ra = reveal(a, nonce: PairingSAS.randomNonce(), fp: Array(0..<32), id: "A\(i)", role: .host)
            let rb = reveal(b, nonce: PairingSAS.randomNonce(), fp: Array(32..<64), id: "B\(i)", role: .client)
            let sas = try PairingSAS.sasValue(localKeyPair: a, peerEphPublicKey: b.publicKeyRawRepresentation,
                                              initiatorReveal: ra, responderReveal: rb, protocolVersion: SecurityHandshakeProtocol.version)
            #expect(sas < PairingSAS.sasSpace)
        }
    }

    @Test func wordsAreShortLowercaseAndFarApart() {
        for w in PairingSAS.wordlist {
            #expect(w.count >= 4 && w.count <= 8, "\(w) is a bad length for a glance-compare")
            #expect(w.allSatisfy { $0.isLowercase && $0.isASCII && $0.isLetter }, "\(w) is not plain lowercase ascii")
        }
        // A one-edit gap (falcon/falcen) is what a hurried human misreads. Require ≥ 2.
        let list = PairingSAS.wordlist
        for i in list.indices {
            for j in (i + 1)..<list.count where editDistance(list[i], list[j]) < 2 {
                Issue.record("\"\(list[i])\" and \"\(list[j])\" are one edit apart")
            }
        }
    }

    private func editDistance(_ a: String, _ b: String) -> Int {
        let x = Array(a), y = Array(b)
        if abs(x.count - y.count) > 1 { return 2 }   // only "< 2" matters here
        var prev = Array(0...y.count)
        for i in 1...x.count {
            var cur = [i] + Array(repeating: 0, count: y.count)
            for j in 1...y.count {
                cur[j] = x[i - 1] == y[j - 1] ? prev[j - 1]
                                              : min(prev[j - 1], prev[j], cur[j - 1]) + 1
            }
            prev = cur
        }
        return prev[y.count]
    }

    @Test func differentEcdhSecretChangesSAS() throws {
        // Same transcript, different actual key pair => different secret => different SAS.
        // Proves the SAS is keyed by the ECDH secret, not the (public) transcript alone.
        let a = PairingKeyPair(); let b = PairingKeyPair(); let mallory = PairingKeyPair()
        let ra = reveal(a, nonce: [1,2,3,4], fp: Array(0..<32), id: "A", role: .host)
        let rb = reveal(b, nonce: [5,6,7,8], fp: Array(32..<64), id: "B", role: .client)
        let honest = try PairingSAS.sasValue(localKeyPair: a, peerEphPublicKey: b.publicKeyRawRepresentation, initiatorReveal: ra, responderReveal: rb, protocolVersion: SecurityHandshakeProtocol.version)
        let attacker = try PairingSAS.sasValue(localKeyPair: a, peerEphPublicKey: mallory.publicKeyRawRepresentation, initiatorReveal: ra, responderReveal: rb, protocolVersion: SecurityHandshakeProtocol.version)
        #expect(honest != attacker)
    }

    @Test func sameValueRendersConsistently() {
        let v: UInt32 = 123456
        #expect(PairingSAS.digits(from: v) == "00123456")
        #expect(PairingSAS.words(from: v) == PairingSAS.words(from: v))
    }

    // The device name shown at SAS confirm is only safe because it is BOUND: a
    // MITM cannot swap it without breaking BOTH the commitment and the SAS.
    @Test func deviceNameIsBoundByCommitmentAndSAS() throws {
        let kp = PairingKeyPair()
        let nonce = PairingSAS.randomNonce()
        let fp = Array<UInt8>(0..<32)
        let honest = reveal(kp, nonce: nonce, fp: fp, id: "A", role: .host, name: "Hieu MacBook")
        let commitment = PairingSAS.commitment(for: honest)
        let tampered = reveal(kp, nonce: nonce, fp: fp, id: "A", role: .host, name: "Attacker Mac")

        #expect(PairingSAS.verifyCommitment(commitment, against: honest) == true)
        #expect(PairingSAS.verifyCommitment(commitment, against: tampered) == false,
                "device name must be committed — a tampered name must not open the commitment")

        let peerKP = PairingKeyPair()
        let responder = reveal(peerKP, nonce: PairingSAS.randomNonce(), fp: Array(32..<64), id: "B", role: .client, name: "Mac B")
        let sasHonest = try PairingSAS.sasValue(localKeyPair: kp, peerEphPublicKey: peerKP.publicKeyRawRepresentation,
                                                initiatorReveal: honest, responderReveal: responder, protocolVersion: 1)
        let sasTampered = try PairingSAS.sasValue(localKeyPair: kp, peerEphPublicKey: peerKP.publicKeyRawRepresentation,
                                                  initiatorReveal: tampered, responderReveal: responder, protocolVersion: 1)
        #expect(sasHonest != sasTampered,
                "device name must be in the SAS transcript — changing it must change the SAS")
    }
}
