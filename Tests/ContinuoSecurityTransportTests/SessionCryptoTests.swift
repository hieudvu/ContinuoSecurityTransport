import Testing
@testable import ContinuoSecurityTransport

@Suite struct SessionCryptoTests {
    @Test func bothDirectionsAgreeAndRoundTrip() throws {
        let offer = SessionKeyAgreement.makeOffer()
        let accepted = try SessionKeyAgreement.accept(offerPublicKey: offer.ephemeralPublicKey)
        let initiator = try SessionKeyAgreement.complete(
            offer: offer,
            responsePublicKey: accepted.responsePublicKey
        )

        let first = Array("first direction".utf8)
        let firstBox = try initiator.sealer.seal(first)
        let openedFirst = try accepted.context.opener.open(firstBox)
        #expect(openedFirst.epoch == 0)
        #expect(openedFirst.sequence == 0)
        #expect(openedFirst.plaintext == first)

        let reply = Array("return direction".utf8)
        let replyBox = try accepted.context.sealer.seal(reply)
        #expect(try initiator.opener.open(replyBox).plaintext == reply)
    }

    @Test func malformedKeyAndCiphertextFailClosed() {
        #expect(throws: SessionCryptoError.invalidPublicKey) {
            _ = try SessionKeyAgreement.accept(offerPublicKey: [1, 2, 3])
        }
        #expect(throws: SessionCryptoError.invalidPublicKey) {
            _ = try SessionKeyAgreement.accept(offerPublicKey: [UInt8](repeating: 0, count: 32))
        }

        let offer = SessionKeyAgreement.makeOffer()
        #expect(throws: SessionCryptoError.malformedCiphertext) {
            _ = try SessionKeyAgreement.complete(
                offer: offer,
                responsePublicKey: SessionKeyAgreement.accept(
                    offerPublicKey: offer.ephemeralPublicKey
                ).responsePublicKey
            ).opener.open([0])
        }
    }

    @Test func tamperingFailsAuthentication() throws {
        let offer = SessionKeyAgreement.makeOffer()
        let accepted = try SessionKeyAgreement.accept(offerPublicKey: offer.ephemeralPublicKey)
        let initiator = try SessionKeyAgreement.complete(
            offer: offer,
            responsePublicKey: accepted.responsePublicKey
        )
        var box = try initiator.sealer.seal([1, 2, 3])
        box[12] ^= 0x80

        #expect(throws: SessionCryptoError.authenticationFailed) {
            _ = try accepted.context.opener.open(box)
        }
    }

    @Test func concurrentSealsAllocateUniqueNonces() async throws {
        let offer = SessionKeyAgreement.makeOffer()
        let accepted = try SessionKeyAgreement.accept(offerPublicKey: offer.ephemeralPublicKey)
        let initiator = try SessionKeyAgreement.complete(
            offer: offer,
            responsePublicKey: accepted.responsePublicKey
        )

        let boxes = try await withThrowingTaskGroup(of: [UInt8].self) { group in
            for value in UInt8(0) ..< 64 {
                group.addTask { try initiator.sealer.seal([value]) }
            }
            var result: [[UInt8]] = []
            for try await box in group { result.append(box) }
            return result
        }

        var nonces = Set<String>()
        for box in boxes {
            let opened = try accepted.context.opener.open(box)
            nonces.insert("\(opened.epoch):\(opened.sequence)")
        }
        #expect(nonces.count == boxes.count)
    }

    @Test func nonceCounterFailsClosedAfterExhaustion() throws {
        var counter = SessionNonceSequence(epoch: .max, sequence: .max)
        let final = try counter.take()
        #expect(final.epoch == .max)
        #expect(final.sequence == .max)
        #expect(throws: SessionCryptoError.nonceExhausted) {
            _ = try counter.take()
        }
    }
}
