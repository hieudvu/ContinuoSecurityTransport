import Testing
@testable import ContinuoSecurityTransport

@Suite struct SecurityHandshakeMessageTests {
    private let key = Array(0 ..< 32).map(UInt8.init)
    private let nonce = Array(32 ..< 48).map(UInt8.init)
    private let fingerprint = Array(48 ..< 80).map(UInt8.init)

    @Test func everyMessageRoundTrips() throws {
        let messages: [SecurityHandshakeMessage] = [
            .negotiate(version: 1),
            .pairCommit(commitment: key),
            .pairReveal(
                ephPublicKey: key,
                nonce: nonce,
                tlsFingerprint: fingerprint,
                machineID: "mac-Ω-42",
                deviceName: "Hiếu's Mac"
            ),
            .pairSasConfirm(accepted: true),
            .pairSasConfirm(accepted: false),
            .sessionKeyOffer(ephPublicKey: key),
            .sessionKeyAccept(ephPublicKey: key),
            .complete,
            .failure(.authenticationFailed),
        ]

        for message in messages {
            #expect(try SecurityHandshakeMessage.decode(message.encode()) == message)
        }
    }

    @Test func magicAndTagsAreIndependentAndStable() throws {
        let messages: [(SecurityHandshakeMessage, UInt8)] = [
            (.negotiate(version: 1), 1),
            (.pairCommit(commitment: key), 2),
            (.pairReveal(ephPublicKey: key, nonce: nonce, tlsFingerprint: fingerprint, machineID: "A", deviceName: "Mac"), 3),
            (.pairSasConfirm(accepted: true), 4),
            (.sessionKeyOffer(ephPublicKey: key), 5),
            (.sessionKeyAccept(ephPublicKey: key), 6),
            (.complete, 7),
            (.failure(.rejectedByUser), 8),
        ]

        for (message, tag) in messages {
            let encoded = try message.encode()
            #expect(Array(encoded.prefix(4)) == [0x43, 0x53, 0x48, 0x53])
            #expect(encoded[4] == tag)
        }
    }

    @Test func encoderRejectsInvalidFixedLengthsAndStringBounds() {
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.pairCommit(commitment: Array(repeating: 0, count: 31)).encode()
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.sessionKeyOffer(ephPublicKey: Array(repeating: 0, count: 33)).encode()
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.pairReveal(
                ephPublicKey: key,
                nonce: Array(repeating: 0, count: 15),
                tlsFingerprint: fingerprint,
                machineID: "A",
                deviceName: "Mac"
            ).encode()
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.pairReveal(
                ephPublicKey: key,
                nonce: nonce,
                tlsFingerprint: Array(repeating: 0, count: 31),
                machineID: "A",
                deviceName: "Mac"
            ).encode()
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.pairReveal(
                ephPublicKey: key,
                nonce: nonce,
                tlsFingerprint: fingerprint,
                machineID: "",
                deviceName: "Mac"
            ).encode()
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.pairReveal(
                ephPublicKey: key,
                nonce: nonce,
                tlsFingerprint: fingerprint,
                machineID: String(repeating: "m", count: 129),
                deviceName: "Mac"
            ).encode()
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.pairReveal(
                ephPublicKey: key,
                nonce: nonce,
                tlsFingerprint: fingerprint,
                machineID: "A",
                deviceName: String(repeating: "n", count: 256)
            ).encode()
        }
    }

    @Test func decoderRejectsBadMagicUnknownTagStrictBooleanAndTrailingBytes() throws {
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode([0, 0, 0, 0, 7])
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(Self.raw(tag: 0xFF))
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(Self.raw(tag: 4, body: [2]))
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(try SecurityHandshakeMessage.complete.encode() + [0])
        }
    }

    @Test func decoderRejectsOversizeBeforeReadingPayload() {
        var body = SecurityBinaryWriter()
        body.writeUInt32(33)
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(Self.raw(tag: 2, body: body.bytes))
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(Array(repeating: 0, count: 513))
        }
    }

    @Test func decoderRejectsInvalidUtf8AndUnknownFailureCode() {
        var reveal = SecurityBinaryWriter()
        reveal.writeData(key)
        reveal.writeData(nonce)
        reveal.writeData(fingerprint)
        reveal.writeData([0xFF])
        reveal.writeData([])
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(Self.raw(tag: 3, body: reveal.bytes))
        }
        #expect(throws: SecurityWireError.self) {
            try SecurityHandshakeMessage.decode(Self.raw(tag: 8, body: [0xFF]))
        }
    }

    private static func raw(tag: UInt8, body: [UInt8] = []) -> [UInt8] {
        [0x43, 0x53, 0x48, 0x53, tag] + body
    }
}
