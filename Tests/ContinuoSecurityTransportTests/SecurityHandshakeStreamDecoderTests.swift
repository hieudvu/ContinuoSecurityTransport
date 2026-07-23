import Testing
@testable import ContinuoSecurityTransport

@Suite struct SecurityHandshakeStreamDecoderTests {
    @Test func fragmentedFrameEmitsOnlyAfterCompletion() throws {
        let message = SecurityHandshakeMessage.negotiate(version: SecurityHandshakeProtocol.version)
        let frame = SecurityFrameCodec.frame(try message.encode())
        var decoder = SecurityHandshakeStreamDecoder()

        #expect(try decoder.ingest(Array(frame.prefix(3))).isEmpty)
        #expect(try decoder.ingest(Array(frame.dropFirst(3).prefix(2))).isEmpty)
        #expect(try decoder.ingest(Array(frame.dropFirst(5))) == [message])
    }

    @Test func multipleFramesInOneChunkPreserveOrder() throws {
        let messages: [SecurityHandshakeMessage] = [
            .negotiate(version: SecurityHandshakeProtocol.version),
            .pairSasConfirm(accepted: true),
            .complete,
        ]
        let bytes = try messages.flatMap { SecurityFrameCodec.frame(try $0.encode()) }
        var decoder = SecurityHandshakeStreamDecoder()

        #expect(try decoder.ingest(bytes) == messages)
    }

    @Test func oversizeClaimFailsBeforeBufferingPayload() {
        var decoder = SecurityHandshakeStreamDecoder()
        let claimedLength = SecurityHandshakeProtocol.maxMessageBytes + 1
        let prefix: [UInt8] = [
            UInt8(claimedLength >> 24 & 0xFF),
            UInt8(claimedLength >> 16 & 0xFF),
            UInt8(claimedLength >> 8 & 0xFF),
            UInt8(claimedLength & 0xFF),
        ]

        #expect(throws: SecurityFrameError.frameTooLarge) {
            _ = try decoder.ingest(prefix)
        }
    }

    @Test func malformedFramedPayloadFailsClosed() {
        var decoder = SecurityHandshakeStreamDecoder()
        let malformed = SecurityFrameCodec.frame([0x00])

        #expect(throws: SecurityWireError.self) {
            _ = try decoder.ingest(malformed)
        }
    }
}
