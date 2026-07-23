/// Independent wire constants for the source-visible security handshake.
/// This protocol is deliberately separate from the closed product protocol.
public enum SecurityHandshakeProtocol {
    /// ASCII "CSHS".
    public static let magic: UInt32 = 0x4353_4853
    public static let version: UInt16 = 1
    public static let maxMessageBytes = 512

    public static let commitmentBytes = 32
    public static let publicKeyBytes = 32
    public static let fingerprintBytes = 32
    public static let nonceBytes = 16
    public static let maxMachineIDBytes = 128
    public static let maxDeviceNameBytes = 255
}

/// Redacted failure codes safe to expose on the security handshake.
public enum SecurityHandshakeFailure: UInt8, Sendable, Equatable {
    case unsupportedVersion = 1
    case malformedMessage = 2
    case authenticationFailed = 3
    case rejectedByUser = 4
    case internalError = 5
}

/// Messages exchanged before the closed product protocol is admitted.
public enum SecurityHandshakeMessage: Sendable, Equatable {
    case negotiate(version: UInt16)
    case pairCommit(commitment: [UInt8])
    case pairReveal(
        ephPublicKey: [UInt8],
        nonce: [UInt8],
        tlsFingerprint: [UInt8],
        machineID: String,
        deviceName: String
    )
    case pairSasConfirm(accepted: Bool)
    case sessionKeyOffer(ephPublicKey: [UInt8])
    case sessionKeyAccept(ephPublicKey: [UInt8])
    case complete
    case failure(SecurityHandshakeFailure)

    private enum Tag: UInt8 {
        case negotiate = 1
        case pairCommit = 2
        case pairReveal = 3
        case pairSasConfirm = 4
        case sessionKeyOffer = 5
        case sessionKeyAccept = 6
        case complete = 7
        case failure = 8
    }

    public func encode() throws -> [UInt8] {
        var writer = SecurityBinaryWriter(reserving: SecurityHandshakeProtocol.maxMessageBytes)
        writer.writeUInt32(SecurityHandshakeProtocol.magic)

        switch self {
        case let .negotiate(version):
            writer.writeUInt8(Tag.negotiate.rawValue)
            writer.writeUInt16(version)

        case let .pairCommit(commitment):
            try Self.requireExact(commitment, count: SecurityHandshakeProtocol.commitmentBytes, field: "commitment")
            writer.writeUInt8(Tag.pairCommit.rawValue)
            writer.writeData(commitment)

        case let .pairReveal(ephPublicKey, nonce, tlsFingerprint, machineID, deviceName):
            try Self.requireExact(ephPublicKey, count: SecurityHandshakeProtocol.publicKeyBytes, field: "ephemeral public key")
            try Self.requireExact(nonce, count: SecurityHandshakeProtocol.nonceBytes, field: "nonce")
            try Self.requireExact(tlsFingerprint, count: SecurityHandshakeProtocol.fingerprintBytes, field: "TLS fingerprint")
            let machineBytes = Array(machineID.utf8)
            let nameBytes = Array(deviceName.utf8)
            guard !machineBytes.isEmpty, machineBytes.count <= SecurityHandshakeProtocol.maxMachineIDBytes else {
                throw SecurityWireError.invalidValue("machineID length")
            }
            guard nameBytes.count <= SecurityHandshakeProtocol.maxDeviceNameBytes else {
                throw SecurityWireError.invalidValue("deviceName length")
            }
            writer.writeUInt8(Tag.pairReveal.rawValue)
            writer.writeData(ephPublicKey)
            writer.writeData(nonce)
            writer.writeData(tlsFingerprint)
            writer.writeData(machineBytes)
            writer.writeData(nameBytes)

        case let .pairSasConfirm(accepted):
            writer.writeUInt8(Tag.pairSasConfirm.rawValue)
            writer.writeUInt8(accepted ? 1 : 0)

        case let .sessionKeyOffer(ephPublicKey):
            try Self.requireExact(ephPublicKey, count: SecurityHandshakeProtocol.publicKeyBytes, field: "session offer public key")
            writer.writeUInt8(Tag.sessionKeyOffer.rawValue)
            writer.writeData(ephPublicKey)

        case let .sessionKeyAccept(ephPublicKey):
            try Self.requireExact(ephPublicKey, count: SecurityHandshakeProtocol.publicKeyBytes, field: "session accept public key")
            writer.writeUInt8(Tag.sessionKeyAccept.rawValue)
            writer.writeData(ephPublicKey)

        case .complete:
            writer.writeUInt8(Tag.complete.rawValue)

        case let .failure(failure):
            writer.writeUInt8(Tag.failure.rawValue)
            writer.writeUInt8(failure.rawValue)
        }

        guard writer.bytes.count <= SecurityHandshakeProtocol.maxMessageBytes else {
            throw SecurityWireError.invalidValue("security handshake message exceeds limit")
        }
        return writer.bytes
    }

    public static func decode(_ bytes: [UInt8]) throws -> SecurityHandshakeMessage {
        guard bytes.count <= SecurityHandshakeProtocol.maxMessageBytes else {
            throw SecurityWireError.invalidValue("security handshake message exceeds limit")
        }

        var reader = SecurityBinaryReader(bytes)
        let magic = try reader.readUInt32()
        guard magic == SecurityHandshakeProtocol.magic else {
            throw SecurityWireError.invalidValue("bad security handshake magic")
        }
        let rawTag = try reader.readUInt8()
        guard let tag = Tag(rawValue: rawTag) else { throw SecurityWireError.unknownTag(rawTag) }

        let message: SecurityHandshakeMessage
        switch tag {
        case .negotiate:
            message = .negotiate(version: try reader.readUInt16())

        case .pairCommit:
            message = .pairCommit(commitment: try readExact(
                &reader,
                count: SecurityHandshakeProtocol.commitmentBytes,
                field: "commitment"
            ))

        case .pairReveal:
            let ephPublicKey = try readExact(
                &reader,
                count: SecurityHandshakeProtocol.publicKeyBytes,
                field: "ephemeral public key"
            )
            let nonce = try readExact(
                &reader,
                count: SecurityHandshakeProtocol.nonceBytes,
                field: "nonce"
            )
            let fingerprint = try readExact(
                &reader,
                count: SecurityHandshakeProtocol.fingerprintBytes,
                field: "TLS fingerprint"
            )
            let machineID = try readString(
                &reader,
                maxBytes: SecurityHandshakeProtocol.maxMachineIDBytes,
                allowEmpty: false,
                field: "machineID"
            )
            let deviceName = try readString(
                &reader,
                maxBytes: SecurityHandshakeProtocol.maxDeviceNameBytes,
                allowEmpty: true,
                field: "deviceName"
            )
            message = .pairReveal(
                ephPublicKey: ephPublicKey,
                nonce: nonce,
                tlsFingerprint: fingerprint,
                machineID: machineID,
                deviceName: deviceName
            )

        case .pairSasConfirm:
            let value = try reader.readUInt8()
            guard value == 0 || value == 1 else {
                throw SecurityWireError.invalidValue("invalid SAS confirmation boolean")
            }
            message = .pairSasConfirm(accepted: value == 1)

        case .sessionKeyOffer:
            message = .sessionKeyOffer(ephPublicKey: try readExact(
                &reader,
                count: SecurityHandshakeProtocol.publicKeyBytes,
                field: "session offer public key"
            ))

        case .sessionKeyAccept:
            message = .sessionKeyAccept(ephPublicKey: try readExact(
                &reader,
                count: SecurityHandshakeProtocol.publicKeyBytes,
                field: "session accept public key"
            ))

        case .complete:
            message = .complete

        case .failure:
            let rawFailure = try reader.readUInt8()
            guard let failure = SecurityHandshakeFailure(rawValue: rawFailure) else {
                throw SecurityWireError.invalidValue("unknown security handshake failure")
            }
            message = .failure(failure)
        }

        guard reader.remaining == 0 else {
            throw SecurityWireError.invalidValue("trailing security handshake bytes")
        }
        return message
    }

    private static func requireExact(_ bytes: [UInt8], count: Int, field: String) throws {
        guard bytes.count == count else { throw SecurityWireError.invalidValue("invalid \(field) length") }
    }

    private static func readExact(
        _ reader: inout SecurityBinaryReader,
        count: Int,
        field: String
    ) throws -> [UInt8] {
        let bytes = try reader.readData(maxLength: count)
        guard bytes.count == count else { throw SecurityWireError.invalidValue("invalid \(field) length") }
        return bytes
    }

    private static func readString(
        _ reader: inout SecurityBinaryReader,
        maxBytes: Int,
        allowEmpty: Bool,
        field: String
    ) throws -> String {
        let bytes = try reader.readData(maxLength: maxBytes)
        guard allowEmpty || !bytes.isEmpty else { throw SecurityWireError.invalidValue("empty \(field)") }
        guard let value = String(bytes: bytes, encoding: .utf8) else {
            throw SecurityWireError.invalidValue("invalid \(field) UTF-8")
        }
        return value
    }
}
