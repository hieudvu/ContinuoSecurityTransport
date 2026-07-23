import Foundation

public enum SecurityWireError: Error, Equatable, Sendable {
    case truncated(expected: Int, available: Int)
    case unknownTag(UInt8)
    case lengthOverflow(declared: Int, available: Int)
    case invalidValue(String)
}

public struct SecurityBinaryWriter: Sendable {
    public private(set) var bytes: [UInt8]

    public init(reserving capacity: Int = 64) {
        bytes = []
        bytes.reserveCapacity(capacity)
    }

    public mutating func writeUInt8(_ value: UInt8) { bytes.append(value) }

    public mutating func writeUInt16(_ value: UInt16) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeUInt32(_ value: UInt32) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 24))
        bytes.append(UInt8(truncatingIfNeeded: value >> 16))
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    public mutating func writeData(_ data: [UInt8]) {
        writeUInt32(UInt32(data.count))
        bytes.append(contentsOf: data)
    }
}

public struct SecurityBinaryReader: Sendable {
    private let bytes: [UInt8]
    public private(set) var cursor: Int

    public init(_ bytes: [UInt8]) {
        self.bytes = bytes
        self.cursor = 0
    }

    public var remaining: Int { bytes.count - cursor }

    private mutating func require(_ count: Int) throws {
        guard remaining >= count else {
            throw SecurityWireError.truncated(expected: count, available: remaining)
        }
    }

    public mutating func readUInt8() throws -> UInt8 {
        try require(1)
        defer { cursor += 1 }
        return bytes[cursor]
    }

    public mutating func readUInt16() throws -> UInt16 {
        try require(2)
        defer { cursor += 2 }
        return UInt16(bytes[cursor]) << 8 | UInt16(bytes[cursor + 1])
    }

    public mutating func readUInt32() throws -> UInt32 {
        try require(4)
        defer { cursor += 4 }
        var value: UInt32 = 0
        for index in 0 ..< 4 {
            value = value << 8 | UInt32(bytes[cursor + index])
        }
        return value
    }

    public mutating func readData(maxLength: Int) throws -> [UInt8] {
        let length = Int(try readUInt32())
        guard length <= maxLength else {
            throw SecurityWireError.invalidValue("data length exceeds limit")
        }
        guard remaining >= length else {
            throw SecurityWireError.lengthOverflow(declared: length, available: remaining)
        }
        defer { cursor += length }
        return Array(bytes[cursor ..< cursor + length])
    }
}
