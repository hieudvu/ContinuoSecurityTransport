import Foundation

public enum SecurityFrameError: Error, Equatable, Sendable {
    case frameTooLarge
}

public enum SecurityFrameCodec {
    public static func frame(_ payload: [UInt8]) -> [UInt8] {
        let count = UInt32(payload.count)
        return [
            UInt8(count >> 24 & 0xFF),
            UInt8(count >> 16 & 0xFF),
            UInt8(count >> 8 & 0xFF),
            UInt8(count & 0xFF),
        ] + payload
    }

    public static func frameData(_ payload: [UInt8]) -> Data {
        var data = Data(capacity: 4 + payload.count)
        let count = UInt32(payload.count)
        data.append(UInt8(count >> 24 & 0xFF))
        data.append(UInt8(count >> 16 & 0xFF))
        data.append(UInt8(count >> 8 & 0xFF))
        data.append(UInt8(count & 0xFF))
        data.append(contentsOf: payload)
        return data
    }

    public static func parseAt(
        _ buffer: [UInt8],
        offset: Int,
        maxFrame: Int
    ) throws -> (payload: [UInt8], next: Int)? {
        guard buffer.count - offset >= 4 else { return nil }
        let count = (Int(buffer[offset]) << 24)
            | (Int(buffer[offset + 1]) << 16)
            | (Int(buffer[offset + 2]) << 8)
            | Int(buffer[offset + 3])
        guard count <= maxFrame else { throw SecurityFrameError.frameTooLarge }
        let bodyStart = offset + 4
        guard buffer.count - bodyStart >= count else { return nil }
        return (Array(buffer[bodyStart ..< bodyStart + count]), bodyStart + count)
    }
}
