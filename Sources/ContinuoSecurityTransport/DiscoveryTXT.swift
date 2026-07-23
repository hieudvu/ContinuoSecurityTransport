import CryptoKit
import Foundation

/// Builds and reads the privacy-sensitive TXT record advertised for discovery.
/// The record carries a truncated hash, the caller's wire version, and an
/// optional user-chosen label. It never carries the raw machine identifier.
public enum DiscoveryTXT {
    private static let hashPrefixLength = 8

    public static func make(
        machineID: String,
        name: String = "",
        protocolVersion: UInt16
    ) -> [String: String] {
        var txt = [
            "h": serviceInstanceName(machineID: machineID),
            "v": String(protocolVersion),
        ]
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            txt["n"] = trimmed
        }
        return txt
    }

    public static func machineIDHash(_ txt: [String: String]) -> String? {
        txt["h"]
    }

    /// Reads the canonical positive UInt16 wire version. Missing, non-decimal,
    /// zero, overflowed, and non-canonical values fail closed.
    public static func protocolVersion(_ txt: [String: String]) -> UInt16? {
        guard let raw = txt["v"],
              !raw.isEmpty,
              raw.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              raw.first != "0",
              let version = UInt16(raw),
              String(version) == raw else { return nil }
        return version
    }

    public static func broadcastName(_ txt: [String: String]) -> String? {
        guard let name = txt["n"] else { return nil }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Stable, non-identifying service instance name derived from the same hash
    /// carried in the TXT record. This avoids platform fallback to a local name.
    public static func serviceInstanceName(machineID: String) -> String {
        let digest = SHA256.hash(data: Data(machineID.utf8))
        return digest.prefix(hashPrefixLength)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
