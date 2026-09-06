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
        protocolVersion: UInt16,
        infraHost: String = "",
        infraPort: UInt16 = 0
    ) -> [String: String] {
        var txt = [
            "h": serviceInstanceName(machineID: machineID),
            "v": String(protocolVersion),
        ]
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            txt["n"] = trimmed
        }
        // `a`/`p`: this Mac's own routable IPv4 and its listener port, so a peer
        // that found us can dial us WITHOUT resolving our `.local` name.
        //
        // mDNS is multicast and link-local — it cannot cross a router, by design.
        // Two Macs on different subnets of one home network (a second router, a
        // guest SSID) therefore never resolve each other's Bonjour name even though
        // plain unicast between them works perfectly: field capture 2026-08-21 had
        // 192.168.102.29 and 192.168.1.5 one hop apart, ping 2/2, while every infra
        // lookup came back empty. The peers were visible only because discovery
        // permits peer-to-peer and the browse arrived over AWDL — carrying this
        // very TXT record. An address travels in that record where a name cannot be
        // resolved, which is the whole point.
        //
        // Not privacy-sensitive in the way `h` is: a private LAN address is already
        // visible to anything on the link, identifies no person, and is broadcast
        // by every Bonjour service on the machine. It is also only ever a HINT — it
        // buys a dial attempt, never trust. Pinned mTLS is what decides whether the
        // Mac that answers is the one we meant, so a spoofed `a` costs an attacker
        // a refused handshake and nothing else.
        let host = infraHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if !host.isEmpty, infraPort != 0 {
            txt["a"] = host
            txt["p"] = String(infraPort)
        }
        return txt
    }

    /// The peer's advertised routable IPv4, or nil when it advertised none (an
    /// older build, or a Mac with no infrastructure interface up).
    ///
    /// DELIBERATELY NOT VALIDATED HERE. This module is the public-mirror boundary
    /// and knows nothing about what a caller will do with the value; the dial site
    /// owns the "could this be a peer on a LAN" question, because it is the site
    /// that would suffer a bad answer by turning a hostile string into a DNS lookup.
    /// See `InfraAddress.isValidAdvertisedHost`, which every caller must pass this
    /// through before building an endpoint from it.
    public static func infraHost(_ txt: [String: String]) -> String? {
        guard let host = txt["a"] else { return nil }
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// The peer's advertised listener port. Same canonical-decimal discipline as
    /// `protocolVersion`: missing, non-decimal, zero, overflowed and
    /// leading-zero-padded values all fail closed rather than dialing port 0 or a
    /// silently truncated number.
    public static func infraPort(_ txt: [String: String]) -> UInt16? {
        guard let raw = txt["p"],
              !raw.isEmpty,
              raw.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              raw.first != "0",
              let port = UInt16(raw),
              String(port) == raw else { return nil }
        return port
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
