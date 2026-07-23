import Foundation

/// Renders a TLS fingerprint's leading bytes as SAS-style words for an
/// out-of-band "these match on both Macs" check, reusing `PairingSAS`'s
/// 256-word list.
///
/// Encoding: the first 5 bytes (40 bits) map one byte to one word, since the
/// wordlist is exactly 256 entries — 5 words total. Exactly round-trippable.
public enum FingerprintWords {
    public static func render(_ fingerprint: [UInt8]) -> [String] {
        prefix5(fingerprint).map { PairingSAS.word(at: Int($0)) }
    }

    public static func decode(_ words: [String]) -> [UInt8]? {
        guard words.count == 5 else { return nil }
        var out: [UInt8] = []
        for w in words {
            guard let idx = PairingSAS.index(ofWord: w) else { return nil }
            out.append(UInt8(idx))
        }
        return out
    }

    private static func prefix5(_ fp: [UInt8]) -> [UInt8] {
        var b = Array(fp.prefix(5))
        while b.count < 5 { b.append(0) }
        return b
    }
}
