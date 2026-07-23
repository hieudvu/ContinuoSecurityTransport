import CryptoKit
import Foundation

/// Errors from the commit-reveal SAS pairing (see spec §Security & Pairing).
public enum PairingSASError: Error, Equatable, Sendable {
    case commitmentMismatch
    case fingerprintMismatch
    case invalidPublicKey
    case keyAgreementFailed
    case unsupportedProtocolVersion
    case unexpectedMessage
    case peerRejected
}

/// One side's revealed pairing material (sent after both commitments exchanged).
public struct PairingReveal: Sendable, Equatable {
    public var ephPublicKey: [UInt8]
    public var nonce: [UInt8]
    public var tlsFingerprint: [UInt8]
    public var machineID: String
    /// Human-readable device name. Bound by the commitment AND the SAS transcript
    /// (below), so the name displayed at SAS-confirm cannot be forged by a MITM
    /// without breaking the SAS — that is what makes it safe to show the REAL
    /// computer name here (vs the LAN-broadcast discovery, which stays anonymous).
    public var deviceName: String
    public var role: DeviceRole
    public init(ephPublicKey: [UInt8], nonce: [UInt8], tlsFingerprint: [UInt8], machineID: String, deviceName: String, role: DeviceRole) {
        self.ephPublicKey = ephPublicKey; self.nonce = nonce; self.tlsFingerprint = tlsFingerprint
        self.machineID = machineID; self.deviceName = deviceName; self.role = role
    }
}

/// Commit-then-reveal Short Authentication String. A MITM must bind its ephemeral
/// before seeing the peer's, so forcing a matching SAS is 2^-24 per attempt.
public enum PairingSAS {
    private static let sasInfo = Data("continuo-pairing-sas-v1".utf8)
    /// Exactly 24 bits. A power of two so `raw % sasSpace` is uniform — a non-power
    /// (the old 1_000_000) biases the SAS and shaves entropy off the attacker's guess.
    static let sasSpace: UInt32 = 1 << 24
    static let wordBase = 256                 // 8 bits per word
    static let wordCount = 3                  // 3 x 8 = 24 bits, the whole space

    /// 256 glance-distinct words; 3 of them render one SAS value (base-256).
    /// Invariants enforced by `PairingSASTests`: unique, 4-8 lowercase ascii letters,
    /// every pair >= 2 edits apart with distinct 3-letter prefixes. Adding a word that
    /// is one typo away from another weakens the only check a human actually performs.
    /// Order is load-bearing — it IS the encoding; never re-sort or splice this list.
    static let wordlist: [String] = [
        "acorn","almond","amulet","anchor","antler","apron","arcade","armor",
        "arrow","aspen","atlas","aurora","autumn","bagel","ballad","bamboo",
        "banjo","basil","beacon","bishop","blossom","bobcat","bonsai","boulder",
        "bramble","bridge","cabin","cactus","camel","candle","carbon","castle",
        "cedar","cellar","cement","chalk","cinder","cobalt","dagger","dahlia",
        "daisy","delta","denim","desert","diamond","diesel","dolphin","domino",
        "donkey","dune","eagle","echo","elbow","elder","ember","emerald",
        "empire","enamel","engine","equator","ermine","fabric","falcon","fennel",
        "ferry","fiber","fiddle","flannel","flint","flute","forest","fossil",
        "frost","gadget","galaxy","garden","gecko","gerbil","geyser","ginger",
        "glacier","glider","globe","granite","hammer","harbor","hazel","heather",
        "helmet","heron","hickory","hollow","honey","hornet","hostel","iceberg",
        "igloo","indigo","ingot","insect","island","ivory","jacket","jaguar",
        "jasmine","jelly","jersey","jigsaw","jockey","journal","jubilee","jungle",
        "kayak","kernel","kettle","keyhole","kimono","kingdom","kiosk","kitten",
        "knapsack","koala","krypton","lagoon","lantern","lariat","lattice","laurel",
        "lavender","ledger","legend","lemon","lentil","leopard","magnet","mammoth",
        "mandolin","maple","marble","mascot","meadow","medal","melon","mentor",
        "mercury","nebula","nectar","needle","nickel","nomad","noodle","notch",
        "nougat","nozzle","nugget","nutmeg","oasis","oatmeal","obelisk","ocean",
        "octave","olive","onyx","opal","orbit","orchard","oregano","paddle",
        "pagoda","palace","pancake","papaya","parcel","pasta","pebble","pelican",
        "pendant","pigeon","quartz","quiver","rabbit","raccoon","radar","rafter",
        "rainbow","rampart","ranch","rapid","raven","reactor","relay","saffron",
        "sage","salmon","sandal","sapphire","sardine","satchel","saucer","scarlet",
        "scooter","seagull","tabby","tackle","talon","tandem","tapioca","tavern",
        "teapot","tempo","tendril","termite","timber","ukulele","umbra","unicorn",
        "upland","uranium","urchin","utensil","valley","vanilla","vault","velvet",
        "vendor","veranda","vessel","viola","viper","vista","volcano","waffle",
        "wagon","walnut","wasabi","weasel","whistle","wicker","widget","willow",
        "windmill","wisteria","xenon","yacht","yeast","yellow","yogurt","yonder",
        "yucca","zebra","zenith","zephyr","zinc","zipper","zircon","zodiac",
    ]

    public static func randomNonce() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 16)
        for i in bytes.indices { bytes[i] = UInt8.random(in: .min ... .max) }
        return bytes
    }

    public static func commitment(for reveal: PairingReveal) -> [UInt8] {
        var h = SHA256()
        h.update(data: Data(reveal.ephPublicKey))
        h.update(data: Data(reveal.nonce))
        h.update(data: Data(reveal.tlsFingerprint))
        h.update(data: Data(reveal.machineID.utf8))
        h.update(data: Data(reveal.deviceName.utf8))
        h.update(data: Data([reveal.role.rawValue]))
        return Array(h.finalize())
    }

    public static func verifyCommitment(_ commitment: [UInt8], against reveal: PairingReveal) -> Bool {
        let expected = self.commitment(for: reveal)
        return SymmetricKey(data: commitment) == SymmetricKey(data: expected)  // constant-time
    }

    public static func sasValue(
        localKeyPair: PairingKeyPair,
        peerEphPublicKey: [UInt8],
        initiatorReveal: PairingReveal,
        responderReveal: PairingReveal,
        protocolVersion: UInt16
    ) throws -> UInt32 {
        let secret: SharedSecret
        do { secret = try localKeyPair.sharedSecret(with: peerEphPublicKey) }
        catch let e as PairingError where e == .invalidPublicKey { throw PairingSASError.invalidPublicKey }
        catch { throw PairingSASError.keyAgreementFailed }

        // Fixed order A = initiator, B = responder.
        var t = SecurityBinaryWriter()
        t.writeData(initiatorReveal.ephPublicKey)
        t.writeData(responderReveal.ephPublicKey)
        t.writeData(initiatorReveal.nonce)
        t.writeData(responderReveal.nonce)
        t.writeData(initiatorReveal.tlsFingerprint)
        t.writeData(responderReveal.tlsFingerprint)
        t.writeData(Array(initiatorReveal.machineID.utf8))
        t.writeData(Array(responderReveal.machineID.utf8))
        t.writeData(Array(initiatorReveal.deviceName.utf8))
        t.writeData(Array(responderReveal.deviceName.utf8))
        t.writeUInt16(protocolVersion)

        let key = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(t.bytes), sharedInfo: sasInfo, outputByteCount: 4
        )
        let raw = key.withUnsafeBytes { buf -> UInt32 in
            var v: UInt32 = 0
            for b in buf { v = (v << 8) | UInt32(b) }
            return v
        }
        return raw % sasSpace
    }

    /// Digit rendering of the *same* value — 8 digits, because `sasSpace` needs them all.
    public static func digits(from value: UInt32) -> String { String(format: "%08u", value % sasSpace) }

    public static func words(from value: UInt32) -> [String] {
        var v = value % sasSpace
        var out: [String] = []
        for _ in 0..<wordCount { out.append(wordlist[Int(v % UInt32(wordBase))]); v /= UInt32(wordBase) }
        return out
    }

    /// Inverse of `words(from:)` — least-significant symbol first.
    static func value(fromWords words: [String]) -> UInt32? {
        guard words.count == wordCount else { return nil }
        var v: UInt32 = 0
        for w in words.reversed() {
            guard let idx = index(ofWord: w) else { return nil }
            v = v &* UInt32(wordBase) &+ UInt32(idx)
        }
        return v
    }

    /// Single-symbol access for other renderings built on the same wordlist.
    static func word(at index: Int) -> String { wordlist[index % wordBase] }
    static func index(ofWord word: String) -> Int? { wordIndex[word] }

    private static let wordIndex: [String: Int] =
        Dictionary(uniqueKeysWithValues: wordlist.enumerated().map { ($1, $0) })

    public static func matches(_ a: UInt32, _ b: UInt32) -> Bool {
        // Constant-time over 4 bytes.
        SymmetricKey(data: withUnsafeBytes(of: a.bigEndian) { Data($0) })
            == SymmetricKey(data: withUnsafeBytes(of: b.bigEndian) { Data($0) })
    }
}
