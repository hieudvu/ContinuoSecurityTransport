import CryptoKit
import Foundation

/// Errors from the PIN + Curve25519 pairing handshake.
public enum PairingError: Error, Equatable, Sendable {
    /// A raw public-key representation was not a valid Curve25519 key.
    case invalidPublicKey
    /// Key agreement failed (e.g. a malformed peer key).
    case keyAgreementFailed
    /// The confirmation tag did not verify: wrong PIN or a man-in-the-middle.
    case confirmationMismatch
    /// A PIN was not exactly 6 decimal digits.
    case invalidPIN
}

/// A 6-digit pairing PIN shown on the target machine and typed on the host.
///
/// The PIN is never transmitted; it is the out-of-band secret the user carries.
/// It authenticates the key exchange by salting the confirmation tag, so a
/// man-in-the-middle who relayed different public keys produces a different tag
/// and fails verification.
public struct PairingPIN: Equatable, Sendable {
    public let digits: String

    /// - Throws: `PairingError.invalidPIN` unless `digits` is exactly 6 decimals.
    public init(digits: String) throws {
        guard digits.count == 6, digits.allSatisfy(\.isNumber) else {
            throw PairingError.invalidPIN
        }
        self.digits = digits
    }

    /// Generates a uniformly random 6-digit PIN (000000–999999).
    ///
    /// - Parameter generator: injectable RNG so tests are deterministic; defaults
    ///   to the system CSPRNG for real pairing.
    public static func random<G: RandomNumberGenerator>(using generator: inout G) -> PairingPIN {
        let value = UInt32.random(in: 0...999_999, using: &generator)
        // `init` cannot fail for a value in range; the padded string is 6 digits.
        return try! PairingPIN(digits: String(format: "%06u", value))
    }

    public static func random() -> PairingPIN {
        var generator = SystemRandomNumberGenerator()
        return random(using: &generator)
    }
}

/// Stateless helpers for the pairing handshake. Deliberately holds no I/O:
/// Persistence and network exchange live outside this pure cryptographic type,
/// so it remains fully unit-testable.
///
/// Flow:
/// 1. Target shows a random `PairingPIN`; both sides make a `PairingKeyPair`.
/// 2. Public keys are exchanged over an untrusted candidate channel.
/// 3. User types the PIN on the host.
/// 4. Host computes and sends `confirmationTag`.
/// 5. Target recomputes the tag with its own PIN and `verify`s it. A match
///    proves both sides share the same PIN *and* saw the same two public keys,
///    so each may now pin and store the peer's public key.
public enum Pairing {
    private static let info = Data("continuo-pairing-v1".utf8)

    /// Derives the confirmation tag binding the shared secret, the PIN, and both
    /// public keys. Deterministic in all inputs and independent of argument
    /// order because host/target keys are passed in fixed roles.
    ///
    /// - Parameters:
    ///   - sharedSecret: output of `PairingKeyPair.sharedSecret(with:)`.
    ///   - pin: the 6-digit PIN, used as HKDF salt.
    ///   - hostPublicKey: host pairing public key (raw representation).
    ///   - targetPublicKey: target pairing public key (raw representation).
    public static func confirmationTag(
        sharedSecret: SharedSecret,
        pin: PairingPIN,
        hostPublicKey: [UInt8],
        targetPublicKey: [UInt8]
    ) -> [UInt8] {
        var transcript = Data()
        transcript.append(contentsOf: hostPublicKey)
        transcript.append(contentsOf: targetPublicKey)
        let key = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(pin.digits.utf8),
            sharedInfo: info + transcript,
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Array($0) }
    }

    /// Constant-time comparison of a received tag against the locally computed
    /// expected tag.
    public static func verify(receivedTag: [UInt8], expectedTag: [UInt8]) -> Bool {
        // `SymmetricKey`'s `==` is constant time; wrap both sides in it.
        SymmetricKey(data: receivedTag) == SymmetricKey(data: expectedTag)
    }
}

/// A Curve25519 key-agreement key pair for one pairing attempt, wrapping
/// CryptoKit behind a small, mockable surface.
///
/// For the long-term identity key that TLS later pins, reuse the same
/// `publicKeyRawRepresentation`; the network layer stores the *peer's* value in
/// the Keychain as the trust anchor.
public struct PairingKeyPair: Sendable {
    private let privateKey: Curve25519.KeyAgreement.PrivateKey

    /// Generates a fresh key pair from the system CSPRNG.
    public init() {
        privateKey = Curve25519.KeyAgreement.PrivateKey()
    }

    /// Reconstructs a key pair from a stored raw private-key representation.
    ///
    /// - Throws: `PairingError.invalidPublicKey` if the bytes are not a valid key.
    public init(rawPrivateKey: [UInt8]) throws {
        do {
            privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(rawPrivateKey))
        } catch {
            throw PairingError.invalidPublicKey
        }
    }

    /// This key pair's public key in raw representation, for the wire and for
    /// storage as a pinned trust anchor.
    public var publicKeyRawRepresentation: [UInt8] {
        Array(privateKey.publicKey.rawRepresentation)
    }

    /// The private key's raw representation, for optional secure storage.
    public var privateKeyRawRepresentation: [UInt8] {
        Array(privateKey.rawRepresentation)
    }

    /// Performs Curve25519 key agreement with a peer's raw public key.
    ///
    /// - Throws: `PairingError.invalidPublicKey` / `.keyAgreementFailed`.
    public func sharedSecret(with peerPublicKey: [UInt8]) throws -> SharedSecret {
        let peer: Curve25519.KeyAgreement.PublicKey
        do {
            peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(peerPublicKey))
        } catch {
            throw PairingError.invalidPublicKey
        }
        do {
            return try privateKey.sharedSecretFromKeyAgreement(with: peer)
        } catch {
            throw PairingError.keyAgreementFailed
        }
    }
}
