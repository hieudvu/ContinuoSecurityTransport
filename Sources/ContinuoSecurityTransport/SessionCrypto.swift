import CryptoKit
import Foundation
import os

public enum SessionCryptoError: Error, Equatable, Sendable {
    case invalidPublicKey
    case malformedCiphertext
    case authenticationFailed
    case nonceExhausted
}

public struct SecuritySessionKeyOffer: Sendable {
    fileprivate let privateKey: Curve25519.KeyAgreement.PrivateKey
    public let ephemeralPublicKey: [UInt8]
}

/// Directional key material for one authenticated session. Instances never
/// cross the module boundary; callers receive a `SecuritySessionContext`.
struct SecuritySessionKeys: Sendable {
    fileprivate let sendKey: SymmetricKey
    fileprivate let receiveKey: SymmetricKey
}

/// Opaque cryptographic capabilities for one side of an authenticated session.
/// Product code can seal and open bytes but cannot read or export key material.
public struct SecuritySessionContext: Sendable {
    public let sealer: SessionAEADSealer
    public let opener: SessionAEADOpener

    fileprivate init(keys: SecuritySessionKeys) {
        self.sealer = SessionAEADSealer(keys: keys)
        self.opener = SessionAEADOpener(keys: keys)
    }
}

public enum SessionKeyAgreement {
    public static func makeOffer() -> SecuritySessionKeyOffer {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return SecuritySessionKeyOffer(
            privateKey: privateKey,
            ephemeralPublicKey: Array(privateKey.publicKey.rawRepresentation)
        )
    }

    public static func accept(
        offerPublicKey: [UInt8]
    ) throws -> (context: SecuritySessionContext, responsePublicKey: [UInt8]) {
        let offerKey: Curve25519.KeyAgreement.PublicKey
        do {
            offerKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: Data(offerPublicKey)
            )
        } catch {
            throw SessionCryptoError.invalidPublicKey
        }

        let responsePrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let responsePublicKey = Array(responsePrivateKey.publicKey.rawRepresentation)
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try responsePrivateKey.sharedSecretFromKeyAgreement(with: offerKey)
        } catch {
            throw SessionCryptoError.invalidPublicKey
        }
        return (
            SecuritySessionContext(keys: derive(
                sharedSecret: sharedSecret,
                offerPublicKey: offerPublicKey,
                responsePublicKey: responsePublicKey,
                isInitiator: false
            )),
            responsePublicKey
        )
    }

    public static func complete(
        offer: SecuritySessionKeyOffer,
        responsePublicKey: [UInt8]
    ) throws -> SecuritySessionContext {
        let responseKey: Curve25519.KeyAgreement.PublicKey
        do {
            responseKey = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: Data(responsePublicKey)
            )
        } catch {
            throw SessionCryptoError.invalidPublicKey
        }

        let sharedSecret: SharedSecret
        do {
            sharedSecret = try offer.privateKey.sharedSecretFromKeyAgreement(with: responseKey)
        } catch {
            throw SessionCryptoError.invalidPublicKey
        }
        return SecuritySessionContext(
            keys: derive(
                sharedSecret: sharedSecret,
                offerPublicKey: offer.ephemeralPublicKey,
                responsePublicKey: responsePublicKey,
                isInitiator: true
            )
        )
    }

    private static func derive(
        sharedSecret: SharedSecret,
        offerPublicKey: [UInt8],
        responsePublicKey: [UInt8],
        isInitiator: Bool
    ) -> SecuritySessionKeys {
        let salt = Data(SHA256.hash(data: Data(offerPublicKey + responsePublicKey)))
        let initiatorToResponder = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("continuo-security-session-i2r-v1".utf8),
            outputByteCount: 32
        )
        let responderToInitiator = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data("continuo-security-session-r2i-v1".utf8),
            outputByteCount: 32
        )
        return isInitiator
            ? SecuritySessionKeys(
                sendKey: initiatorToResponder,
                receiveKey: responderToInitiator
            )
            : SecuritySessionKeys(
                sendKey: responderToInitiator,
                receiveKey: initiatorToResponder
            )
    }
}

struct SessionNonceSequence: Sendable {
    private(set) var epoch: UInt32
    private(set) var sequence: UInt64
    private var exhausted = false

    init(epoch: UInt32 = 0, sequence: UInt64 = 0) {
        self.epoch = epoch
        self.sequence = sequence
    }

    mutating func take() throws -> (epoch: UInt32, sequence: UInt64) {
        guard !exhausted else { throw SessionCryptoError.nonceExhausted }
        let current = (epoch, sequence)
        if sequence < .max {
            sequence += 1
        } else if epoch < .max {
            epoch += 1
            sequence = 0
        } else {
            exhausted = true
        }
        return current
    }
}

/// Thread-safe, monotonic nonce owner for one directional key. Callers cannot
/// provide or reuse a nonce; copies of `SecuritySessionContext` share this object.
public final class SessionAEADSealer: @unchecked Sendable {
    private let key: SymmetricKey
    private let nonceSequence = OSAllocatedUnfairLock(initialState: SessionNonceSequence())

    fileprivate init(keys: SecuritySessionKeys) {
        self.key = keys.sendKey
    }

    public func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
        // Reserve before encryption. If sealing itself fails, skipping a nonce is
        // harmless; ever reusing one under this key would not be.
        let position = try nonceSequence.withLock { try $0.take() }
        let header = sessionHeader(epoch: position.epoch, sequence: position.sequence)
        let nonce = try ChaChaPoly.Nonce(data: Data(header))
        let box = try ChaChaPoly.seal(
            Data(plaintext),
            using: key,
            nonce: nonce,
            authenticating: Data(header)
        )
        return header + Array(box.ciphertext) + Array(box.tag)
    }
}

public struct SessionAEADOpener: Sendable {
    private let key: SymmetricKey

    fileprivate init(keys: SecuritySessionKeys) {
        self.key = keys.receiveKey
    }

    public func open(
        _ ciphertext: [UInt8]
    ) throws -> (epoch: UInt32, sequence: UInt64, plaintext: [UInt8]) {
        guard ciphertext.count >= 28 else {
            throw SessionCryptoError.malformedCiphertext
        }
        let header = Array(ciphertext[0 ..< 12])
        let encrypted = Data(ciphertext[12 ..< ciphertext.count - 16])
        let tag = Data(ciphertext[ciphertext.count - 16 ..< ciphertext.count])

        do {
            let nonce = try ChaChaPoly.Nonce(data: Data(header))
            let box = try ChaChaPoly.SealedBox(
                nonce: nonce,
                ciphertext: encrypted,
                tag: tag
            )
            let plaintext = try ChaChaPoly.open(
                box,
                using: key,
                authenticating: Data(header)
            )
            return (
                readUInt32(header, offset: 0),
                readUInt64(header, offset: 4),
                Array(plaintext)
            )
        } catch {
            throw SessionCryptoError.authenticationFailed
        }
    }
}

private func sessionHeader(epoch: UInt32, sequence: UInt64) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: epoch >> 24),
        UInt8(truncatingIfNeeded: epoch >> 16),
        UInt8(truncatingIfNeeded: epoch >> 8),
        UInt8(truncatingIfNeeded: epoch),
        UInt8(truncatingIfNeeded: sequence >> 56),
        UInt8(truncatingIfNeeded: sequence >> 48),
        UInt8(truncatingIfNeeded: sequence >> 40),
        UInt8(truncatingIfNeeded: sequence >> 32),
        UInt8(truncatingIfNeeded: sequence >> 24),
        UInt8(truncatingIfNeeded: sequence >> 16),
        UInt8(truncatingIfNeeded: sequence >> 8),
        UInt8(truncatingIfNeeded: sequence),
    ]
}

private func readUInt32(_ bytes: [UInt8], offset: Int) -> UInt32 {
    bytes[offset ..< offset + 4].reduce(0) { ($0 << 8) | UInt32($1) }
}

private func readUInt64(_ bytes: [UInt8], offset: Int) -> UInt64 {
    bytes[offset ..< offset + 8].reduce(0) { ($0 << 8) | UInt64($1) }
}
