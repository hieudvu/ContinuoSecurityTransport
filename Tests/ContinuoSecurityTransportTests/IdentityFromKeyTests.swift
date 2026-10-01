import Foundation
import Security
import Testing
@testable import ContinuoSecurityTransport

/// An identity hand-built over a key presents a fingerprint that depends on the key
/// alone, so the login-window agent — which builds its certificate afresh at every
/// start — presents the fingerprint its controllers pinned.
@Suite struct IdentityFromKeyTests {
    private func randomKey() throws -> SecKey {
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrKeySizeInBits as String: 256]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else { throw TrustStoreError.signingFailed }
        return key
    }

    @Test func sameKeyGivesTheSameFingerprintEveryTime() throws {
        let key = try randomKey()
        let a = try IdentityFactory.makeSelfSigned(label: "a", privateKey: key)
        let b = try IdentityFactory.makeSelfSigned(label: "b", privateKey: key)
        #expect(TLSFingerprint.ofSPKI(a.spkiDER) == TLSFingerprint.ofSPKI(b.spkiDER))
    }
}
