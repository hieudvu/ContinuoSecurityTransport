import Foundation
import Network
import Security

// MARK: - TLS pin verification (Task 12)
//
// Continuo has no CA. Trust is pinned by the SHA-256 of the peer's SubjectPublicKeyInfo
// (SPKI) DER. The verify block deliberately ignores chain/expiry (there is no CA) and
// compares ONLY the SPKI fingerprint. Fail closed: if the fingerprint can't be extracted,
// reject the handshake.

public enum PinVerification {
    /// Extracts the leaf certificate from `secTrust`, computes its SPKI DER fingerprint.
    ///
    /// `SecCertificateCopyKey` + `SecKeyCopyExternalRepresentation` for an EC key yields the
    /// RAW EC point (0x04 ‖ X ‖ Y), NOT the full SPKI DER. Task 11's `IdentityFactory`
    /// fingerprints the full SPKI DER via `SPKI.der(fromECPoint:)`, so we wrap the raw point
    /// with that SAME shared helper here. This makes the presented-cert fingerprint match the
    /// pinned identity's fingerprint by construction (both hash identical SPKI DER bytes).
    public static func spkiFingerprint(of secTrust: SecTrust) -> TLSFingerprint? {
        guard let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
              let leaf = chain.first,
              let pub = SecCertificateCopyKey(leaf),
              let ecPoint = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return nil }
        let spkiDER = SPKI.der(fromECPoint: [UInt8](ecPoint))  // raw EC point -> full SPKI DER (Task 11's helper)
        return TLSFingerprint.ofSPKI(spkiDER)
    }

    /// Builds `NWProtocolTLS.Options` bound to the local `identity`, TLS 1.3 minimum, with a
    /// verify block that computes the peer leaf's SPKI fingerprint and calls `verify` to
    /// pin-compare. Chain/expiry are deliberately ignored (no CA). Fails closed on any
    /// extraction failure.
    public static func makeTLSOptions(identity: SecIdentity, verify: @escaping @Sendable (TLSFingerprint) -> Bool) -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()
        let sec = options.securityProtocolOptions
        if let secIdentity = sec_identity_create(identity) {
            sec_protocol_options_set_local_identity(sec, secIdentity)
        }
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv13)
        sec_protocol_options_set_verify_block(sec, { _, secTrustRef, complete in
            let trust = sec_trust_copy_ref(secTrustRef).takeRetainedValue()
            guard let fp = spkiFingerprint(of: trust) else { complete(false); return }
            complete(verify(fp))  // pin-compare only; chain/expiry deliberately ignored (no CA)
        }, DispatchQueue(label: "app.continuo.tls.verify"))
        return options
    }
}
