import Dispatch
import Foundation
import Network
import Security

/// Minimal seam between TLS metadata and Continuo's pinned SPKI identity.
/// Production reads one connection's negotiated TLS metadata; unit tests supply
/// a complete in-memory source and never open a socket.
public protocol TLSPeerPublicKeyMetadata: Sendable {
    func copyPeerPublicKeyBytes() -> [UInt8]?
}

/// Converts the raw uncompressed P-256 public key returned by Security.framework
/// into the same SPKI fingerprint used by identity creation and certificate pinning.
public enum PeerConnectionFingerprint {
    public static func make(from metadata: some TLSPeerPublicKeyMetadata) -> TLSFingerprint? {
        guard let point = metadata.copyPeerPublicKeyBytes(),
              point.count == 65,
              point.first == 0x04 else { return nil }
        return TLSFingerprint.ofSPKI(SPKI.der(fromECPoint: point))
    }
}

/// Per-connection Security.framework adapter. Call only after the connection is
/// `.ready`, when negotiated TLS metadata is available.
public final class NWConnectionTLSPeerPublicKeyMetadata: TLSPeerPublicKeyMetadata, @unchecked Sendable {
    private let connection: NWConnection

    public init(connection: NWConnection) {
        self.connection = connection
    }

    public func copyPeerPublicKeyBytes() -> [UInt8]? {
        // Derive the raw EC point from the peer's LEAF CERTIFICATE, not from
        // `sec_protocol_metadata_copy_peer_public_key`: that API returns nil (or a
        // non-EC-point encoding) for our self-signed EC identities on real
        // hardware AND on loopback, which silently fails the inbound fingerprint
        // closed and makes every inbound pairing/session connection reset before
        // the SAS exchange. The certificate chain is reliably present here because
        // the pairing listener REQUIRES peer certificate presentation (mutual TLS),
        // and `SecCertificateCopyKey` + `SecKeyCopyExternalRepresentation` yield the
        // SAME raw EC point (0x04 ‖ X ‖ Y) the verify-block path (`PinVerification`)
        // and identity creation use — so the fingerprint matches by construction.
        guard let tls = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return nil
        }
        var leaf: SecCertificate?
        _ = sec_protocol_metadata_access_peer_certificate_chain(tls.securityProtocolMetadata) { certificate in
            if leaf == nil {
                leaf = sec_certificate_copy_ref(certificate).takeRetainedValue()
            }
        }
        guard let leaf,
              let publicKey = SecCertificateCopyKey(leaf),
              let ecPoint = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        return [UInt8](ecPoint)
    }
}
