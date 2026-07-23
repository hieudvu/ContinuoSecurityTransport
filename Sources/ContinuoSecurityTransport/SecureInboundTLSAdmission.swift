import Network
import Security

/// Source-visible admission policy for an unpinned inbound pairing connection.
/// Discovery/listener lifecycle stays with the product, while the security
/// package owns mutual certificate presentation and connection-bound identity.
public enum SecureInboundTLSAdmission {
    /// Pairing deliberately accepts any certificate chain because the SAS is the
    /// authenticator, but it requires the peer to present a certificate so that
    /// the SAS transcript can bind the exact connection's public key.
    public static func makePairingTLSOptions(identity: SecIdentity) -> NWProtocolTLS.Options {
        let options = PinVerification.makeTLSOptions(identity: identity) { _ in true }
        sec_protocol_options_set_peer_authentication_required(
            options.securityProtocolOptions,
            true
        )
        return options
    }

    /// Captures one immutable metadata source in one provider closure. The
    /// generic form is the fully mocked unit-test seam.
    public static func fingerprintProvider<Metadata: TLSPeerPublicKeyMetadata>(
        metadata: Metadata
    ) -> @Sendable () -> TLSFingerprint? {
        { PeerConnectionFingerprint.make(from: metadata) }
    }

    /// Production adapter for the exact accepted connection supplied by the
    /// listener callback. Call the returned provider only after `.ready`.
    public static func fingerprintProvider(
        for connection: NWConnection
    ) -> @Sendable () -> TLSFingerprint? {
        fingerprintProvider(
            metadata: NWConnectionTLSPeerPublicKeyMetadata(connection: connection)
        )
    }
}
