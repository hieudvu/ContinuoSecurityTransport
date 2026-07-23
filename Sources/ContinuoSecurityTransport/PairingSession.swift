import Foundation

// MARK: - Pairing coordinator (Task 15)
//
// `PairingSession` is a PURE, message-driven state machine for the commit-then-reveal
// Short Authentication String (SAS) exchange. It performs NO I/O: it consumes
// `SecurityHandshakeMessage`s and emits `PairingEvent`s. The live NW connection, teardown, and
// reconnect are orchestrated by `PeerSessionManager` (Task 17).
//
// SECURITY — commit-before-reveal is the whole MITM defense: each side commits to its
// ephemeral pairing material BEFORE it sees the peer's reveal, so an attacker must bind
// its ephemeral before learning the peer's, making a forced-matching SAS 2^-24 per attempt.
// The step-3(b) live-cert cross-check binds the SAS to the ACTUAL TLS leaf seen on the
// pairing connection (`presentedPeerFingerprint`), defeating a substituted certificate.
//
// Fail closed: any verification failure emits `.failed(...)` and halts — never compute or
// display a SAS after a mismatch, never pin on failure.
//
// Redacted: this file logs NOTHING (no SAS/nonces/commitments/reveals/fingerprints/keys).

/// Side effects the coordinator asks its host (the connection layer) to perform.
public enum PairingEvent: Sendable, Equatable {
    /// Transmit this security-handshake frame to the peer.
    case send(SecurityHandshakeMessage)
    /// Show this SAS to the user for out-of-band comparison.
    case displaySAS(UInt32)
    /// Persist this peer as trusted (only after the user confirms the SAS matches).
    case pinPeer(PinnedPeer)
    /// The exchange failed and is halted; never followed by a SAS or a pin.
    case failed(PairingSASError)
}

public enum PairingIngressDecision: Equatable, Sendable {
    case drive
    case peerConfirmation(Bool)
    case reject
}

/// Pure phase/message gate used by the live connection layer. Keeping this decision
/// independent of Network.framework makes the unpinned-channel authority boundary
/// exhaustively unit-testable without opening a socket.
public enum PairingIngress {
    public static func decide(
        _ message: SecurityHandshakeMessage,
        pairingActive: Bool
    ) -> PairingIngressDecision {
        guard pairingActive else { return .reject }
        switch message {
        case .negotiate, .pairCommit, .pairReveal, .failure:
            return .drive
        case let .pairSasConfirm(accepted):
            return accepted ? .peerConfirmation(true) : .reject
        case .sessionKeyOffer, .sessionKeyAccept, .complete:
            return .reject
        }
    }
}

/// A pure, message-driven commit-reveal SAS state machine for one pairing attempt.
///
/// Transition summary (host = initiator = "A", client = responder = "B"):
/// - `start()` (both roles): negotiate the independent security protocol; the initiator
///   then commits immediately.
/// - `handle(.pairCommit)`: store peer commitment; if we have NOT committed yet, commit
///   reactively (responder path); if we already committed (initiator path), reveal.
/// - `handle(.pairReveal)`: verify commitment + cross-check fingerprint (fail closed),
///   compute the SAS on the role-fixed transcript, emit `displaySAS`; also reveal if we
///   have not yet (responder path).
/// - `userConfirmed()`: request durable `pinPeer`, then emit `pairSasConfirm(true)`.
///
/// Idempotency flags make the machine robust to duplicate/extra deliveries from the
/// caller's pump loop.
public struct PairingSession: Sendable {
    private let role: DeviceRole
    private let selfMachineID: String
    private let presentedPeerFingerprint: TLSFingerprint
    private let localKeyPair: PairingKeyPair

    /// Our own reveal, built once at init from a fresh nonce so the nonce used in our
    /// commitment is the SAME one we later reveal (the commitment must match the reveal).
    private let ownReveal: PairingReveal

    // Mutable state.
    private var storedPeerCommitment: [UInt8]?
    private var sentNegotiation = false
    private var peerNegotiated = false
    private var sentCommit = false
    private var sentReveal = false
    private var finished = false
    private var locallyConfirmed = false
    /// I4: the peer's REAL machineID, learned ONLY from the verified reveal frame
    /// (never a pre-known/discovery-hash parameter). Set exactly when `handleReveal`
    /// has confirmed the commitment binds it and the live-cert cross-check passed;
    /// `userConfirmed` pins under THIS id. Nil until then, so a pin can never be
    /// written for an unverified identity (fail closed).
    private let selfDeviceName: String
    private var verifiedPeerMachineID: String?
    /// The peer's device name, learned ONLY from the SAME verified reveal that is
    /// bound by the commitment + SAS transcript — so it is MITM-safe to display.
    private var verifiedPeerDeviceName: String?

    /// The peer's REAL machineID once the reveal has been verified, else nil.
    /// Callers (the manager) read this to key/pin the peer by the cross-checked
    /// identity rather than the discovery hash.
    public var pairedPeerMachineID: String? { verifiedPeerMachineID }
    /// The peer's verified (commitment+SAS-bound) device name, else nil.
    public var pairedPeerDeviceName: String? { verifiedPeerDeviceName }

    public init(
        role: DeviceRole,
        selfMachineID: String,
        selfDeviceName: String,
        selfFingerprint: TLSFingerprint,
        localKeyPair: PairingKeyPair,
        presentedPeerFingerprint: TLSFingerprint
    ) {
        self.role = role
        self.selfMachineID = selfMachineID
        self.selfDeviceName = selfDeviceName
        self.presentedPeerFingerprint = presentedPeerFingerprint
        self.localKeyPair = localKeyPair
        self.ownReveal = PairingReveal(
            ephPublicKey: localKeyPair.publicKeyRawRepresentation,
            nonce: PairingSAS.randomNonce(),
            tlsFingerprint: selfFingerprint.bytes,
            machineID: selfMachineID,
            deviceName: selfDeviceName,
            role: role
        )
    }

    // MARK: - Entry points

    /// Starts the independent security protocol. Both roles negotiate; the host also
    /// commits immediately. Idempotent and inert after terminal failure/completion.
    public mutating func start() -> [PairingEvent] {
        guard !sentNegotiation, !finished else { return [] }
        sentNegotiation = true
        var events: [PairingEvent] = [
            .send(.negotiate(version: SecurityHandshakeProtocol.version)),
        ]
        if role == .host, !sentCommit {
            sentCommit = true
            events.append(.send(.pairCommit(commitment: PairingSAS.commitment(for: ownReveal))))
        }
        return events
    }

    /// Consumes one security-handshake frame and returns the resulting side effects.
    public mutating func handle(_ msg: SecurityHandshakeMessage) -> [PairingEvent] {
        // A peer confirmation is meaningful only after this side verified the reveal
        // and displayed the SAS. Accepting it earlier would let a stale or malicious
        // frame satisfy the live layer's mutual-confirm barrier prematurely.
        if case let .pairSasConfirm(accepted) = msg {
            guard accepted else {
                finished = true
                return [.failed(.peerRejected)]
            }
            guard peerNegotiated, verifiedPeerMachineID != nil else {
                return failUnexpectedMessage()
            }
            return []
        }
        guard !finished else { return [] }
        switch msg {
        case let .negotiate(version):
            guard version == SecurityHandshakeProtocol.version else {
                finished = true
                return [.failed(.unsupportedProtocolVersion)]
            }
            guard !peerNegotiated else { return [] }
            peerNegotiated = true
            return []
        case let .pairCommit(commitment):
            guard peerNegotiated else { return failUnexpectedMessage() }
            return handleCommit(commitment)
        case let .pairReveal(ephPublicKey, nonce, tlsFingerprint, machineID, deviceName):
            guard peerNegotiated else { return failUnexpectedMessage() }
            return handleReveal(ephPublicKey: ephPublicKey, nonce: nonce, tlsFingerprint: tlsFingerprint, machineID: machineID, deviceName: deviceName)
        case .pairSasConfirm:
            return [] // handled above so valid confirmations remain admissible after SAS completion
        case .failure:
            finished = true
            return [.failed(.peerRejected)]
        case .sessionKeyOffer, .sessionKeyAccept, .complete:
            return failUnexpectedMessage()
        }
    }

    /// User confirmed the displayed SAS matches the peer's: authorize the connection and
    /// pin the fingerprint ACTUALLY on the wire (which, post cross-check, equals the
    /// revealed one) under the peer's REAL machineID as learned from the verified
    /// reveal (I4). Fails closed (emits nothing) if no reveal has been verified yet —
    /// a pin must never be written for an unauthenticated/unrevealed identity.
    public mutating func userConfirmed() -> [PairingEvent] {
        guard let peerID = verifiedPeerMachineID, !locallyConfirmed else { return [] }
        locallyConfirmed = true
        return [
            .pinPeer(PinnedPeer(machineID: peerID, fingerprint: presentedPeerFingerprint,
                                deviceName: verifiedPeerDeviceName ?? "")),
            // Persistence is deliberately requested first. The live layer emits this
            // confirmation only after the durable pin succeeds, so the peer cannot
            // pivot to a pin-verified reconnect while this side is still unpinned.
            .send(.pairSasConfirm(accepted: true)),
        ]
    }

    // MARK: - Transitions

    private mutating func handleCommit(_ commitment: [UInt8]) -> [PairingEvent] {
        // First commitment wins; ignore duplicates so the pump loop can't double-drive us.
        guard storedPeerCommitment == nil else { return [] }
        storedPeerCommitment = commitment

        if !sentCommit {
            // Responder path: we had not committed yet — commit reactively (do NOT reveal
            // yet; the peer has not revealed).
            sentCommit = true
            return [.send(.pairCommit(commitment: PairingSAS.commitment(for: ownReveal)))]
        } else {
            // Initiator path: both sides have now committed — it is safe to reveal.
            guard !sentReveal else { return [] }
            sentReveal = true
            return [revealEvent()]
        }
    }

    private mutating func handleReveal(ephPublicKey: [UInt8], nonce: [UInt8], tlsFingerprint: [UInt8], machineID: String, deviceName: String) -> [PairingEvent] {
        guard !finished else { return [] }
        // A reveal without a stored commitment is out of order; ignore (never verify blind).
        guard let commitment = storedPeerCommitment else { return [] }

        // I4: reconstruct the peer's full reveal using the machineID REVEALED IN THE
        // FRAME (not a pre-known/discovery-hash parameter). The peer committed over its
        // real machineID, so the verifier must reconstruct the SAME bytes to open the
        // commitment. `role` is not on the wire but is fixed by the connection direction
        // (host↔client), so both sides agree on it deterministically.
        let peerRole: DeviceRole = (role == .host) ? .client : .host
        let peerReveal = PairingReveal(
            ephPublicKey: ephPublicKey,
            nonce: nonce,
            tlsFingerprint: tlsFingerprint,
            machineID: machineID,
            deviceName: deviceName,
            role: peerRole
        )

        // 1. Commitment must open to exactly what was committed (defeats late binding).
        //    Because the commitment covers `machineID`, this ALSO proves the revealed
        //    identity is the one the peer bound before either side revealed — a MITM
        //    cannot substitute a different machineID without failing this check (and
        //    any forced-matching attempt is 2^-24 per the SAS, confirmed out-of-band).
        guard PairingSAS.verifyCommitment(commitment, against: peerReveal) else {
            finished = true
            return [.failed(.commitmentMismatch)]
        }

        // 2. Live-cert cross-check: the revealed fingerprint must equal the leaf actually
        //    seen on the live pairing TLS connection. This binds the SAS to the real channel.
        guard peerReveal.tlsFingerprint == presentedPeerFingerprint.bytes else {
            finished = true
            return [.failed(.fingerprintMismatch)]
        }

        // 3. Role-fixed transcript so BOTH sides compute an identical SAS: host = initiator.
        let initiatorReveal = (role == .host) ? ownReveal : peerReveal
        let responderReveal = (role == .host) ? peerReveal : ownReveal

        let sas: UInt32
        do {
            sas = try PairingSAS.sasValue(
                localKeyPair: localKeyPair,
                peerEphPublicKey: peerReveal.ephPublicKey,
                initiatorReveal: initiatorReveal,
                responderReveal: responderReveal,
                protocolVersion: SecurityHandshakeProtocol.version
            )
        } catch let error as PairingSASError {
            finished = true
            return [.failed(error)]
        } catch {
            finished = true
            return [.failed(.keyAgreementFailed)]
        }

        finished = true
        // Only now — after the commitment opened to this machineID AND the live-cert
        // cross-check passed — is the revealed identity trustworthy enough to pin.
        verifiedPeerMachineID = machineID
        verifiedPeerDeviceName = deviceName
        var events: [PairingEvent] = []
        // Responder path: the peer revealed first (we have not) — reveal now so it can also
        // reach the SAS. Safe: we have already committed (both committed before either reveal).
        if !sentReveal {
            sentReveal = true
            events.append(revealEvent())
        }
        events.append(.displaySAS(sas))
        return events
    }

    private func revealEvent() -> PairingEvent {
        .send(.pairReveal(
            ephPublicKey: ownReveal.ephPublicKey,
            nonce: ownReveal.nonce,
            tlsFingerprint: ownReveal.tlsFingerprint,
            machineID: ownReveal.machineID,   // == selfMachineID; the peer verifies our commitment binds it
            deviceName: ownReveal.deviceName
        ))
    }

    private mutating func failUnexpectedMessage() -> [PairingEvent] {
        finished = true
        return [.failed(.unexpectedMessage)]
    }
}
