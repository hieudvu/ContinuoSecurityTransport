import Foundation
import Network
import os

/// Queue-confined decoder for the bounded, length-prefixed security stream.
/// It is intentionally independent of Network.framework so fragmentation,
/// coalescing, malformed payloads, and size limits are covered by pure tests.
struct SecurityHandshakeStreamDecoder: Sendable {
    private var buffer: [UInt8] = []
    private var readIndex = 0

    mutating func ingest(_ bytes: [UInt8]) throws -> [SecurityHandshakeMessage] {
        buffer.append(contentsOf: bytes)
        var messages: [SecurityHandshakeMessage] = []

        while let (payload, next) = try SecurityFrameCodec.parseAt(
            buffer,
            offset: readIndex,
            maxFrame: SecurityHandshakeProtocol.maxMessageBytes
        ) {
            readIndex = next
            messages.append(try SecurityHandshakeMessage.decode(payload))
        }

        compactConsumed()
        return messages
    }

    private mutating func compactConsumed() {
        guard readIndex > 0 else { return }
        buffer.removeFirst(readIndex)
        readIndex = 0
    }
}

private let securityHandshakeLog = Logger(subsystem: "app.continuo", category: "security-handshake")

/// A dedicated TLS stream for the source-visible security handshake. Product
/// messages cannot be encoded or decoded by this type, making the
/// unpinned connection boundary structural rather than a phase check alone.
public final class SecurityHandshakeChannel: @unchecked Sendable {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private var onMessage: ((SecurityHandshakeMessage) -> Void)?
    private var decoder = SecurityHandshakeStreamDecoder()
    private let state = OSAllocatedUnfairLock(initialState: (started: false, closed: false))

    public init(accepted connection: NWConnection) {
        self.connection = connection
        self.queue = DispatchQueue(label: "app.continuo.security-handshake")
    }

    /// Adopts a connection already started on `queue` by the inbound classifier.
    public init(accepted connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    public func start(onMessage: @escaping (SecurityHandshakeMessage) -> Void) {
        state.withLock { state in
            precondition(!state.started, "SecurityHandshakeChannel.start called more than once")
            state.started = true
        }
        self.onMessage = onMessage
        connection.start(queue: queue)
        receiveLoop()
    }

    public func startAdopted(onMessage: @escaping (SecurityHandshakeMessage) -> Void) {
        state.withLock { state in
            precondition(!state.started, "SecurityHandshakeChannel.startAdopted called more than once")
            state.started = true
        }
        self.onMessage = onMessage
        receiveLoop()
    }

    public func send(_ message: SecurityHandshakeMessage) {
        guard !state.withLock({ $0.closed }) else { return }
        guard let payload = try? message.encode() else {
            failClosed(reason: "invalid outbound message", byteCount: 0)
            return
        }
        connection.send(
            content: SecurityFrameCodec.frameData(payload),
            completion: .contentProcessed { _ in }
        )
    }

    /// Calls `then` after Network.framework processes the send, or immediately if
    /// the channel is already closed / the bounded codec rejects the message.
    public func send(_ message: SecurityHandshakeMessage, then: @escaping @Sendable () -> Void) {
        guard !state.withLock({ $0.closed }) else { then(); return }
        guard let payload = try? message.encode() else {
            failClosed(reason: "invalid outbound message", byteCount: 0)
            then()
            return
        }
        connection.send(
            content: SecurityFrameCodec.frameData(payload),
            completion: .contentProcessed { _ in then() }
        )
    }

    public func cancel() {
        state.withLock { $0.closed = true }
        connection.cancel()
    }

    private func receiveLoop() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                do {
                    for message in try self.decoder.ingest(Array(data)) {
                        self.onMessage?(message)
                    }
                } catch {
                    self.failClosed(reason: "invalid inbound frame", byteCount: data.count)
                    return
                }
            }
            // Ending the loop is not the same as closing the channel: without
            // this the connection is abandoned while `send()` still believes it
            // is live, and the channel stays "open" forever. Both exits route
            // through `failClosed` so the state and the connection agree.
            if let error {
                self.failClosed(reason: "receive failed (\(error.debugDescription))", byteCount: 0)
                return
            }
            if isComplete {
                self.failClosed(reason: "peer closed the handshake connection", byteCount: 0)
                return
            }
            self.receiveLoop()
        }
    }

    /// Logs only an error class and count; handshake payloads and identities stay
    /// out of diagnostics.
    private func failClosed(reason: String, byteCount: Int) {
        state.withLock { $0.closed = true }
        securityHandshakeLog.error(
            "Security handshake violation (\(reason, privacy: .public)), bytes=\(byteCount, privacy: .public) — tearing down connection"
        )
        connection.cancel()
    }
}
