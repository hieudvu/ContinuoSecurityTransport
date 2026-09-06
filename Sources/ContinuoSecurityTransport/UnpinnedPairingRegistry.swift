import Foundation
import os

/// Bounds the lifetime and inbound concurrency of TLS-authenticated peers that
/// have not completed Continuo's user-confirmed pinning flow.
public final class UnpinnedPairingRegistry: @unchecked Sendable {
    public static let defaultMaxConcurrentInbound = 4
    public static let defaultLifetimeNanos: UInt64 = 180_000_000_000

    private enum Direction: Sendable, Equatable {
        case inbound
        case outbound
    }

    private struct Record: Sendable {
        let direction: Direction
        let startedAtNanos: UInt64
    }

    private struct State: Sendable {
        var records: [UUID: Record] = [:]
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    private let maxConcurrentInbound: Int
    private let lifetimeNanos: UInt64

    public init(
        maxConcurrentInbound: Int = defaultMaxConcurrentInbound,
        lifetimeNanos: UInt64 = defaultLifetimeNanos
    ) {
        precondition(maxConcurrentInbound > 0)
        precondition(lifetimeNanos > 0)
        self.maxConcurrentInbound = maxConcurrentInbound
        self.lifetimeNanos = lifetimeNanos
    }

    public func beginInbound(nowNanos: UInt64) -> UnpinnedPairingAttempt? {
        let id = state.withLock { state -> UUID? in
            // Pre-sweep abandoned attempts past their lifetime BEFORE the capacity
            // check. A mis-classified inbound token for an already-pinned peer is
            // never confirmed or retired (its phase leaves the pull-based expiry
            // path), so without this sweep four such attempts would permanently
            // consume every inbound slot and block ALL future pairing.
            state.records = state.records.filter { record in
                // Guard the monotonic-clock subtraction against underflow: a record
                // whose start reads "after" this caller's clock sample is not expired.
                guard nowNanos >= record.value.startedAtNanos else { return true }
                return nowNanos - record.value.startedAtNanos < lifetimeNanos
            }
            let inboundCount = state.records.values.lazy
                .filter { $0.direction == .inbound }
                .count
            guard inboundCount < maxConcurrentInbound else { return nil }

            let id = UUID()
            state.records[id] = Record(direction: .inbound, startedAtNanos: nowNanos)
            return id
        }
        return id.map { UnpinnedPairingAttempt(id: $0, registry: self) }
    }

    public func beginOutbound(nowNanos: UInt64) -> UnpinnedPairingAttempt {
        let id = state.withLock { state -> UUID in
            let id = UUID()
            state.records[id] = Record(direction: .outbound, startedAtNanos: nowNanos)
            return id
        }
        return UnpinnedPairingAttempt(id: id, registry: self)
    }

    fileprivate func expire(id: UUID, nowNanos: UInt64) -> Bool {
        state.withLock { state in
            // `nowNanos >= startedAtNanos` first, matching the sweep above. On its
            // own the `&-` wraps to a colossal value whenever the clock sample
            // precedes the record, which expires a FRESH attempt rather than a
            // stale one — the opposite of what this function is for.
            guard let record = state.records[id],
                  nowNanos >= record.startedAtNanos,
                  nowNanos &- record.startedAtNanos >= lifetimeNanos
            else {
                return false
            }
            state.records[id] = nil
            return true
        }
    }

    fileprivate func finish(id: UUID) {
        state.withLock { $0.records[id] = nil }
    }
}

public final class UnpinnedPairingAttempt: @unchecked Sendable {
    private let id: UUID
    private let registry: UnpinnedPairingRegistry

    fileprivate init(id: UUID, registry: UnpinnedPairingRegistry) {
        self.id = id
        self.registry = registry
    }

    public func expireIfNeeded(nowNanos: UInt64) -> Bool {
        registry.expire(id: id, nowNanos: nowNanos)
    }

    public func finish() {
        registry.finish(id: id)
    }

    deinit {
        finish()
    }
}
