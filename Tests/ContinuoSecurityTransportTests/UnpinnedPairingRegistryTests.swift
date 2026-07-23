import Testing
@testable import ContinuoSecurityTransport

@Suite struct UnpinnedPairingRegistryTests {
    @Test func fifthConcurrentInboundAttemptIsRejected() {
        let registry = UnpinnedPairingRegistry()
        let held = (0 ..< 4).compactMap { registry.beginInbound(nowNanos: UInt64($0)) }

        #expect(held.count == 4)
        #expect(registry.beginInbound(nowNanos: 4) == nil)
    }

    @Test func concurrentInboundAdmissionNeverExceedsCapacity() async {
        let registry = UnpinnedPairingRegistry()
        let held = await withTaskGroup(of: UnpinnedPairingAttempt?.self) { group in
            for value in 0 ..< 32 {
                group.addTask { registry.beginInbound(nowNanos: UInt64(value)) }
            }

            var result: [UnpinnedPairingAttempt] = []
            for await attempt in group {
                if let attempt { result.append(attempt) }
            }
            return result
        }

        #expect(held.count == 4)
    }

    @Test func outboundAttemptDoesNotConsumeInboundCapacity() {
        let registry = UnpinnedPairingRegistry()
        let outbound = registry.beginOutbound(nowNanos: 0)
        let inbound = (0 ..< 4).compactMap { registry.beginInbound(nowNanos: UInt64($0)) }

        #expect(inbound.count == 4)
        #expect(registry.beginInbound(nowNanos: 5) == nil)
        outbound.finish()
    }

    @Test func attemptExpiresExactlyAtThreeMinutesOnce() {
        let registry = UnpinnedPairingRegistry()
        let attempt = registry.beginOutbound(nowNanos: 10)

        #expect(!attempt.expireIfNeeded(nowNanos: 180_000_000_009))
        #expect(attempt.expireIfNeeded(nowNanos: 180_000_000_010))
        #expect(!attempt.expireIfNeeded(nowNanos: 180_000_000_011))
    }

    // Ghost-token slot leak (2026-07-23): a mis-classified inbound token for an
    // already-pinned peer is never confirmed or retired, so without a sweep its
    // attempt permanently consumes an inbound slot — four of them would block ALL
    // future pairing ("inbound pairing capacity reached"). `beginInbound` must drop
    // records past their lifetime before the capacity check.
    @Test func staleAttemptsPastLifetimeAreSweptSoTheSlotIsReclaimed() {
        let registry = UnpinnedPairingRegistry()
        let held = (0 ..< 4).compactMap { _ in registry.beginInbound(nowNanos: 0) }
        #expect(held.count == 4)
        // Still within lifetime → genuinely full.
        #expect(registry.beginInbound(nowNanos: 179_000_000_000) == nil)
        // Past lifetime → the four abandoned attempts are swept and a fresh one admits.
        #expect(registry.beginInbound(nowNanos: 180_000_000_001) != nil,
                "an abandoned inbound attempt past its lifetime must not permanently consume a slot")
        _ = held
    }

    @Test func finishingTwiceReleasesOneInboundSlot() {
        let registry = UnpinnedPairingRegistry()
        let held = (0 ..< 4).compactMap { registry.beginInbound(nowNanos: UInt64($0)) }

        #expect(held.count == 4)
        held[0].finish()
        held[0].finish()
        #expect(registry.beginInbound(nowNanos: 5) != nil)
    }
}
