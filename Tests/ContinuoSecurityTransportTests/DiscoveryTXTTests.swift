import Testing
@testable import ContinuoSecurityTransport

@Suite struct DiscoveryTXTTests {
    @Test func recordCarriesOnlyHashAndSuppliedVersion() {
        let machineID = "my-secret-machine-id"
        let txt = DiscoveryTXT.make(
            machineID: machineID,
            name: "",
            protocolVersion: 3
        )

        #expect(txt["v"] == "3")
        #expect(txt["h"] == DiscoveryTXT.serviceInstanceName(machineID: machineID))
        #expect(!txt.values.contains(machineID))
        #expect(DiscoveryTXT.machineIDHash(txt) == txt["h"])
    }

    @Test func optionalBroadcastNameIsTrimmedAndClearable() {
        let named = DiscoveryTXT.make(
            machineID: "id",
            name: "  Studio Mac  ",
            protocolVersion: 3
        )
        #expect(named["n"] == "Studio Mac")
        #expect(DiscoveryTXT.broadcastName(named) == "Studio Mac")

        let unnamed = DiscoveryTXT.make(
            machineID: "id",
            name: "   ",
            protocolVersion: 3
        )
        #expect(unnamed["n"] == nil)
        #expect(DiscoveryTXT.broadcastName(["n": "  "]) == nil)
    }

    @Test func serviceNameIsStableAndNotRawIdentity() {
        let machineID = "my-secret-machine-id"
        let first = DiscoveryTXT.serviceInstanceName(machineID: machineID)
        let second = DiscoveryTXT.serviceInstanceName(machineID: machineID)

        #expect(first == second)
        #expect(first != machineID)
        #expect(first.count == 16)
    }

    @Test func protocolVersionParsingIsStrictAndBounded() {
        #expect(DiscoveryTXT.protocolVersion(["v": "3"]) == 3)
        #expect(DiscoveryTXT.protocolVersion([:]) == nil)
        #expect(DiscoveryTXT.protocolVersion(["v": "0"]) == nil)
        #expect(DiscoveryTXT.protocolVersion(["v": "03"]) == nil)
        #expect(DiscoveryTXT.protocolVersion(["v": "-1"]) == nil)
        #expect(DiscoveryTXT.protocolVersion(["v": "65536"]) == nil)
        #expect(DiscoveryTXT.protocolVersion(["v": "three"]) == nil)
    }
}
