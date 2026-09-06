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

    // MARK: The advertised address (`a`/`p`)

    // mDNS is multicast and link-local: it cannot cross a router. Two Macs on
    // different subnets of one home network therefore never resolve each other's
    // `.local` name however long they wait — 2026-08-21 measured 192.168.102.29 and
    // 192.168.1.5 one hop apart, ping 2/2, with every infra lookup empty. An
    // ADDRESS carried in the TXT is reachable where a NAME is not, and the record
    // itself still arrives (over AWDL) because discovery permits peer-to-peer.

    @Test func theRecordCarriesTheAddressAndPortWhenBothAreKnown() {
        let txt = DiscoveryTXT.make(machineID: "m-1", protocolVersion: 3,
                                    infraHost: "192.168.1.5", infraPort: 59_590)
        #expect(DiscoveryTXT.infraHost(txt) == "192.168.1.5")
        #expect(DiscoveryTXT.infraPort(txt) == 59_590)
    }

    /// Both halves or neither. A host with no port cannot be dialed, and a port with
    /// no host addresses nothing — publishing either alone would put a value in the
    /// record that no reader can act on.
    @Test func aHalfKnownEndpointIsNotAdvertisedAtAll() {
        let noPort = DiscoveryTXT.make(machineID: "m-1", protocolVersion: 3,
                                       infraHost: "192.168.1.5", infraPort: 0)
        #expect(noPort["a"] == nil)
        #expect(noPort["p"] == nil)

        let noHost = DiscoveryTXT.make(machineID: "m-1", protocolVersion: 3,
                                       infraHost: "", infraPort: 59_590)
        #expect(noHost["a"] == nil)
        #expect(noHost["p"] == nil)

        let blankHost = DiscoveryTXT.make(machineID: "m-1", protocolVersion: 3,
                                          infraHost: "   ", infraPort: 59_590)
        #expect(blankHost["a"] == nil, "whitespace is not an address")
    }

    /// A build that advertises no address must read back as exactly that, not as an
    /// empty string a caller might try to dial.
    @Test func anOlderRecordWithoutAnAddressReadsAsAbsent() {
        let txt = DiscoveryTXT.make(machineID: "m-1", protocolVersion: 3)
        #expect(DiscoveryTXT.infraHost(txt) == nil)
        #expect(DiscoveryTXT.infraPort(txt) == nil)
    }

    /// Same canonical-decimal discipline as `protocolVersion`: a port is either an
    /// exact decimal we can round-trip or it is absent. Anything else would dial a
    /// silently truncated or padded number.
    @Test func aPortThatIsNotCanonicalDecimalFailsClosed() {
        for raw in ["0", "059590", "-1", "65536", "59 590", "59590 ", "0x1", "", "abc"] {
            #expect(DiscoveryTXT.infraPort(["p": raw]) == nil,
                    "\(raw) must not be read as a port")
        }
        #expect(DiscoveryTXT.infraPort(["p": "65535"]) == 65_535, "the real upper bound still works")
    }

    /// The reader deliberately does NOT validate the host — that belongs to the dial
    /// site, which is the code that would suffer a bad answer by turning a hostile
    /// string into a DNS lookup. This asserts the boundary stays where it is, so a
    /// future caller cannot assume validation happened here.
    @Test func theReaderReturnsTheHostVerbatimAndLeavesValidationToTheDialSite() {
        #expect(DiscoveryTXT.infraHost(["a": "evil.example"]) == "evil.example")
    }
}
