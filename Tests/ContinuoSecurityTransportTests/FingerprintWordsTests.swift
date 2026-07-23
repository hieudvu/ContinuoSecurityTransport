import Testing
@testable import ContinuoSecurityTransport

@Suite struct FingerprintWordsTests {
    @Test func rendersFiveWordsFromWordlist() {
        let fp = [UInt8](0..<32)
        let words = FingerprintWords.render(fp)
        #expect(words.count == 5)                       // 5 bytes, one 256-word symbol per byte
        for w in words { #expect(PairingSAS.wordlist.contains(w)) }
    }

    @Test func renderIsDeterministic() {
        let fp: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x99, 0x01, 0x7F] + [UInt8](repeating: 0, count: 24)
        #expect(FingerprintWords.render(fp) == FingerprintWords.render(fp))
    }

    @Test func roundTripsFirstFiveBytes() {
        let fp: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x9A] + [UInt8](repeating: 0xFF, count: 27)
        let recovered = FingerprintWords.decode(FingerprintWords.render(fp))
        #expect(recovered == [0x12, 0x34, 0x56, 0x78, 0x9A])
    }

    @Test func everyByteValueRoundTrips() {
        for b in UInt8.min...UInt8.max {
            let fp = [UInt8](repeating: b, count: 5)
            #expect(FingerprintWords.decode(FingerprintWords.render(fp)) == fp)
        }
    }

    @Test func zeroPrefixIsAllFirstWord() {
        let words = FingerprintWords.render([UInt8](repeating: 0, count: 32))
        #expect(words == Array(repeating: PairingSAS.wordlist[0], count: 5))
    }

    @Test func decodeRejectsBadInput() {
        #expect(FingerprintWords.decode([PairingSAS.wordlist[0]]) == nil)
        #expect(FingerprintWords.decode(Array(repeating: "notaword", count: 5)) == nil)
    }
}
