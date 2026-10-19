import Foundation
import Security
import Testing
@testable import ContinuoSecurityTransport

/// The self-signed certificate is rebuilt at every launch with a 20-year
/// validity, so from 2030 on its notAfter falls in 2050 or later. UTCTime has a
/// two-digit year and RFC 5280 §4.1.2.5 reads "50"–"99" as 1950–1999: written as
/// UTCTime, that certificate claimed to have expired 80 years before it was made.
/// Pin verification ignores expiry today, which is the only reason it worked.
@Suite struct CertificateValidityTests {
    private func randomKey() throws -> SecKey {
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrKeySizeInBits as String: 256]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else { throw TrustStoreError.signingFailed }
        return key
    }

    private func utc(_ y: Int, _ m: Int, _ d: Int) -> Date {
        var c = DateComponents(); c.year = y; c.month = m; c.day = d; c.hour = 12
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        return cal.date(from: c)!
    }

    private func validity(of identity: SecIdentity) throws -> (notBefore: Date, notAfter: Date) {
        var cert: SecCertificate?
        #expect(SecIdentityCopyCertificate(identity, &cert) == errSecSuccess)
        let keys = [kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray
        let certificate = try #require(cert)
        let values = try #require(SecCertificateCopyValues(certificate, keys, nil) as? [String: Any])
        func date(_ oid: CFString) throws -> Date {
            let entry = try #require(values[oid as String] as? [String: Any])
            let n = try #require(entry[kSecPropertyKeyValue as String] as? NSNumber)
            return Date(timeIntervalSinceReferenceDate: n.doubleValue)
        }
        return (try date(kSecOIDX509V1ValidityNotBefore), try date(kSecOIDX509V1ValidityNotAfter))
    }

    @Test(arguments: [2026, 2029, 2030, 2031, 2049, 2055])
    func notAfterIsTwentyYearsLaterWhateverTheYear(year: Int) throws {
        let now = utc(year, 3, 4)
        let built = try IdentityFactory.makeSelfSigned(label: "v", privateKey: try randomKey(), now: now)
        let window = try validity(of: built.identity)
        #expect(abs(window.notBefore.timeIntervalSince(now)) < 1)
        #expect(abs(window.notAfter.timeIntervalSince(utc(year + 20, 3, 4))) < 1)
    }

    @Test func eitherEncodingStillPresentsTheSameFingerprint() throws {
        let key = try randomKey()
        let before = try IdentityFactory.makeSelfSigned(label: "v", privateKey: key, now: utc(2026, 1, 1))
        let after = try IdentityFactory.makeSelfSigned(label: "v", privateKey: key, now: utc(2031, 1, 1))
        #expect(TLSFingerprint.ofSPKI(before.spkiDER) == TLSFingerprint.ofSPKI(after.spkiDER))
    }
}
