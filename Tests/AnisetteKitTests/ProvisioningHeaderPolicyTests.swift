import XCTest
@testable import AnisetteKit

final class ProvisioningHeaderPolicyTests: XCTestCase {
    func testStandardHeadersRemainExactlyUnchanged() {
        let headers = fixture
        XCTAssertEqual(AnisetteProvisioningHeaderPolicy.standard.apply(to: headers), headers)
    }

    func testWindowsHeadersMatchPR1835WithoutRoutingOrSerial() {
        var expected = fixture
        expected.removeValue(forKey: "X-Apple-I-MD-RINFO")
        expected.removeValue(forKey: "X-Apple-I-SRL-NO")
        let actual = AnisetteProvisioningHeaderPolicy.windowsV3.apply(to: fixture)
        XCTAssertEqual(actual, expected)
        XCTAssertEqual(Set(actual.keys), Set(["User-Agent", "Content-Type", "Accept", "X-Mme-Client-Info",
            "X-Apple-I-MD-LU", "X-Mme-Device-Id", "X-Apple-Locale", "X-Apple-I-TimeZone", "X-Apple-I-Client-Time"]))
    }

    private var fixture: [String: String] {
        ["User-Agent": "fake-agent", "Content-Type": "text/x-xml-plist", "Accept": "*/*",
         "X-Mme-Client-Info": "<Windows;fake>", "X-Apple-I-MD-LU": "fake-lu",
         "X-Mme-Device-Id": "00010203-0405-0607-0809-0A0B0C0D0E0F", "X-Apple-Locale": "en_US",
         "X-Apple-I-TimeZone": "UTC", "X-Apple-I-Client-Time": "2026-01-01T00:00:00Z",
         "X-Apple-I-MD-RINFO": "17106176", "X-Apple-I-SRL-NO": "fake-serial"]
    }
}
