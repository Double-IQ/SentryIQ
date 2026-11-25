import XCTest
@testable import SentryIQMaster

final class ProtectedTrustStatePolicyTests: XCTestCase {
    func testAcceptsFreshAnchorWithinOneDayWindow() {
        XCTAssertTrue(TrustRegistryAnchorPolicy.isFresh(issuedAt: 1_700_000_000, expiresAt: 1_700_086_400, now: 1_700_000_100))
    }

    func testRejectsExpiredStaleAndOverlongAnchors() {
        XCTAssertFalse(TrustRegistryAnchorPolicy.isFresh(issuedAt: 1_700_000_000, expiresAt: 1_700_000_100, now: 1_700_000_100))
        XCTAssertFalse(TrustRegistryAnchorPolicy.isFresh(issuedAt: 1_700_000_000, expiresAt: 1_700_086_401, now: 1_700_086_401))
        XCTAssertFalse(TrustRegistryAnchorPolicy.isFresh(issuedAt: 1_700_000_000, expiresAt: 1_700_086_401, now: 1_700_000_000))
    }

    func testAllowsOnlySixtySecondsOfFutureClockSkew() {
        XCTAssertTrue(TrustRegistryAnchorPolicy.isFresh(issuedAt: 1_700_000_060, expiresAt: 1_700_000_300, now: 1_700_000_000))
        XCTAssertFalse(TrustRegistryAnchorPolicy.isFresh(issuedAt: 1_700_000_061, expiresAt: 1_700_000_300, now: 1_700_000_000))
    }
}
