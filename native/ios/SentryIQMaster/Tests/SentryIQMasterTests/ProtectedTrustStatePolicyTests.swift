import XCTest
@testable import SentryIQMaster

final class ProtectedTrustStatePolicyTests: XCTestCase {
    func testInitialAnchorMustStartAtSequenceOneWithoutPreviousDigest() {
        XCTAssertTrue(TrustRegistryAnchorPolicy.isValidInitialAnchor(sequence: 1, previousBundleSHA256: nil))
        XCTAssertFalse(TrustRegistryAnchorPolicy.isValidInitialAnchor(sequence: 2, previousBundleSHA256: nil))
        XCTAssertFalse(TrustRegistryAnchorPolicy.isValidInitialAnchor(sequence: 1, previousBundleSHA256: Data(repeating: 0x11, count: 32)))
    }

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
