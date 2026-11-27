import CryptoKit
import Foundation
import XCTest
@testable import SentryIQMaster

final class SentryIQTufTrustVerifierTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures")
        )
        return try Data(contentsOf: url)
    }

    func testValidSignedMetadataRefreshCrossesRustLibraryBoundary() throws {
        let root = try fixture("root")
        let accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot: root,
            expectedInitialRootSHA256: Data(SHA256.hash(data: root)),
            candidateRoots: [],
            cachedTimestamp: nil,
            cachedSnapshot: nil,
            cachedTargets: nil,
            newTimestamp: try fixture("timestamp"),
            newSnapshot: try fixture("snapshot"),
            newTargets: try fixture("targets"),
            referenceTimeUnixSeconds: 1_800_000_000
        )
        XCTAssertTrue(accepted, "Valid signed TUF metadata must verify through Rust FFI")
    }

    func testTamperedSignedMetadataFailsThroughRustLibrary() throws {
        let root = try fixture("root")
        var timestamp = try fixture("timestamp")
        timestamp[0] ^= 1
        let accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot: root,
            expectedInitialRootSHA256: Data(SHA256.hash(data: root)),
            candidateRoots: [],
            cachedTimestamp: nil,
            cachedSnapshot: nil,
            cachedTargets: nil,
            newTimestamp: timestamp,
            newSnapshot: try fixture("snapshot"),
            newTargets: try fixture("targets"),
            referenceTimeUnixSeconds: 1_800_000_000
        )
        XCTAssertFalse(accepted, "Tampered signed metadata must fail closed through Rust FFI")
    }

    func testInvalidTopLevelMetadataFailsClosedThroughRustLibrary() {
        let accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot: Data(),
            expectedInitialRootSHA256: Data(repeating: 0, count: 32),
            candidateRoots: [],
            cachedTimestamp: nil,
            cachedSnapshot: nil,
            cachedTargets: nil,
            newTimestamp: Data(),
            newSnapshot: Data([1]),
            newTargets: Data([1]),
            referenceTimeUnixSeconds: 1_700_000_000
        )
        XCTAssertFalse(accepted)
    }

    func testDelegatedTargetVerifierRejectsInvalidInputThroughRustLibrary() {
        let accepted = SentryIQTufTrustVerifier.verifyTargetDelegation(
            initialRoot: Data(),
            expectedInitialRootSHA256: Data(repeating: 0, count: 32),
            candidateRoots: [],
            cachedTimestamp: nil,
            cachedSnapshot: nil,
            cachedTargets: nil,
            newTimestamp: Data([1]),
            newSnapshot: Data([1]),
            newTargets: Data([1]),
            delegatedRoles: [],
            delegatedMetadata: [],
            targetPath: "../escape",
            referenceTimeUnixSeconds: 1_700_000_000
        )
        XCTAssertFalse(accepted)
    }
}
