import Foundation
import XCTest
@testable import SentryIQMaster

final class SentryIQTufTrustVerifierTests: XCTestCase {
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

    func testDelegatedTargetVerifierRejectsControlCharactersAndOversizedPathsThroughRustLibrary() {
        for path in ["releases/\u{0000}app.tar.zst", "releases/\napp.tar.zst", String(repeating: "a", count: 4097)] {
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
                targetPath: path,
                referenceTimeUnixSeconds: 1_700_000_000
            )
            XCTAssertFalse(accepted, "Unsafe target path must fail closed: \\(path.debugDescription)")
        }
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
