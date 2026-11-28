import XCTest
@testable import SentryIQMaster

final class BootstrapLifecycleTests: XCTestCase {
    func testDerivesUninitialisedAndMasterCreatedStates() {
        XCTAssertEqual(
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .absent, protectedTrust: .absent, identityContinuity: .neverInitialized)),
            .uninitialised
        )
        XCTAssertEqual(
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .complete, protectedTrust: .absent, identityContinuity: .previouslyInitialized)),
            .masterCreatedPendingRoots
        )
    }

    func testRestoredOrUnknownIdentityNeverFallsBackToFirstRun() {
        XCTAssertEqual(BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .absent, protectedTrust: .absent, identityContinuity: .previouslyInitialized)), .recoveryRequired)
        XCTAssertEqual(BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .absent, protectedTrust: .absent)), .recoveryRequired)
    }

    func testAcceptedReceiptLeavesVerifierPendingUntilIndependentQualification() {
        let evidence = BootstrapLifecycleEvidence(masterKeyset: .complete, protectedTrust: .valid, hasAcceptedBootstrapReceipt: true)
        XCTAssertEqual(BootstrapLifecycle.evaluate(evidence), .rootsPendingVerifier)
        XCTAssertFalse(BootstrapLifecycle.allowsVerifierGatedOperation(.rootsPendingVerifier))
        let qualified = BootstrapLifecycleEvidence(
            masterKeyset: .complete,
            protectedTrust: .valid,
            hasAcceptedBootstrapReceipt: true,
            verifierQualification: .qualified
        )
        XCTAssertEqual(BootstrapLifecycle.evaluate(qualified), .trusted)
        XCTAssertTrue(BootstrapLifecycle.allowsVerifierGatedOperation(.trusted))
    }

    func testCorruptOrMissingIdentityAndReceiptMismatchRequireRecovery() {
        XCTAssertEqual(
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .incomplete, protectedTrust: .absent)),
            .recoveryRequired
        )
        XCTAssertEqual(
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .absent, protectedTrust: .valid, hasAcceptedBootstrapReceipt: true)),
            .recoveryRequired
        )
        XCTAssertEqual(
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .complete, protectedTrust: .corrupt, hasAcceptedBootstrapReceipt: true)),
            .recoveryRequired
        )
        XCTAssertEqual(
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(masterKeyset: .complete, protectedTrust: .valid)),
            .recoveryRequired
        )
    }

    func testReceiptWithoutProtectedTrustRequiresRecovery() {
        let evidence = BootstrapLifecycleEvidence(
            masterKeyset: .complete,
            protectedTrust: .absent,
            hasAcceptedBootstrapReceipt: true
        )
        XCTAssertEqual(BootstrapLifecycle.evaluate(evidence), .recoveryRequired)
    }

    func testRevokedOrExpiredVerifierSuspendsTrustedState() {
        let evidence = BootstrapLifecycleEvidence(
            masterKeyset: .complete,
            protectedTrust: .valid,
            hasAcceptedBootstrapReceipt: true,
            verifierQualification: .revokedOrExpired
        )
        XCTAssertEqual(BootstrapLifecycle.evaluate(evidence), .suspended)
    }
}
