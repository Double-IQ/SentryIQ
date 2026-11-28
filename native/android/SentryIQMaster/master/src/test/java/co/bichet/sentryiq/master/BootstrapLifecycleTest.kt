package co.bichet.sentryiq.master

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootstrapLifecycleTest {
    @Test fun derivesUninitialisedAndMasterCreatedStates() {
        assertEquals(
            BootstrapLifecycleState.UNINITIALISED,
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(MasterKeysetStatus.ABSENT, ProtectedTrustStatus.ABSENT))
        )
        assertEquals(
            BootstrapLifecycleState.MASTER_CREATED_PENDING_ROOTS,
            BootstrapLifecycle.evaluate(BootstrapLifecycleEvidence(MasterKeysetStatus.COMPLETE, ProtectedTrustStatus.ABSENT))
        )
    }

    @Test fun acceptedReceiptLeavesVerifierPendingUntilIndependentQualification() {
        val evidence = BootstrapLifecycleEvidence(
            MasterKeysetStatus.COMPLETE, ProtectedTrustStatus.VALID, true
        )
        assertEquals(BootstrapLifecycleState.ROOTS_PENDING_VERIFIER, BootstrapLifecycle.evaluate(evidence))
        assertFalse(BootstrapLifecycle.allowsVerifierGatedOperation(BootstrapLifecycle.evaluate(evidence)))
        assertEquals(
            BootstrapLifecycleState.TRUSTED,
            BootstrapLifecycle.evaluate(evidence.copy(verifierQualification = VerifierQualificationStatus.QUALIFIED))
        )
        assertTrue(BootstrapLifecycle.allowsVerifierGatedOperation(
            BootstrapLifecycle.evaluate(evidence.copy(verifierQualification = VerifierQualificationStatus.QUALIFIED))
        ))
    }

    @Test fun corruptOrMissingIdentityAndReceiptMismatchRequireRecovery() {
        assertEquals(BootstrapLifecycleState.RECOVERY_REQUIRED, BootstrapLifecycle.evaluate(
            BootstrapLifecycleEvidence(MasterKeysetStatus.INCOMPLETE, ProtectedTrustStatus.ABSENT)
        ))
        assertEquals(BootstrapLifecycleState.RECOVERY_REQUIRED, BootstrapLifecycle.evaluate(
            BootstrapLifecycleEvidence(MasterKeysetStatus.ABSENT, ProtectedTrustStatus.VALID, true)
        ))
        assertEquals(BootstrapLifecycleState.RECOVERY_REQUIRED, BootstrapLifecycle.evaluate(
            BootstrapLifecycleEvidence(MasterKeysetStatus.COMPLETE, ProtectedTrustStatus.CORRUPT, true)
        ))
        assertEquals(BootstrapLifecycleState.RECOVERY_REQUIRED, BootstrapLifecycle.evaluate(
            BootstrapLifecycleEvidence(MasterKeysetStatus.COMPLETE, ProtectedTrustStatus.VALID, false)
        ))
    }

    @Test fun receiptWithoutProtectedTrustRequiresRecovery() {
        assertEquals(BootstrapLifecycleState.RECOVERY_REQUIRED, BootstrapLifecycle.evaluate(
            BootstrapLifecycleEvidence(MasterKeysetStatus.COMPLETE, ProtectedTrustStatus.ABSENT, true)
        ))
    }

    @Test fun revokedOrExpiredVerifierSuspendsTrustedState() {
        assertEquals(BootstrapLifecycleState.SUSPENDED, BootstrapLifecycle.evaluate(
            BootstrapLifecycleEvidence(
                MasterKeysetStatus.COMPLETE,
                ProtectedTrustStatus.VALID,
                true,
                VerifierQualificationStatus.REVOKED_OR_EXPIRED
            )
        ))
    }
}
