package co.bichet.sentryiq.master

/** Durable evidence used to reconstruct bootstrap state after process restart. */
enum class MasterKeysetStatus { ABSENT, COMPLETE, INCOMPLETE }
enum class ProtectedTrustStatus { ABSENT, VALID, CORRUPT }
enum class VerifierQualificationStatus { PENDING, QUALIFIED, REVOKED_OR_EXPIRED }

enum class BootstrapLifecycleState {
    UNINITIALISED,
    MASTER_CREATED_PENDING_ROOTS,
    ROOTS_PENDING_VERIFIER,
    TRUSTED,
    RECOVERY_REQUIRED,
    SUSPENDED
}

/**
 * Fail-closed first-run state reducer.
 *
 * Callers must derive these values from loadExisting() on the hardware key store,
 * authenticated ProtectedTrustStateStore reads, the persisted bootstrap receipt,
 * and independently verified Phase 4 verifier qualification evidence. Never
 * populate them from API response flags or UI state.
 */
data class BootstrapLifecycleEvidence(
    val masterKeyset: MasterKeysetStatus,
    val protectedTrust: ProtectedTrustStatus,
    val hasAcceptedBootstrapReceipt: Boolean = false,
    val verifierQualification: VerifierQualificationStatus = VerifierQualificationStatus.PENDING
)

object BootstrapLifecycle {
    fun evaluate(evidence: BootstrapLifecycleEvidence): BootstrapLifecycleState {
        if (evidence.protectedTrust == ProtectedTrustStatus.CORRUPT ||
            evidence.masterKeyset == MasterKeysetStatus.INCOMPLETE ||
            (evidence.masterKeyset == MasterKeysetStatus.ABSENT &&
                evidence.protectedTrust == ProtectedTrustStatus.VALID)) {
            return BootstrapLifecycleState.RECOVERY_REQUIRED
        }

        if (evidence.protectedTrust == ProtectedTrustStatus.VALID &&
            evidence.masterKeyset == MasterKeysetStatus.COMPLETE &&
            !evidence.hasAcceptedBootstrapReceipt) {
            return BootstrapLifecycleState.RECOVERY_REQUIRED
        }

        if (evidence.protectedTrust == ProtectedTrustStatus.VALID &&
            evidence.verifierQualification == VerifierQualificationStatus.REVOKED_OR_EXPIRED) {
            return BootstrapLifecycleState.SUSPENDED
        }

        return when {
            evidence.masterKeyset == MasterKeysetStatus.ABSENT &&
                evidence.protectedTrust == ProtectedTrustStatus.ABSENT ->
                BootstrapLifecycleState.UNINITIALISED
            evidence.masterKeyset == MasterKeysetStatus.COMPLETE &&
                evidence.protectedTrust == ProtectedTrustStatus.ABSENT ->
                BootstrapLifecycleState.MASTER_CREATED_PENDING_ROOTS
            evidence.masterKeyset == MasterKeysetStatus.COMPLETE &&
                evidence.protectedTrust == ProtectedTrustStatus.VALID &&
                evidence.hasAcceptedBootstrapReceipt &&
                evidence.verifierQualification == VerifierQualificationStatus.QUALIFIED ->
                BootstrapLifecycleState.TRUSTED
            evidence.masterKeyset == MasterKeysetStatus.COMPLETE &&
                evidence.protectedTrust == ProtectedTrustStatus.VALID &&
                evidence.hasAcceptedBootstrapReceipt ->
                BootstrapLifecycleState.ROOTS_PENDING_VERIFIER
            else -> BootstrapLifecycleState.RECOVERY_REQUIRED
        }
    }

    /** Verifier-dependent operations are forbidden until independent qualification is trusted. */
    fun allowsVerifierGatedOperation(state: BootstrapLifecycleState): Boolean =
        state == BootstrapLifecycleState.TRUSTED
}
