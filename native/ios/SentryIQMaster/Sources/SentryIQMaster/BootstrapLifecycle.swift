import Foundation

public enum MasterKeysetStatus {
    case absent
    case complete
    case incomplete
}

public enum ProtectedTrustStatus {
    case absent
    case valid
    case corrupt
}

public enum VerifierQualificationStatus {
    case pending
    case qualified
    case revokedOrExpired
}

public enum BootstrapLifecycleState: Equatable {
    case uninitialised
    case masterCreatedPendingRoots
    case rootsPendingVerifier
    case trusted
    case recoveryRequired
    case suspended
}

/**
 Durable evidence used to reconstruct bootstrap state after process restart.
 Callers must source it from loadExisting() on the hardware key store,
 authenticated ProtectedTrustStateStore reads, the persisted bootstrap receipt,
 and independently verified Phase 4 qualification evidence. Never populate it
 from API response flags or UI state.
 */
public struct BootstrapLifecycleEvidence {
    public let masterKeyset: MasterKeysetStatus
    public let protectedTrust: ProtectedTrustStatus
    public let hasAcceptedBootstrapReceipt: Bool
    public let verifierQualification: VerifierQualificationStatus

    public init(
        masterKeyset: MasterKeysetStatus,
        protectedTrust: ProtectedTrustStatus,
        hasAcceptedBootstrapReceipt: Bool = false,
        verifierQualification: VerifierQualificationStatus = .pending
    ) {
        self.masterKeyset = masterKeyset
        self.protectedTrust = protectedTrust
        self.hasAcceptedBootstrapReceipt = hasAcceptedBootstrapReceipt
        self.verifierQualification = verifierQualification
    }
}

/** Fail-closed first-run state reducer shared semantically with the Android adapter. */
public enum BootstrapLifecycle {
    public static func evaluate(_ evidence: BootstrapLifecycleEvidence) -> BootstrapLifecycleState {
        if evidence.protectedTrust == .corrupt ||
            evidence.masterKeyset == .incomplete ||
            (evidence.masterKeyset == .absent && evidence.protectedTrust == .valid) {
            return .recoveryRequired
        }

        if evidence.protectedTrust == .valid &&
            evidence.masterKeyset == .complete &&
            !evidence.hasAcceptedBootstrapReceipt {
            return .recoveryRequired
        }

        if evidence.protectedTrust == .valid &&
            evidence.verifierQualification == .revokedOrExpired {
            return .suspended
        }

        if evidence.masterKeyset == .absent && evidence.protectedTrust == .absent {
            return .uninitialised
        }
        if evidence.masterKeyset == .complete && evidence.protectedTrust == .absent {
            return .masterCreatedPendingRoots
        }
        if evidence.masterKeyset == .complete &&
            evidence.protectedTrust == .valid &&
            evidence.hasAcceptedBootstrapReceipt &&
            evidence.verifierQualification == .qualified {
            return .trusted
        }
        if evidence.masterKeyset == .complete &&
            evidence.protectedTrust == .valid &&
            evidence.hasAcceptedBootstrapReceipt {
            return .rootsPendingVerifier
        }
        return .recoveryRequired
    }

    /// Verifier-dependent operations remain denied until independent qualification is trusted.
    public static func allowsVerifierGatedOperation(_ state: BootstrapLifecycleState) -> Bool {
        state == .trusted
    }
}
