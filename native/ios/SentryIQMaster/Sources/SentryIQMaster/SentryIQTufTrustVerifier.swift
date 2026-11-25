import Foundation
import SentryIQTufCoreBindings

/// Thin native facade over the shared Rust TUF verifier.
/// The caller must supply the independently pinned root and current metadata.
public enum SentryIQTufTrustVerifier {
    public static func verifyMetadataRefresh(
        initialRoot: Data,
        expectedInitialRootSHA256: Data,
        candidateRoots: [Data],
        cachedTimestamp: Data?,
        cachedSnapshot: Data?,
        cachedTargets: Data?,
        newTimestamp: Data,
        newSnapshot: Data,
        newTargets: Data,
        referenceTimeUnixSeconds: Int64
    ) -> Bool {
        verifyTufMetadataRefresh(
            initialRoot: initialRoot,
            expectedInitialRootSha256: expectedInitialRootSHA256,
            candidateRoots: candidateRoots,
            cachedTimestamp: cachedTimestamp,
            cachedSnapshot: cachedSnapshot,
            cachedTargets: cachedTargets,
            newTimestamp: newTimestamp,
            newSnapshot: newSnapshot,
            newTargets: newTargets,
            referenceTimeUnixSeconds: referenceTimeUnixSeconds
        )
    }
}
