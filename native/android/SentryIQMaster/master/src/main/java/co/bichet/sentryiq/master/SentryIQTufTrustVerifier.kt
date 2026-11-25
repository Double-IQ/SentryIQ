package co.bichet.sentryiq.master

import co.bichet.sentryiq.tuf.verifyTufMetadataRefresh

/** Thin native facade over the shared Rust TUF verifier. */
object SentryIQTufTrustVerifier {
    fun verifyMetadataRefresh(
        initialRoot: ByteArray,
        expectedInitialRootSha256: ByteArray,
        candidateRoots: List<ByteArray>,
        cachedTimestamp: ByteArray?,
        cachedSnapshot: ByteArray?,
        cachedTargets: ByteArray?,
        newTimestamp: ByteArray,
        newSnapshot: ByteArray,
        newTargets: ByteArray,
        referenceTimeUnixSeconds: Long
    ): Boolean = verifyTufMetadataRefresh(
        initialRoot,
        expectedInitialRootSha256,
        candidateRoots,
        cachedTimestamp,
        cachedSnapshot,
        cachedTargets,
        newTimestamp,
        newSnapshot,
        newTargets,
        referenceTimeUnixSeconds
    )
}
