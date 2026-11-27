package co.bichet.sentryiq.master

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on an Android runtime so UniFFI/JNA must load the packaged Rust .so
 * from jniLibs and cross the Kotlin -> JNA -> Rust FFI boundary.
 */
@RunWith(AndroidJUnit4::class)
class SentryIQTufNativeIntegrationTest {
    @Test
    fun packagedRustVerifierLoadsAndRejectsInvalidBootstrap() {
        val accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot = byteArrayOf(),
            expectedInitialRootSha256 = ByteArray(32),
            candidateRoots = emptyList(),
            cachedTimestamp = null,
            cachedSnapshot = null,
            cachedTargets = null,
            newTimestamp = byteArrayOf(),
            newSnapshot = byteArrayOf(1),
            newTargets = byteArrayOf(1),
            referenceTimeUnixSeconds = 1_700_000_000L
        )
        assertFalse("Invalid TUF bootstrap must fail closed", accepted)
    }
    @Test
    fun packagedRustDelegationVerifierRejectsControlCharactersAndOversizedPaths() {
        val unsafePaths = listOf(
            "releases/\u0000app.tar.zst",
            "releases/\napp.tar.zst",
            "a".repeat(4097)
        )
        unsafePaths.forEach { path ->
            val accepted = SentryIQTufTrustVerifier.verifyTargetDelegation(
                initialRoot = byteArrayOf(),
                expectedInitialRootSha256 = ByteArray(32),
                candidateRoots = emptyList(),
                cachedTimestamp = null,
                cachedSnapshot = null,
                cachedTargets = null,
                newTimestamp = byteArrayOf(1),
                newSnapshot = byteArrayOf(1),
                newTargets = byteArrayOf(1),
                delegatedRoles = emptyList(),
                delegatedMetadata = emptyList(),
                targetPath = path,
                referenceTimeUnixSeconds = 1_700_000_000L
            )
            assertFalse("Unsafe target path must fail closed: $path", accepted)
        }
    }

    @Test
    fun packagedRustDelegationVerifierLoadsAndRejectsUnsafeTargetPath() {
        val accepted = SentryIQTufTrustVerifier.verifyTargetDelegation(
            initialRoot = byteArrayOf(),
            expectedInitialRootSha256 = ByteArray(32),
            candidateRoots = emptyList(),
            cachedTimestamp = null,
            cachedSnapshot = null,
            cachedTargets = null,
            newTimestamp = byteArrayOf(1),
            newSnapshot = byteArrayOf(1),
            newTargets = byteArrayOf(1),
            delegatedRoles = emptyList(),
            delegatedMetadata = emptyList(),
            targetPath = "../escape",
            referenceTimeUnixSeconds = 1_700_000_000L
        )
        assertFalse("Unsafe delegated target path must fail closed", accepted)
    }
}
