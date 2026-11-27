package co.bichet.sentryiq.master

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.MessageDigest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on Android so UniFFI/JNA must load the packaged Rust .so and cross
 * the Kotlin -> JNA -> Rust FFI boundary.
 */
@RunWith(AndroidJUnit4::class)
class SentryIQTufNativeIntegrationTest {
    private fun fixture(name: String): ByteArray =
        InstrumentationRegistry.getInstrumentation().context.assets
            .open("tufet-python-tuf/$name.json").use { it.readBytes() }

    @Test
    fun packagedRustVerifierAcceptsValidSignedMetadataRefresh() {
        val root = fixture("root")
        val rootPin = MessageDigest.getInstance("SHA-256").digest(root)
        val accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot = root,
            expectedInitialRootSha256 = rootPin,
            candidateRoots = emptyList(),
            cachedTimestamp = null,
            cachedSnapshot = null,
            cachedTargets = null,
            newTimestamp = fixture("timestamp"),
            newSnapshot = fixture("snapshot"),
            newTargets = fixture("targets"),
            referenceTimeUnixSeconds = 1_800_000_000L
        )
        assertTrue("Valid signed TUF metadata must verify through Rust FFI", accepted)
    }

    @Test
    fun packagedRustVerifierRejectsTamperedSignedMetadata() {
        val root = fixture("root")
        val timestamp = fixture("timestamp").also { it[0] = (it[0].toInt() xor 1).toByte() }
        val accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot = root,
            expectedInitialRootSha256 = MessageDigest.getInstance("SHA-256").digest(root),
            candidateRoots = emptyList(),
            cachedTimestamp = null,
            cachedSnapshot = null,
            cachedTargets = null,
            newTimestamp = timestamp,
            newSnapshot = fixture("snapshot"),
            newTargets = fixture("targets"),
            referenceTimeUnixSeconds = 1_800_000_000L
        )
        assertFalse("Tampered signed metadata must fail closed through Rust FFI", accepted)
    }

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
