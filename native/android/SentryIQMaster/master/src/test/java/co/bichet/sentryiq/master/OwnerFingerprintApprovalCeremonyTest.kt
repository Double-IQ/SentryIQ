package co.bichet.sentryiq.master

import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class OwnerFingerprintApprovalCeremonyTest {
    private val bundle = "canonical-trust-bundle".toByteArray()
    private val root = "independent-release-root".toByteArray()
    private val keyset = "device-keyset-public-identifiers".toByteArray()
    private val challenge = ByteArray(32) { 0x5a }
    private val expiry = 1_700_000_200L
    private val now = 1_700_000_000L
    private fun fp(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun approve(bundleFP: String = fp(bundle), rootFP: String = fp(root), owner: String = "owner-123",
        role: String = "release-authorisation", purpose: String = "bootstrap-release-root",
        expires: Long = expiry, verify: (ByteArray, String, String, ByteArray, ByteArray, String) -> Boolean = { _, _, _, _, _, _ -> true },
        fresh: () -> Unit = {}, sign: (ByteArray) -> ByteArray = { byteArrayOf(0x30, 1) }
    ) = OwnerFingerprintApprovalCeremony.approve(bundle, bundleFP, owner, role, "release-root-1",
        fp(root), fp(keyset), purpose, challenge, expires, { fp(bundle) }, { rootFP }, verify, fresh, sign, now)

    @Test fun proofBindsAllApprovalContext() {
        var transcript = ByteArray(0); var fresh = false
        val proof = approve(fresh = { fresh = true }, sign = { transcript = it; byteArrayOf(0x30, 1) })
        assertTrue(fresh); assertEquals(fp(bundle), proof.bundleFingerprint)
        assertEquals("release-authorisation", proof.rootRole); assertEquals("release-root-1", proof.rootKeyId)
        assertEquals(fp(root), proof.rootFingerprint); assertEquals(fp(keyset), proof.deviceKeysetDigest)
        assertEquals("bootstrap-release-root", proof.purpose); assertArrayEquals(challenge, proof.challenge)
        assertEquals(expiry, proof.expiresAt)

        val expected = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(expected).use { out ->
            out.write("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n".toByteArray(Charsets.US_ASCII))
            fun field(s: String) { val b = s.toByteArray(); out.writeInt(b.size); out.write(b) }
            field("owner-123"); out.write(MessageDigest.getInstance("SHA-256").digest(bundle))
            field("release-authorisation"); field("release-root-1")
            out.write(MessageDigest.getInstance("SHA-256").digest(root))
            out.write(MessageDigest.getInstance("SHA-256").digest(keyset))
            field("bootstrap-release-root"); out.writeInt(32); out.write(challenge); out.writeLong(expiry)
        }
        assertArrayEquals(expected.toByteArray(), transcript)
        val sharedGoldenHex = "53454e54525949512d4f574e45522d424f4f5453545241502d415050524f56414c2d56320a000000096f776e65722d31323387ffacd652854aba4246164ce5154c94d6d06b145eade6b33e93b1e53f74328d0000001572656c656173652d617574686f7269736174696f6e0000000e72656c656173652d726f6f742d31739cc47de826dd91653d08e80ac816b26e3b0b38cf782e506dadd4828a3050bc63053de68b07ab2d29fa13eee284d9ae272d1d228afc19c48cdb8486ab61e7d800000016626f6f7473747261702d72656c656173652d726f6f74000000205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000000006553f1c8"
        val actualHex = transcript.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertEquals(sharedGoldenHex, actualHex)
    }

    @Test fun preparedApprovalCompletesOnlyAfterAuthenticationAndSignsExactTranscript() {
        val prepared = OwnerFingerprintApprovalCeremony.prepare(
            bundle, fp(bundle), "owner-123", "release-authorisation", "release-root-1",
            fp(root), fp(keyset), "bootstrap-release-root", challenge, expiry,
            { fp(bundle) }, { fp(root) }, { _, _, _, _, _, _ -> true }, now
        )
        var authenticated = false
        var signedTranscript = ByteArray(0)
        val proof = OwnerFingerprintApprovalCeremony.complete(
            prepared,
            requireFreshUserVerification = { authenticated = true },
            sign = { signedTranscript = it; byteArrayOf(0x01) },
            now = now
        )
        assertTrue(authenticated)
        assertArrayEquals(prepared.transcript, signedTranscript)
        assertEquals(fp(bundle), proof.bundleFingerprint)
        assertEquals(fp(root), proof.rootFingerprint)
    }

    @Test fun wrongRootFingerprintFailsBeforeAuthenticationOrSigning() {
        var fresh = false; var signed = false
        try { approve(rootFP = "0".repeat(64), fresh = { fresh = true }, sign = { signed = true; byteArrayOf(1) }); fail("Mismatch") }
        catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { }
        assertFalse(fresh); assertFalse(signed)
    }
    @Test fun wrongBundleFingerprintFailsClosed() {
        try { approve(bundleFP = "0".repeat(64)); fail("Mismatch") } catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { }
    }
    @Test fun wrongOwnerAndMalformedContextFailClosed() {
        val calls = listOf<() -> Unit>({ approve(owner = "") }, { approve(owner = "owner-é") }, { approve(role = "release authorisation") }, { approve(purpose = "") })
        calls.forEach { try { it(); fail("Invalid context") } catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { } }
    }
    @Test fun expiredChallengeAndInvalidCandidateFailBeforeSigning() {
        var signed = false
        try { approve(expires = now); fail("Expired") } catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { }
        try { approve(verify = { _, _, _, _, _, _ -> false }, sign = { signed = true; byteArrayOf(1) }); fail("Invalid TUF") }
        catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { }
        assertFalse(signed)
    }
    @Test fun freshUserVerificationMustSucceedBeforeSigning() {
        var signed = false
        try { approve(fresh = { throw IllegalStateException("biometric required") }, sign = { signed = true; byteArrayOf(1) }); fail("Fresh auth") }
        catch (_: IllegalStateException) { }
        assertFalse(signed)
    }
}
