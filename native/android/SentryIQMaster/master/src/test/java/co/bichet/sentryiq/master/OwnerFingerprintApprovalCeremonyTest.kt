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
        val calls = listOf<() -> Unit>({ approve(owner = "") }, { approve(role = "release authorisation") }, { approve(purpose = "") })
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
