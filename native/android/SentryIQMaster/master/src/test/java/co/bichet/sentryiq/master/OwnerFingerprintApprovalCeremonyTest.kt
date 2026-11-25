package co.bichet.sentryiq.master

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class OwnerFingerprintApprovalCeremonyTest {
    @Test fun approvalSignsDeterministicOwnerBoundTranscriptAfterFreshVerification() {
        val bundle = "canonical-trust-bundle".toByteArray()
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(bundle).joinToString("") { "%02x".format(it) }
        val challenge = ByteArray(32) { 0x5a }
        val expiry = 1_700_000_200L
        var verified = false
        var signed = ByteArray(0)
        val proof = OwnerFingerprintApprovalCeremony.approve(bundle, fingerprint, "owner-123", challenge, expiry, fingerprint, { true }, { verified = true }, { signed = it; byteArrayOf(0x30, 0x01) }, now = 1_700_000_000L)
        assertTrue(verified)
        assertEquals(fingerprint, proof.fingerprint)
        assertArrayEquals(challenge, proof.challenge)
        assertEquals(expiry, proof.expiresAt)
        assertArrayEquals(byteArrayOf(0x30, 0x01), proof.signature)

        val expected = ByteArrayOutputStream()
        DataOutputStream(expected).use { out ->
            out.write("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1\n".toByteArray(Charsets.US_ASCII))
            val owner = "owner-123".toByteArray()
            out.writeInt(owner.size); out.write(owner)
            out.write(MessageDigest.getInstance("SHA-256").digest(bundle))
            out.writeInt(challenge.size); out.write(challenge); out.writeLong(expiry)
        }
        assertArrayEquals(expected.toByteArray(), signed)
    }

    @Test fun mismatchFailsBeforeVerificationAndSigning() {
        val bundle = "candidate".toByteArray()
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(bundle).joinToString("") { "%02x".format(it) }
        var verified = false; var signed = false
        try {
            OwnerFingerprintApprovalCeremony.approve(bundle, "0".repeat(64), "owner-123", ByteArray(32), 1_700_000_200L, fingerprint, { verified = true }, { signed = true; byteArrayOf(1) }, now = 1_700_000_000L)
            fail("Fingerprint mismatch must be rejected")
        } catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { }
        assertFalse(verified); assertFalse(signed)
    }

    @Test fun expiredChallengeFailsClosed() {
        val bundle = "candidate".toByteArray()
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(bundle).joinToString("") { "%02x".format(it) }
        try {
            OwnerFingerprintApprovalCeremony.approve(bundle, fingerprint, "owner-123", ByteArray(32), 1_700_000_000L, fingerprint, { true }, {}, { byteArrayOf(1) }, now = 1_700_000_000L)
            fail("Expired challenge must be rejected")
        } catch (_: OwnerFingerprintApprovalCeremony.CeremonyException) { }
    }
}