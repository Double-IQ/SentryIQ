package co.bichet.sentryiq.master

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.Locale

/** Owner confirmation proof over the exact canonical candidate bundle. */
object OwnerFingerprintApprovalCeremony {
    data class ApprovalProof(val fingerprint: String, val challenge: ByteArray, val expiresAt: Long, val signature: ByteArray)
    class CeremonyException(message: String) : Exception(message)

    /** UI confirmation and OS fresh-user-verification are mandatory callbacks. */
    fun approve(canonicalBundle: ByteArray, outOfBandFingerprint: String, ownerIdentifier: String, challenge: ByteArray, expiresAt: Long, confirmFingerprint: String, requireFreshUserVerification: () -> Unit, sign: (ByteArray) -> ByteArray, now: Long = System.currentTimeMillis() / 1000L): ApprovalProof {
        if (ownerIdentifier.isBlank() || ownerIdentifier.contains("\n") || ownerIdentifier.contains("\r")) throw CeremonyException("Invalid owner identifier.")
        if (challenge.size != 32) throw CeremonyException("Invalid bootstrap challenge.")
        if (expiresAt <= now || expiresAt - now > 300) throw CeremonyException("Bootstrap challenge is expired or exceeds five minutes.")
        val digest = MessageDigest.getInstance("SHA-256").digest(canonicalBundle)
        val expected = decodeFingerprint(outOfBandFingerprint); val confirmed = decodeFingerprint(confirmFingerprint)
        if (!MessageDigest.isEqual(digest, expected) || !MessageDigest.isEqual(digest, confirmed)) throw CeremonyException("Owner-confirmed fingerprint does not match candidate bundle.")
        val transcript = makeTranscript(ownerIdentifier, digest, challenge, expiresAt)
        requireFreshUserVerification()
        val signature = sign(transcript)
        if (signature.isEmpty()) throw CeremonyException("Master signer returned an empty signature.")
        return ApprovalProof(formatFingerprint(digest), challenge.copyOf(), expiresAt, signature)
    }

    private fun decodeFingerprint(value: String): ByteArray {
        val hex = value.replace(":", "").replace(" ", "").lowercase(Locale.ROOT)
        if (hex.length != 64 || hex.any { it.digitToIntOrNull(16) == null }) throw CeremonyException("Fingerprint must be a SHA-256 hex value.")
        return ByteArray(32) { index -> hex.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
    private fun formatFingerprint(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    private fun makeTranscript(ownerIdentifier: String, digest: ByteArray, challenge: ByteArray, expiresAt: Long): ByteArray {
        val owner = ownerIdentifier.toByteArray(Charsets.UTF_8); val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data -> data.write("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1\n".toByteArray(Charsets.US_ASCII)); data.writeInt(owner.size); data.write(owner); data.write(digest); data.writeInt(challenge.size); data.write(challenge); data.writeLong(expiresAt) }
        return output.toByteArray()
    }
}