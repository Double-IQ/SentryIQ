package co.bichet.sentryiq.master

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.Locale

/** Owner proof bound to one bundle, root role/key, device keyset and operation. */
object OwnerFingerprintApprovalCeremony {
    data class ApprovalProof(
        val bundleFingerprint: String, val rootRole: String, val rootKeyId: String,
        val rootFingerprint: String, val deviceKeysetDigest: String, val purpose: String,
        val challenge: ByteArray, val expiresAt: Long, val signature: ByteArray
    )
    class CeremonyException(message: String) : Exception(message)

    /** The verifier must atomically consume the challenge exactly once when accepting this proof. */
    fun approve(
        canonicalBundle: ByteArray, outOfBandFingerprint: String, ownerIdentifier: String,
        rootRole: String, rootKeyId: String, outOfBandRootFingerprint: String,
        deviceKeysetDigest: String, purpose: String, challenge: ByteArray, expiresAt: Long,
        confirmFingerprint: () -> String, confirmRootFingerprint: () -> String,
        verifyCandidateTrustChain: (ByteArray, String, String, ByteArray, ByteArray, String) -> Boolean,
        requireFreshUserVerification: () -> Unit, sign: (ByteArray) -> ByteArray,
        now: Long = System.currentTimeMillis() / 1000L
    ): ApprovalProof {
        if (ownerIdentifier.isBlank() || ownerIdentifier.toByteArray(Charsets.UTF_8).size > 256 ||
            ownerIdentifier.contains("\n") || ownerIdentifier.contains("\r")) {
            throw CeremonyException("Invalid owner identifier.")
        }
        if (!validToken(rootRole) || !validToken(rootKeyId) || !validToken(purpose) || challenge.size != 32) {
            throw CeremonyException("Invalid ceremony context or challenge.")
        }
        if (expiresAt <= now || expiresAt - now > 300) {
            throw CeremonyException("Bootstrap challenge is expired or exceeds five minutes.")
        }
        val bundleDigest = MessageDigest.getInstance("SHA-256").digest(canonicalBundle)
        val expectedBundle = decodeFingerprint(outOfBandFingerprint)
        val expectedRoot = decodeFingerprint(outOfBandRootFingerprint)
        val keysetDigest = decodeFingerprint(deviceKeysetDigest)
        // Validate the bundle and resolve its selected root before asking the owner to confirm it.
        if (!verifyCandidateTrustChain(canonicalBundle, rootRole, rootKeyId, expectedRoot, keysetDigest, purpose)) {
            throw CeremonyException("Candidate trust chain or approval context failed validation.")
        }
        val confirmedBundle = decodeFingerprint(confirmFingerprint())
        val confirmedRoot = decodeFingerprint(confirmRootFingerprint())
        if (!MessageDigest.isEqual(bundleDigest, expectedBundle) ||
            !MessageDigest.isEqual(bundleDigest, confirmedBundle) ||
            !MessageDigest.isEqual(expectedRoot, confirmedRoot)) {
            throw CeremonyException("Owner-confirmed fingerprint does not match independent record.")
        }

        val transcript = makeTranscript(
            ownerIdentifier, bundleDigest, rootRole, rootKeyId, expectedRoot,
            keysetDigest, purpose, challenge, expiresAt
        )
        requireFreshUserVerification()
        val signature = sign(transcript)
        if (signature.isEmpty()) throw CeremonyException("Master signer returned an empty signature.")
        return ApprovalProof(
            formatFingerprint(bundleDigest), rootRole, rootKeyId, formatFingerprint(expectedRoot),
            formatFingerprint(keysetDigest), purpose, challenge.copyOf(), expiresAt, signature
        )
    }

    private fun validOwnerIdentifier(value: String): Boolean =\n        value.isNotEmpty() && value.toByteArray(Charsets.UTF_8).size <= 256 &&\n            value.matches(Regex("^[A-Za-z0-9._:-]+$"))\n\n    private fun validToken(value: String): Boolean =
        value.isNotEmpty() && value.toByteArray(Charsets.UTF_8).size <= 128 &&
            value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' || it == '_' }

    private fun decodeFingerprint(value: String): ByteArray {
        val hex = value.replace(":", "").replace(" ", "").lowercase(Locale.ROOT)
        if (hex.length != 64 || hex.any { it.digitToIntOrNull(16) == null }) {
            throw CeremonyException("Fingerprint must be a SHA-256 hex value.")
        }
        return ByteArray(32) { index -> hex.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun formatFingerprint(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun makeTranscript(
        owner: String, bundleDigest: ByteArray, role: String, keyId: String,
        rootFingerprint: ByteArray, keysetDigest: ByteArray, purpose: String,
        challenge: ByteArray, expiry: Long
    ): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data ->
            data.write("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n".toByteArray(Charsets.US_ASCII))
            fun field(value: String) {
                val bytes = value.toByteArray(Charsets.UTF_8)
                data.writeInt(bytes.size); data.write(bytes)
            }
            field(owner); data.write(bundleDigest); field(role); field(keyId)
            data.write(rootFingerprint); data.write(keysetDigest); field(purpose)
            data.writeInt(challenge.size); data.write(challenge); data.writeLong(expiry)
        }
        return output.toByteArray()
    }
}
