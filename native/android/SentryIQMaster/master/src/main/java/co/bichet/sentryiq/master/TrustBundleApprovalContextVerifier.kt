package co.bichet.sentryiq.master

import org.json.JSONObject
import java.security.MessageDigest

/** Re-checks the selected approval context against the exact bundle already
 * authenticated by the pinned registry anchor and persisted after TUF refresh. */
class TrustBundleApprovalContextVerifier(
    private val verified: OwnerBootstrapHttpClient.VerifiedBootstrapState
) {
    fun verify(
        canonicalBundle: ByteArray,
        rootRole: String,
        rootKeyId: String,
        rootFingerprint: ByteArray,
        deviceKeysetDigest: ByteArray,
        purpose: String
    ): Boolean {
        return try {
        if (!canonicalBundle.contentEquals(verified.snapshot.canonicalBundle) ||
            !MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(canonicalBundle), verified.anchor.bundleSha256) ||
            verified.anchor.sequence.toString() != verified.snapshot.sequence ||
            !MessageDigest.isEqual(verified.anchor.bundleSha256, decodeHex(verified.snapshot.bundleSha256)) ||
            verified.anchor.ownerId != verified.snapshot.ownerId ||
            verified.snapshot.ownerId.isBlank() ||
            rootRole != "release-authorisation" || purpose != "bootstrap-release-root" ||
            listOf("root.json", "timestamp.json", "snapshot.json", "targets.json").any { it !in verified.verifiedTufMetadata }) {
            return false
        }
        val bundle = JSONObject(canonicalBundle.toString(Charsets.UTF_8))
        if (bundle.getString("owner_id") != verified.snapshot.ownerId) return false
        val releaseKeys = bundle.getJSONObject("release_authorisation").getJSONArray("keys")
        var selected: JSONObject? = null
        for (index in 0 until releaseKeys.length()) {
            val candidate = releaseKeys.getJSONObject(index)
            if (candidate.optString("kid") == rootKeyId) selected = candidate
        }
        val root = selected ?: return false
        if (root.optString("purpose") != "release-authorisation" || root.optString("alg") != "ES256") return false
        val rootDer = P256PublicKeyMaterial.derFromPem(root.getString("public_key_pem"))
        val expectedRoot = MessageDigest.getInstance("SHA-256").digest(rootDer)
        if (!MessageDigest.isEqual(expectedRoot, rootFingerprint)) return false

        val master = bundle.getJSONObject("master_keyset")
        val signing = master.getJSONObject("signing")
        val agreement = master.getJSONObject("key_agreement")
        if (signing.optString("alg") != "ES256" || agreement.optString("alg") != "ECDH-ES") return false
        val digest = MasterKeysetDigest.compute(
            signing.getString("kid"),
            "ES256",
            P256PublicKeyMaterial.rawFromPem(signing.getString("public_key_pem")),
            agreement.getString("kid"),
            "ECDH-ES",
            P256PublicKeyMaterial.rawFromPem(agreement.getString("public_key_pem")),
            master.getString("hardware_assurance")
        )
        val expectedKeyset = ByteArray(32) { index -> digest.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
        MessageDigest.isEqual(expectedKeyset, deviceKeysetDigest)
        } catch (_: Exception) {
            false
        }
    }

    private fun decodeHex(value: String): ByteArray {
        if (!value.matches(Regex("^[a-f0-9]{64}$"))) throw IllegalArgumentException("Invalid SHA-256 hex.")
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}
