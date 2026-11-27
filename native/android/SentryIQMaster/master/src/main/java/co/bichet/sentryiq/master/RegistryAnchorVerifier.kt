package co.bichet.sentryiq.master

import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Locale

data class RegistryAnchorSignerKey(
    val keyId: String,
    val role: String,
    val algorithm: String,
    val subjectPublicKeyInfoDer: ByteArray
)

/** Verifies the canonical registry-anchor envelope using only separately pinned keys. */
object RegistryAnchorVerifier {
    private const val HALF_P256_ORDER = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"

    fun makeVerifier(
        expectedOwnerId: String,
        trustedSignerKeys: List<RegistryAnchorSignerKey>
    ): (ProtectedTrustStateStore.RegistryAnchor) -> Boolean = { anchor ->
        try {
            verify(anchor, expectedOwnerId, trustedSignerKeys)
            true
        } catch (_: Exception) {
            false
        }
    }

    fun verify(
        anchor: ProtectedTrustStateStore.RegistryAnchor,
        expectedOwnerId: String,
        trustedSignerKeys: List<RegistryAnchorSignerKey>,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ) {
        require(validIdentifier(expectedOwnerId, 256) && anchor.ownerId == expectedOwnerId)
        require(validIdentifier(anchor.signerKeyId, 128))
        require(anchor.sequence > 0uL && anchor.bundleSha256.size == 32)
        require(anchor.signature.size == 64)
        require(anchor.previousBundleSha256 == null || anchor.previousBundleSha256.size == 32)
        require(TrustRegistryAnchorPolicy.isFresh(anchor.issuedAt, anchor.expiresAt, nowEpochSeconds))
        require(canonicalPayload(anchor).contentEquals(anchor.signedPayload)) {
            "Registry anchor payload is not canonical or does not bind the supplied fields."
        }

        val byId = LinkedHashMap<String, RegistryAnchorSignerKey>()
        trustedSignerKeys.forEach { key ->
            require(validIdentifier(key.keyId, 128) && byId.putIfAbsent(key.keyId, key) == null) {
                "Pinned registry signer set has invalid or duplicate key IDs."
            }
        }
        val signer = byId[anchor.signerKeyId] ?: throw IllegalArgumentException("Registry signer is not pinned.")
        require(signer.role == "registry-anchor" && signer.algorithm == "ES256") {
            "Registry signer role or algorithm is not permitted."
        }

        val raw = anchor.signature
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val halfOrder = BigInteger(HALF_P256_ORDER, 16)
        require(r.signum() > 0 && s.signum() > 0 && s <= halfOrder) {
            "Registry signature must be canonical low-S ES256."
        }

        val publicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(signer.subjectPublicKeyInfoDer))
        require(publicKey is ECPublicKey && isP256(publicKey.params)) { "Registry signer key must use P-256." }
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(anchor.signedPayload)
        require(verifier.verify(rawSignatureToDer(raw))) { "Registry anchor signature verification failed." }
    }

    private fun canonicalPayload(anchor: ProtectedTrustStateStore.RegistryAnchor): ByteArray {
        val previous = anchor.previousBundleSha256?.toHex()
        val previousJson = if (previous == null) "null" else "\"" + previous + "\""
        val json = "{\"bundle_sha256\":\"" + anchor.bundleSha256.toHex() +
            "\",\"expires_at\":" + anchor.expiresAt +
            ",\"issued_at\":" + anchor.issuedAt +
            ",\"owner_id\":\"" + anchor.ownerId +
            "\",\"previous_bundle_sha256\":" + previousJson +
            ",\"schema_version\":1,\"sequence\":\"" + anchor.sequence +
            "\",\"signer_kid\":\"" + anchor.signerKeyId +
            "\",\"type\":\"SENTRYIQ-REGISTRY-ANCHOR\"}"
        return json.toByteArray(Charsets.UTF_8)
    }

    private fun validIdentifier(value: String, maxLength: Int): Boolean =
        value.length in 1..maxLength && value.matches(Regex("^[A-Za-z0-9._:-]+$"))

    private fun isP256(actual: ECParameterSpec): Boolean {
        val parameters = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        return actual.curve.field == parameters.curve.field &&
            actual.curve.a == parameters.curve.a &&
            actual.curve.b == parameters.curve.b &&
            actual.generator == parameters.generator &&
            actual.order == parameters.order &&
            actual.cofactor == parameters.cofactor
    }

    private fun rawSignatureToDer(raw: ByteArray): ByteArray {
        fun encodeInteger(bytes: ByteArray): ByteArray {
            var first = 0
            while (first < bytes.size - 1 && bytes[first] == 0.toByte()) first++
            var value = bytes.copyOfRange(first, bytes.size)
            if ((value[0].toInt() and 0x80) != 0) value = byteArrayOf(0) + value
            return byteArrayOf(0x02, value.size.toByte()) + value
        }
        val body = encodeInteger(raw.copyOfRange(0, 32)) + encodeInteger(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }
}
