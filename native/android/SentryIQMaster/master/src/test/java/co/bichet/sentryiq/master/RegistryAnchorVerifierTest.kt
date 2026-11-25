package co.bichet.sentryiq.master

import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class RegistryAnchorVerifierTest {
    private val now = 1_800_000_000L
    private val ownerId = "owner-test-001"
    private val signerId = "registry-test-1"
    private val bundleDigest = "11".repeat(32)

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun payload(sequence: Long = 1L, previous: String? = null): ByteArray {
        val previousJson = if (previous == null) "null" else "\"" + previous + "\""
        return ("{\"bundle_sha256\":\"" + bundleDigest +
            "\",\"expires_at\":" + (now + 3600) +
            ",\"issued_at\":" + (now - 10) +
            ",\"owner_id\":\"" + ownerId +
            "\",\"previous_bundle_sha256\":" + previousJson +
            ",\"schema_version\":1,\"sequence\":\"" + sequence +
            "\",\"signer_kid\":\"" + signerId +
            "\",\"type\":\"SENTRYIQ-REGISTRY-ANCHOR\"}").toByteArray(Charsets.UTF_8)
    }

    private fun derToRawLowS(der: ByteArray): ByteArray {
        var offset = 2
        require(der[0] == 0x30.toByte())
        require(der[offset++] == 0x02.toByte())
        val rLength = der[offset++].toInt() and 0xff
        val r = BigInteger(1, der.copyOfRange(offset, offset + rLength))
        offset += rLength
        require(der[offset++] == 0x02.toByte())
        val sLength = der[offset++].toInt() and 0xff
        var s = BigInteger(1, der.copyOfRange(offset, offset + sLength))
        val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        if (s > order.shiftRight(1)) s = order.subtract(s)
        fun fixed(value: BigInteger): ByteArray {
            val raw = value.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
            return ByteArray(32 - raw.size) + raw
        }
        return fixed(r) + fixed(s)
    }

    private fun signedAnchor(pair: KeyPair): ProtectedTrustStateStore.RegistryAnchor {
        val payload = payload()
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(pair.private)
        signer.update(payload)
        return ProtectedTrustStateStore.RegistryAnchor(
            sequence = 1L,
            bundleSha256 = ByteArray(32) { 0x11 },
            signedPayload = payload,
            signature = derToRawLowS(signer.sign()),
            issuedAt = now - 10,
            expiresAt = now + 3600,
            previousBundleSha256 = null,
            ownerId = ownerId,
            signerKeyId = signerId
        )
    }

    @Test fun verifiesSignatureFromIndependentlyPinnedRegistrySigner() {
        val pair = keyPair()
        val anchor = signedAnchor(pair)
        RegistryAnchorVerifier.verify(
            anchor,
            ownerId,
            listOf(RegistryAnchorSignerKey(signerId, "registry-anchor", "ES256", pair.public.encoded)),
            now
        )
    }

    @Test fun rejectsWrongOwnerRolePayloadAndExpiredAnchor() {
        val pair = keyPair()
        val anchor = signedAnchor(pair)
        val key = RegistryAnchorSignerKey(signerId, "registry-anchor", "ES256", pair.public.encoded)
        assertThrows(IllegalArgumentException::class.java) {
            RegistryAnchorVerifier.verify(anchor, "different-owner", listOf(key), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RegistryAnchorVerifier.verify(anchor, ownerId, listOf(key.copy(role = "release-authorisation")), now)
        }
        val changed = anchor.copy(signedPayload = anchor.signedPayload + byteArrayOf(0x20))
        assertThrows(IllegalArgumentException::class.java) {
            RegistryAnchorVerifier.verify(changed, ownerId, listOf(key), now)
        }
        assertThrows(IllegalArgumentException::class.java) {
            RegistryAnchorVerifier.verify(anchor, ownerId, listOf(key), now + 4000)
        }
    }

    @Test fun rejectsDuplicatePinnedSignerIdentifiers() {
        val pair = keyPair()
        val anchor = signedAnchor(pair)
        val key = RegistryAnchorSignerKey(signerId, "registry-anchor", "ES256", pair.public.encoded)
        assertThrows(IllegalArgumentException::class.java) {
            RegistryAnchorVerifier.verify(anchor, ownerId, listOf(key, key), now)
        }
    }
}
