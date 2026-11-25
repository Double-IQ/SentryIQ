package co.bichet.sentryiq.master

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class AndroidP256EncodingTest {
    @Test
    fun subjectPublicKeyInfoPemMatchesJavaEcPublicKey() {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val publicKey = pair.public as ECPublicKey
        val pem = AndroidP256Encoding.subjectPublicKeyInfoPEM(publicKey)
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot { it.isWhitespace() }
        val decoded = Base64.getDecoder().decode(body)

        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----\n"))
        assertTrue(pem.endsWith("-----END PUBLIC KEY-----\n"))
        assertArrayEquals(publicKey.encoded, decoded)
        val parsed = AndroidP256Encoding.parseSubjectPublicKeyInfoPEM(pem)\n        assertArrayEquals(publicKey.encoded, parsed.encoded)\n        assertEquals(64, AndroidP256Encoding.rawPublicKey(publicKey).size)
    }

    @Test
    fun keyIdentifiersAreDeterministicAndRoleSeparated() {
        val raw = ByteArray(64) { 0x42 }
        val signing = AndroidP256Encoding.keyId("master-signing", raw)
        val agreement = AndroidP256Encoding.keyId("master-key-agreement", raw)

        assertEquals(signing, AndroidP256Encoding.keyId("master-signing", raw))
        assertNotEquals(signing, agreement)
        assertTrue(signing.startsWith("master-signing-"))
    }

    @Test
    fun derSignatureConvertsToVerifiableLowSJose() {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val message = "SentryIQ Android master signing test".toByteArray()
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(pair.private)
        signer.update(message)
        val der = signer.sign()
        val jose = Es256SignatureEncoding.derToJoseLowS(der)

        assertEquals(64, jose.size)
        assertFalse(compareUnsigned(jose.copyOfRange(32, 64), halfOrder()) > 0)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(pair.public)
        verifier.update(message)
        assertTrue(verifier.verify(joseToDer(jose)))
    }

    @Test
    fun highSJoseNormalizesToEquivalentLowS() {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val signer = Signature.getInstance("SHA256withECDSA")
        val message = "SentryIQ Android ECDSA malleability test".toByteArray()
        signer.initSign(pair.private)
        signer.update(message)
        val low = Es256SignatureEncoding.derToJoseLowS(signer.sign())
        val high = highSFromLow(low)
        val normalized = Es256SignatureEncoding.normalizeJoseLowS(high)

        assertArrayEquals(low, normalized)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(pair.public)
        verifier.update(message)
        assertTrue(verifier.verify(joseToDer(normalized)))
    }

    @Test
    fun malformedDerSignatureIsRejected() {
        try {
            Es256SignatureEncoding.derToJoseLowS(byteArrayOf(0x30, 0x01, 0x00))
            fail("Malformed DER signature should be rejected.")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }

    @Test
    fun hkdfSha256MatchesRfc5869TestCaseOne() {
        val inputKeyMaterial = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865"
        )

        assertArrayEquals(expected, HkdfSha256.derive(inputKeyMaterial, salt, info, 42))
    }

    private fun highSFromLow(low: ByteArray): ByteArray {
        val order = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        val s = low.copyOfRange(32, 64)
        val high = subtract(order, s)
        return low.copyOfRange(0, 32) + high
    }

    private fun subtract(minuend: ByteArray, subtrahend: ByteArray): ByteArray {
        val result = minuend.copyOf()
        var borrow = 0
        for (index in 31 downTo 0) {
            var value = (minuend[index].toInt() and 0xff) -
                (subtrahend[index].toInt() and 0xff) - borrow
            borrow = if (value < 0) 1 else 0
            if (borrow == 1) value += 256
            result[index] = value.toByte()
        }
        return result
    }

    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        for (index in left.indices) {
            val a = left[index].toInt() and 0xff
            val b = right[index].toInt() and 0xff
            if (a != b) return a.compareTo(b)
        }
        return 0
    }

    private fun halfOrder() =
        hex("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8")

    private fun joseToDer(raw: ByteArray): ByteArray {
        fun integer(value: ByteArray): ByteArray {
            var start = 0
            while (start < value.size - 1 && value[start] == 0.toByte()) start++
            var magnitude = value.copyOfRange(start, value.size)
            if ((magnitude[0].toInt() and 0x80) != 0) magnitude = byteArrayOf(0) + magnitude
            return byteArrayOf(0x02, magnitude.size.toByte()) + magnitude
        }
        val body = integer(raw.copyOfRange(0, 32)) + integer(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
