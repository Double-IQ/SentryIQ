package co.bichet.sentryiq.master

import android.util.Base64
import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.interfaces.ECPublicKey

internal object P256PublicKeyMaterial {
    private val p256Prime = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)

    fun derFromPem(pem: String): ByteArray {
        val body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot { it.isWhitespace() }
        val der = try { Base64.decode(body, Base64.DEFAULT) }
            catch (error: IllegalArgumentException) { throw IllegalArgumentException("Malformed P-256 public key PEM.", error) }
        if (der.size != 91) throw IllegalArgumentException("Unexpected P-256 SPKI length.")
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as ECPublicKey
        if (key.params.curve.field.fieldSize != 256 || key.params.curve.field !is java.security.spec.ECFieldFp ||
            (key.params.curve.field as java.security.spec.ECFieldFp).p != p256Prime) {
            throw IllegalArgumentException("Public key is not NIST P-256.")
        }
        return der
    }

    fun rawFromPem(pem: String): ByteArray {
        val der = derFromPem(pem)
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as ECPublicKey
        fun coordinate(value: BigInteger): ByteArray {
            val raw = value.toByteArray().let { if (it.size > 32 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
            require(raw.size <= 32)
            return ByteArray(32 - raw.size) + raw
        }
        return coordinate(key.w.affineX) + coordinate(key.w.affineY)
    }
}
