package co.bichet.sentryiq.master

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest

/** Matches the iOS and PHP SENTRYIQ-MASTER-KEYSET-V1 transcript exactly. */
object MasterKeysetDigest {
    fun compute(
        signingKeyId: String,
        signingAlgorithm: String,
        signingPublicKeyRaw: ByteArray,
        agreementKeyId: String,
        agreementAlgorithm: String,
        agreementPublicKeyRaw: ByteArray,
        hardwareAssurance: String
    ): String {
        require(signingPublicKeyRaw.size == 64 && agreementPublicKeyRaw.size == 64)
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.write("SENTRYIQ-MASTER-KEYSET-V1\n".toByteArray(Charsets.US_ASCII))
            fun fieldBytes(value: ByteArray) { out.writeInt(value.size); out.write(value) }
            fun fieldString(value: String) { fieldBytes(value.toByteArray(Charsets.UTF_8)) }
            fieldString(signingKeyId); fieldString(signingAlgorithm); fieldBytes(signingPublicKeyRaw)
            fieldString(agreementKeyId); fieldString(agreementAlgorithm); fieldBytes(agreementPublicKeyRaw)
            fieldString(hardwareAssurance)
        }
        return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
