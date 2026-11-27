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
            fun field(value: String) { field(value.toByteArray(Charsets.UTF_8)) }
            fun field(value: ByteArray) { out.writeInt(value.size); out.write(value) }
            field(signingKeyId); field(signingAlgorithm); field(signingPublicKeyRaw)
            field(agreementKeyId); field(agreementAlgorithm); field(agreementPublicKeyRaw)
            field(hardwareAssurance)
        }
        return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
