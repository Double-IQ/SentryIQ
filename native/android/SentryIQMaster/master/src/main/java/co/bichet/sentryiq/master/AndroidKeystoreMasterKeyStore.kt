package co.bichet.sentryiq.master

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Android master-key adapter. API 31+ is the initial floor because AGREE_KEY and
 * KeyInfo.securityLevel are required to distinguish hardware assurance reliably.
 *
 * TEE acceptance is deliberately delegated to an app-supplied attestation policy.
 * That policy must validate the complete Android key-attestation chain, challenge,
 * verified boot state, patch levels, app identity and approved device policy.
 */
class AndroidKeystoreMasterKeyStore(
    private val aliasPrefix: String = "co.bichet.sentryiq.master",
    private val teeAttestationPolicy: (List<java.security.cert.Certificate>, List<java.security.cert.Certificate>, ByteArray) -> Boolean
) {
    data class PublicKeyDescriptor(val kid: String, val alg: String, val publicKeyPem: String)
    data class PublicKeySet(
        val signing: PublicKeyDescriptor,
        val keyAgreement: PublicKeyDescriptor,
        val hardwareAssurance: String
    )

    /** Opaque handle for one Keystore-backed, per-use authenticated signature. */
    class SigningOperation internal constructor(internal val signature: Signature) {
        /** Supply this exact object to BiometricPrompt.CryptoObject. */
        val cryptoObjectSignature: Signature get() = signature
    }

    sealed class StoreException(message: String) : Exception(message) {
        class IncompleteKeyset : StoreException("Master keyset is incomplete; recovery is required.")
        class UnsupportedHardware : StoreException("No approved hardware-backed Android Keystore tier is available.")
        class UnqualifiedTee : StoreException("TEE attestation did not satisfy the configured device policy.")
        class InvalidKey : StoreException("Stored master key material is invalid.")
    }

    private val signingAlias = "$aliasPrefix.signing.v1"
    private val agreementAlias = "$aliasPrefix.agreement.v1"
    private val lock = Any()

    /** Reads existing keys only. It never creates or replaces a missing identity. */
    fun loadExisting(): PublicKeySet = synchronized(lock) {
        val store = keyStore()
        val signing = store.getEntry(signingAlias, null) as? KeyStore.PrivateKeyEntry
        val agreement = store.getEntry(agreementAlias, null) as? KeyStore.PrivateKeyEntry
        if (signing == null || agreement == null) throw StoreException.IncompleteKeyset()
        describe(signing.certificate.publicKey.encoded, agreement.certificate.publicKey.encoded,
            assurance(signing, agreement))
    }

    /** Explicit first-run operation; caller must have completed the owner-start ceremony. */
    fun createInitialMasterKeyset(): PublicKeySet = synchronized(lock) {
        val store = keyStore()
        val hasSigning = store.containsAlias(signingAlias)
        val hasAgreement = store.containsAlias(agreementAlias)
        if (hasSigning || hasAgreement) {
            if (hasSigning && hasAgreement) return@synchronized loadExisting()
            throw StoreException.IncompleteKeyset()
        }

        val challenge = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        try {
            val signing = generate(signingAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY, challenge)
            val agreement = generate(agreementAlias, KeyProperties.PURPOSE_AGREE_KEY, challenge)
            val signingEntry = store.getEntry(signingAlias, null) as KeyStore.PrivateKeyEntry
            val agreementEntry = store.getEntry(agreementAlias, null) as KeyStore.PrivateKeyEntry
            val level = assurance(signingEntry, agreementEntry)
            if (level == "android-tee-qualified") {
                val signingChain = store.getCertificateChain(signingAlias)?.toList().orEmpty()
                val agreementChain = store.getCertificateChain(agreementAlias)?.toList().orEmpty()
                if (!teeAttestationPolicy(signingChain, agreementChain, challenge)) throw StoreException.UnqualifiedTee()
            }
            describe(signing.public.encoded, agreement.public.encoded, level)
        } catch (error: Throwable) {
            // Do not leave a half-created identity that a later run might mistake as valid.
            runCatching { store.deleteEntry(signingAlias) }
            runCatching { store.deleteEntry(agreementAlias) }
            throw error
        }
    }

    /**
     * Prepares a per-use authenticated signing operation.
     *
     * Pass the returned Signature to BiometricPrompt.CryptoObject, then call
     * completeSigningOperation() with the authenticated Signature from the
     * successful AuthenticationResult. A generic biometric check performed
     * separately from this CryptoObject is not sufficient for this key policy.
     */
    fun beginSigningOperation(message: ByteArray): SigningOperation {
        val operation = Signature.getInstance("SHA256withECDSA")
        operation.initSign(privateKey(signingAlias))
        operation.update(message)
        return SigningOperation(operation)
    }

    /** Completes the exact prepared operation after its CryptoObject authenticates. */
    fun completeSigningOperation(operation: SigningOperation): ByteArray =
        derEcdsaToLowSJose(operation.signature.sign())

    /** P-256 ECDH followed by HKDF-SHA256; raw ECDH output is not returned. */
    fun deriveKey(peerSubjectPublicKeyInfo: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val peer = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(peerSubjectPublicKeyInfo))
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey(agreementAlias))
        agreement.doPhase(peer, true)
        return hkdfSha256(agreement.generateSecret(), salt, info, 32)
    }

    private fun generate(alias: String, purposes: Int, challenge: ByteArray): KeyPair {
        val generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .setAttestationChallenge(challenge)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true) }
            .build()

        if (Build.VERSION.SDK_INT >= 28) {
            try {
                generator.initialize(spec(true))
                return generator.generateKeyPair()
            } catch (_: StrongBoxUnavailableException) {
                // Fall through only for genuine StrongBox unavailability.
            }
        }
        generator.initialize(spec(false))
        val pair = generator.generateKeyPair()
        val info = keyInfo(pair.private)
        if (info.securityLevel != KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
            keyStore().deleteEntry(alias)
            throw StoreException.UnsupportedHardware()
        }
        return pair
    }

    private fun assurance(signing: KeyStore.PrivateKeyEntry, agreement: KeyStore.PrivateKeyEntry): String {
        val a = keyInfo(signing.privateKey).securityLevel
        val b = keyInfo(agreement.privateKey).securityLevel
        if (a != b) throw StoreException.UnsupportedHardware()
        return when (a) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "android-strongbox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "android-tee-qualified"
            else -> throw StoreException.UnsupportedHardware()
        }
    }

    private fun keyInfo(key: java.security.PrivateKey): KeyInfo {
        val factory = java.security.KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        return factory.getKeySpec(key, KeyInfo::class.java)
    }

    private fun privateKey(alias: String): java.security.PrivateKey {
        val entry = keyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw StoreException.IncompleteKeyset()
        return entry.privateKey
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun describe(signingDer: ByteArray, agreementDer: ByteArray, assurance: String): PublicKeySet {
        if (signingDer.contentEquals(agreementDer)) throw StoreException.InvalidKey()
        return PublicKeySet(
            descriptor("master-signing", "ES256", signingDer),
            descriptor("master-key-agreement", "ECDH-ES", agreementDer),
            assurance
        )
    }

    private fun descriptor(role: String, alg: String, der: ByteArray): PublicKeyDescriptor {
        val ec = java.security.KeyFactory.getInstance("EC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(der)) as ECPublicKey
        fun coordinate(value: BigInteger): ByteArray {
            val raw = value.toByteArray().let { if (it.size > 32 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
            require(raw.size <= 32)
            return ByteArray(32 - raw.size) + raw
        }
        // Match iOS key IDs: SHA-256 over the 64-byte X||Y P-256 raw public key.
        val rawPublic = coordinate(ec.w.affineX) + coordinate(ec.w.affineY)
        val id = MessageDigest.getInstance("SHA-256").digest(rawPublic).joinToString("") { "%02x".format(it) }
        val pemBody = android.util.Base64.encodeToString(der, android.util.Base64.NO_WRAP)
        val pem = "-----BEGIN PUBLIC KEY-----\n" + pemBody.chunked(64).joinToString("\n") + "\n-----END PUBLIC KEY-----\n"
        return PublicKeyDescriptor("$role-$id", alg, pem)
    }

    private fun derEcdsaToLowSJose(der: ByteArray): ByteArray {
        var p = 0
        require(der[p++].toInt() == 0x30)
        val sequenceLength = der[p++].toInt() and 0xff
        require(sequenceLength == der.size - p)
        require(der[p++].toInt() == 0x02)
        val rLength = der[p++].toInt() and 0xff
        val r = BigInteger(1, der.copyOfRange(p, p + rLength)); p += rLength
        require(der[p++].toInt() == 0x02)
        val sLength = der[p++].toInt() and 0xff
        val sValue = BigInteger(1, der.copyOfRange(p, p + sLength))
        val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        require(r.signum() > 0 && r < order && sValue.signum() > 0 && sValue < order)
        val s = if (sValue > order.shiftRight(1)) order.subtract(sValue) else sValue
        return fixed32(r) + fixed32(s)
    }

    private fun fixed32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray().let { if (it.size > 32 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        require(bytes.size <= 32)
        return ByteArray(32 - bytes.size) + bytes
    }

    private fun hkdfSha256(input: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val extract = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(actualSalt, "HmacSHA256")) }
        val prk = extract.doFinal(input)
        val output = ByteArrayOutputStreamCompat()
        var previous = ByteArray(0)
        var counter = 1
        while (output.size() < length) {
            val expand = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(prk, "HmacSHA256")) }
            expand.update(previous); expand.update(info); expand.update(counter.toByte())
            previous = expand.doFinal()
            output.write(previous)
            counter++
        }
        return output.toByteArray().copyOf(length)
    }

    private class ByteArrayOutputStreamCompat {
        private val chunks = ArrayList<ByteArray>()
        private var count = 0
        fun write(bytes: ByteArray) { chunks.add(bytes); count += bytes.size }
        fun size() = count
        fun toByteArray() = ByteArray(count).also { out ->
            var offset = 0
            chunks.forEach { it.copyInto(out, offset); offset += it.size }
        }
    }
}
