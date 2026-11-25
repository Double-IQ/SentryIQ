package co.bichet.sentryiq.master

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class AndroidMasterKeyException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class AndroidAttestationChallenges(
    val signing: ByteArray,
    val keyAgreement: ByteArray
) {
    init {
        require(signing.size in 16..128) { "Signing attestation challenge must be 16–128 bytes." }
        require(keyAgreement.size in 16..128) { "Agreement attestation challenge must be 16–128 bytes." }
        require(!signing.contentEquals(keyAgreement)) { "Attestation challenges must be unique per key." }
    }
}

data class AndroidAttestationEvidence(
    val packageName: String,
    val signingChallengeBase64: String,
    val agreementChallengeBase64: String,
    val signingCertificateChainDerBase64: List<String>,
    val agreementCertificateChainDerBase64: List<String>
)

/**
 * Must be implemented by an independently trusted verifier, not by code running
 * on the Android device being attested. It must validate the chain, Google/OEM
 * trust anchor, revocation status, challenge, app identity, boot state and key policy.
 */
fun interface IndependentTeeAttestationVerifier {
    fun verify(evidence: AndroidAttestationEvidence): Boolean
}

data class AndroidMasterKeyDescriptor(
    val kid: String,
    val alg: String,
    val public_key_pem: String
)

data class AndroidMasterKeySet(
    val signing: AndroidMasterKeyDescriptor,
    val key_agreement: AndroidMasterKeyDescriptor,
    val hardware_assurance: String,
    val attestationEvidence: AndroidAttestationEvidence
)

/**
 * Android Keystore adapter for separate P-256 signing and ECDH keys.
 *
 * API 31 is the initial implementation floor because PURPOSE_AGREE_KEY and the
 * exact KeyInfo security-level API are available there. This is not yet the
 * final supported-device policy; real-device qualification must set that floor.
 *
 * Authentication is hardware-enforced with a 30-second fresh-auth window.
 * The companion UI must invoke BiometricPrompt/device credential before each
 * sensitive operation. The Keystore rejects use outside that window.
 */
class AndroidMasterKeyStore(
    context: Context,
    private val teeVerifier: IndependentTeeAttestationVerifier? = null
) {
    companion object {
        const val AUTH_VALIDITY_SECONDS = 30
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGNING_ALIAS = "sentryiq.master.v1.signing"
        private const val AGREEMENT_ALIAS = "sentryiq.master.v1.agreement"
        private const val ASSURANCE_STRONGBOX = "android-strongbox"
        private const val ASSURANCE_TEE = "android-tee-qualified"
        private val AUTH_TYPES = KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        private val P256_ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    }

    private val appContext = context.applicationContext
    @Volatile private var validatedAssurance: String? = null

    /**
     * Explicit first-run creation only. The caller supplies fresh, independently
     * issued attestation challenges and must have obtained owner approval.
     * Existing aliases are never overwritten or silently regenerated.
     */
    @Synchronized
    @Throws(Exception::class)
    fun createInitialMasterKeyset(challenges: AndroidAttestationChallenges): AndroidMasterKeySet {
        requireSupportedApi()
        validatedAssurance = null
        val keyStore = loadKeyStore()
        val hasSigning = keyStore.containsAlias(SIGNING_ALIAS)
        val hasAgreement = keyStore.containsAlias(AGREEMENT_ALIAS)
        if (hasSigning || hasAgreement) {
            if (hasSigning && hasAgreement) {
                throw AndroidMasterKeyException("Master keyset already exists; use loadExisting().")
            }
            throw AndroidMasterKeyException("Partial Android master keyset requires recovery; refusing regeneration.")
        }

        try {
            generateKey(SIGNING_ALIAS, KeyProperties.PURPOSE_SIGN, challenges.signing, strongBox = true)
            generateKey(AGREEMENT_ALIAS, KeyProperties.PURPOSE_AGREE_KEY, challenges.keyAgreement, strongBox = true)
            return loadAndValidate(keyStore, challenges, expectedSecurityLevel = KeyProperties.SECURITY_LEVEL_STRONGBOX)
        } catch (unavailable: StrongBoxUnavailableException) {
            deleteAliases(keyStore)
            if (teeVerifier == null) {
                throw AndroidMasterKeyException(
                    "StrongBox is unavailable and no independent TEE attestation verifier is configured.",
                    unavailable
                )
            }
            return createTeeBackedKeyset(challenges, unavailable)
        } catch (failure: Exception) {
            deleteAliases(keyStore)
            throw failure
        }
    }

    /**
     * Loads existing keys only. Missing or partial aliases fail closed and never
     * trigger generation. The original attestation challenges must be supplied
     * from the separately persisted bootstrap receipt.
     */
    @Synchronized
    @Throws(Exception::class)
    fun loadExisting(challenges: AndroidAttestationChallenges): AndroidMasterKeySet {
        requireSupportedApi()
        validatedAssurance = null
        val keyStore = loadKeyStore()
        val hasSigning = keyStore.containsAlias(SIGNING_ALIAS)
        val hasAgreement = keyStore.containsAlias(AGREEMENT_ALIAS)
        if (!hasSigning && !hasAgreement) {
            throw AndroidMasterKeyException("Android master keyset is missing; recovery is required.")
        }
        if (!hasSigning || !hasAgreement) {
            throw AndroidMasterKeyException("Android master keyset is incomplete; recovery is required.")
        }
        return loadAndValidate(keyStore, challenges, expectedSecurityLevel = null)
    }

    /** ES256 signing. Call only after the companion's fresh local authentication. */
    @Synchronized
    fun sign(message: ByteArray): ByteArray {
        requireValidatedMasterKeyset()
        val keyStore = loadKeyStore()
        val privateKey = keyStore.getKey(SIGNING_ALIAS, null) as? PrivateKey
            ?: throw AndroidMasterKeyException("Master signing key is unavailable.")
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(message)
        return Es256SignatureEncoding.derToJoseLowS(signer.sign())
    }

    /**
     * P-256 ECDH followed immediately by HKDF-SHA256. Raw shared-secret bytes are
     * never returned. The peer key must be a P-256 SubjectPublicKeyInfo PEM.
     */
    @Synchronized
    fun deriveKey(peerPublicKeyPem: String, salt: ByteArray, sharedInfo: ByteArray): ByteArray {
        requireValidatedMasterKeyset()
        val keyStore = loadKeyStore()
        val privateKey = keyStore.getKey(AGREEMENT_ALIAS, null) as? PrivateKey
            ?: throw AndroidMasterKeyException("Master key-agreement key is unavailable.")
        val peer = AndroidP256Encoding.parseSubjectPublicKeyInfoPEM(peerPublicKeyPem)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(peer, true)
        val sharedSecret = agreement.generateSecret()
        return try {
            HkdfSha256.derive(sharedSecret, salt, sharedInfo, 32)
        } finally {
            sharedSecret.fill(0)
        }
    }

    private fun createTeeBackedKeyset(
        challenges: AndroidAttestationChallenges,
        strongBoxFailure: StrongBoxUnavailableException
    ): AndroidMasterKeySet {
        val verifier = teeVerifier
            ?: throw AndroidMasterKeyException("TEE fallback is not qualified.", strongBoxFailure)
        val keyStore = loadKeyStore()
        try {
            generateKey(SIGNING_ALIAS, KeyProperties.PURPOSE_SIGN, challenges.signing, strongBox = false)
            generateKey(AGREEMENT_ALIAS, KeyProperties.PURPOSE_AGREE_KEY, challenges.keyAgreement, strongBox = false)
            val result = loadAndValidate(
                keyStore,
                challenges,
                expectedSecurityLevel = KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                verifyTeeAttestation = false
            )
            if (!verifier.verify(result.attestationEvidence)) {
                throw AndroidMasterKeyException("Independent TEE key attestation was not accepted.")
            }
            validatedAssurance = ASSURANCE_TEE
            return result.copy(hardware_assurance = ASSURANCE_TEE)
        } catch (failure: Exception) {
            deleteAliases(keyStore)
            throw failure
        }
    }

    private fun loadAndValidate(
        keyStore: KeyStore,
        challenges: AndroidAttestationChallenges,
        expectedSecurityLevel: Int?,
        verifyTeeAttestation: Boolean = true
    ): AndroidMasterKeySet {
        val signingPrivate = keyStore.getKey(SIGNING_ALIAS, null) as? PrivateKey
            ?: throw AndroidMasterKeyException("Master signing key is missing.")
        val agreementPrivate = keyStore.getKey(AGREEMENT_ALIAS, null) as? PrivateKey
            ?: throw AndroidMasterKeyException("Master key-agreement key is missing.")
        val signingPublic = keyStore.getCertificate(SIGNING_ALIAS)?.publicKey as? ECPublicKey
            ?: throw AndroidMasterKeyException("Master signing public key is missing or malformed.")
        val agreementPublic = keyStore.getCertificate(AGREEMENT_ALIAS)?.publicKey as? ECPublicKey
            ?: throw AndroidMasterKeyException("Master key-agreement public key is missing or malformed.")

        validateP256PublicKey(signingPublic)
        validateP256PublicKey(agreementPublic)
        val signingInfo = keyInfo(signingPrivate)
        val agreementInfo = keyInfo(agreementPrivate)
        validateKeyInfo(signingInfo, KeyProperties.PURPOSE_SIGN)
        validateKeyInfo(agreementInfo, KeyProperties.PURPOSE_AGREE_KEY)

        if (signingInfo.securityLevel != agreementInfo.securityLevel) {
            throw AndroidMasterKeyException("Signing and key-agreement keys have different hardware security levels.")
        }
        if (expectedSecurityLevel != null && signingInfo.securityLevel != expectedSecurityLevel) {
            throw AndroidMasterKeyException("Android Keystore did not provide the requested hardware security level.")
        }

        val assurance = when (signingInfo.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> ASSURANCE_STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> ASSURANCE_TEE
            else -> throw AndroidMasterKeyException("Software or unknown security levels cannot hold master authority.")
        }

        val evidence = attestationEvidence(keyStore, challenges)
        if (assurance == ASSURANCE_TEE && verifyTeeAttestation) {
            val verifier = teeVerifier
                ?: throw AndroidMasterKeyException("TEE-backed master keys require an independent attestation verifier.")
            if (!verifier.verify(evidence)) {
                throw AndroidMasterKeyException("Independent TEE key attestation was not accepted.")
            }
        }

        val signingRaw = AndroidP256Encoding.rawPublicKey(signingPublic)
        val agreementRaw = AndroidP256Encoding.rawPublicKey(agreementPublic)
        if (signingRaw.contentEquals(agreementRaw)) {
            throw AndroidMasterKeyException("Master signing and key-agreement public keys must be distinct.")
        }

        val result = AndroidMasterKeySet(
            signing = AndroidMasterKeyDescriptor(
                kid = AndroidP256Encoding.keyId("master-signing", signingRaw),
                alg = "ES256",
                public_key_pem = AndroidP256Encoding.subjectPublicKeyInfoPEM(signingPublic)
            ),
            key_agreement = AndroidMasterKeyDescriptor(
                kid = AndroidP256Encoding.keyId("master-key-agreement", agreementRaw),
                alg = "ECDH-ES",
                public_key_pem = AndroidP256Encoding.subjectPublicKeyInfoPEM(agreementPublic)
            ),
            hardware_assurance = assurance,
            attestationEvidence = evidence
        )
        if (assurance == ASSURANCE_STRONGBOX || verifyTeeAttestation) {
            validatedAssurance = assurance
        }
        return result
    }

    private fun requireValidatedMasterKeyset() {
        if (validatedAssurance == null) {
            throw AndroidMasterKeyException("Master keys must be hardware-validated before cryptographic use.")
        }
    }

    private fun validateKeyInfo(info: KeyInfo, requiredPurpose: Int) {
        if (info.keySize != 256 || info.purposes != requiredPurpose ||
            info.origin != KeyProperties.ORIGIN_GENERATED) {
            throw AndroidMasterKeyException("Android Keystore key size, origin, or purpose does not match policy.")
        }
        if (requiredPurpose == KeyProperties.PURPOSE_SIGN &&
            !info.digests.contains(KeyProperties.DIGEST_SHA256)) {
            throw AndroidMasterKeyException("Master signing key is not restricted to SHA-256.")
        }
        if (!info.isUserAuthenticationRequired ||
            info.userAuthenticationValidityDurationSeconds != AUTH_VALIDITY_SECONDS ||
            info.userAuthenticationType != AUTH_TYPES ||
            !info.isUserAuthenticationRequirementEnforcedBySecureHardware ||
            !info.isUnlockedDeviceRequired
        ) {
            throw AndroidMasterKeyException("Android Keystore user-authentication policy is not hardware enforced.")
        }
    }

    private fun generateKey(alias: String, purpose: Int, challenge: ByteArray, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, purpose)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(AUTH_VALIDITY_SECONDS, AUTH_TYPES)
            .setUnlockedDeviceRequired(true)
            .setAttestationChallenge(challenge)

        if (purpose == KeyProperties.PURPOSE_SIGN) {
            builder.setDigests(KeyProperties.DIGEST_SHA256)
        }
        builder.setIsStrongBoxBacked(strongBox)

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    private fun keyInfo(privateKey: PrivateKey): KeyInfo {
        val factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        return factory.getKeySpec(privateKey, KeyInfo::class.java)
    }

    private fun attestationEvidence(
        keyStore: KeyStore,
        challenges: AndroidAttestationChallenges
    ): AndroidAttestationEvidence {
        fun chain(alias: String): List<String> {
            val certificates = keyStore.getCertificateChain(alias)
                ?: throw AndroidMasterKeyException("Android Keystore did not return an attestation certificate chain.")
            if (certificates.isEmpty()) {
                throw AndroidMasterKeyException("Android attestation certificate chain is empty.")
            }
            return certificates.map {
                Base64.getEncoder().encodeToString(it.encoded)
            }
        }

        return AndroidAttestationEvidence(
            packageName = appContext.packageName,
            signingChallengeBase64 = Base64.getEncoder().encodeToString(challenges.signing),
            agreementChallengeBase64 = Base64.getEncoder().encodeToString(challenges.keyAgreement),
            signingCertificateChainDerBase64 = chain(SIGNING_ALIAS),
            agreementCertificateChainDerBase64 = chain(AGREEMENT_ALIAS)
        )
    }

    private fun validateP256PublicKey(key: ECPublicKey) {
        if (key.params.curve.field.fieldSize != 256 || key.params.order != P256_ORDER) {
            throw AndroidMasterKeyException("Android Keystore public key is not NIST P-256.")
        }
    }

    private fun requireSupportedApi() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw AndroidMasterKeyException("Android master authority requires API 31 or later in this implementation.")
        }
    }

    private fun loadKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    private fun deleteAliases(keyStore: KeyStore) {
        if (keyStore.containsAlias(SIGNING_ALIAS)) keyStore.deleteEntry(SIGNING_ALIAS)
        if (keyStore.containsAlias(AGREEMENT_ALIAS)) keyStore.deleteEntry(AGREEMENT_ALIAS)
    }
}

object AndroidP256Encoding {
    fun rawPublicKey(key: ECPublicKey): ByteArray {
        fun fixed32(value: BigInteger): ByteArray {
            val encoded = value.toByteArray()
            val magnitude = if (encoded.size == 33 && encoded[0] == 0.toByte()) {
                encoded.copyOfRange(1, encoded.size)
            } else {
                encoded
            }
            require(magnitude.size <= 32) { "P-256 coordinate exceeds 32 bytes." }
            return ByteArray(32 - magnitude.size) + magnitude
        }
        return fixed32(key.w.affineX) + fixed32(key.w.affineY)
    }

    fun keyId(prefix: String, rawPublicKey: ByteArray): String {
        require(rawPublicKey.size == 64)
        val digest = MessageDigest.getInstance("SHA-256").digest(rawPublicKey)
        val hex = digest.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        return prefix + "-" + hex
    }

    fun subjectPublicKeyInfoPEM(key: ECPublicKey): String {
        val encoded = key.encoded ?: throw IllegalArgumentException("P-256 public key has no SPKI encoding.")
        val body = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(encoded)
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"
    }

    fun parseSubjectPublicKeyInfoPEM(pem: String): ECPublicKey {
        require(pem.startsWith("-----BEGIN PUBLIC KEY-----") && pem.trimEnd().endsWith("-----END PUBLIC KEY-----")) {
            "Peer key must use SubjectPublicKeyInfo PEM."
        }
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot { it.isWhitespace() }
        val der = Base64.getDecoder().decode(body)
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as? ECPublicKey
            ?: throw IllegalArgumentException("Peer key is not an EC public key.")
        if (key.params.curve.field.fieldSize != 256 || key.params.order != P256_ORDER) {
            throw IllegalArgumentException("Peer key must use NIST P-256.")
        }
        return key
    }

    private val P256_ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
}

object Es256SignatureEncoding {
    private val order = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    private val halfOrder = hex("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8")

    fun derToJoseLowS(der: ByteArray): ByteArray {
        var offset = 0
        require(readByte(der, offset++) == 0x30) { "ECDSA signature is not a DER sequence." }
        val sequenceLength = readByte(der, offset++)
        require(sequenceLength == der.size - offset) { "ECDSA DER sequence length is invalid." }
        require(readByte(der, offset++) == 0x02) { "ECDSA R integer is missing." }
        val rLength = readByte(der, offset++)
        val r = der.copyOfRange(offset, offset + rLength)
        offset += rLength
        require(readByte(der, offset++) == 0x02) { "ECDSA S integer is missing." }
        val sLength = readByte(der, offset++)
        val s = der.copyOfRange(offset, offset + sLength)
        offset += sLength
        require(offset == der.size) { "ECDSA DER signature has trailing data." }
        return normalizeJoseLowS(fixed32(r) + fixed32(s))
    }

    fun normalizeJoseLowS(raw: ByteArray): ByteArray {
        require(raw.size == 64) { "ES256 JOSE signature must be 64 bytes." }
        val r = raw.copyOfRange(0, 32)
        val s = raw.copyOfRange(32, 64)
        val zero = ByteArray(32)
        require(!r.contentEquals(zero) && compare(r, order) < 0) { "ECDSA R is out of range." }
        require(!s.contentEquals(zero) && compare(s, order) < 0) { "ECDSA S is out of range." }
        val canonicalS = if (compare(s, halfOrder) > 0) subtract(order, s) else s
        return r + canonicalS
    }

    private fun readByte(input: ByteArray, index: Int): Int {
        require(index < input.size) { "ECDSA DER signature is truncated." }
        return input[index].toInt() and 0xff
    }

    private fun fixed32(integer: ByteArray): ByteArray {
        require(integer.isNotEmpty()) { "ECDSA integer is empty." }
        require((integer[0].toInt() and 0x80) == 0) { "ECDSA DER integer must be positive." }
        if (integer.size > 1 && integer[0] == 0.toByte()) {
            require((integer[1].toInt() and 0x80) != 0) { "ECDSA DER integer has redundant sign padding." }
        }
        var start = 0
        while (start < integer.size - 1 && integer[start] == 0.toByte()) start++
        val magnitude = integer.copyOfRange(start, integer.size)
        require(magnitude.size <= 32) { "ECDSA integer exceeds P-256 size." }
        return ByteArray(32 - magnitude.size) + magnitude
    }

    private fun compare(left: ByteArray, right: ByteArray): Int {
        for (index in left.indices) {
            val a = left[index].toInt() and 0xff
            val b = right[index].toInt() and 0xff
            if (a != b) return a.compareTo(b)
        }
        return 0
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

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

object HkdfSha256 {
    fun derive(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        require(outputLength in 1..(255 * 32))
        val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        val pseudorandomKey = extract.doFinal(inputKeyMaterial)

        val expand = Mac.getInstance("HmacSHA256")
        val output = ByteArrayOutputStream()
        var previous = ByteArray(0)
        var counter = 1
        while (output.size() < outputLength) {
            expand.init(SecretKeySpec(pseudorandomKey, "HmacSHA256"))
            expand.update(previous)
            expand.update(info)
            expand.update(counter.toByte())
            previous = expand.doFinal()
            output.write(previous)
            counter++
        }
        pseudorandomKey.fill(0)
        previous.fill(0)
        return output.toByteArray().copyOf(outputLength)
    }
}
