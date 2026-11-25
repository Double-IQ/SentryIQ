package co.bichet.sentryiq.master

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object TrustRegistryAnchorPolicy {
    fun isFresh(issuedAt: Long, expiresAt: Long, now: Long): Boolean {
        if (issuedAt <= 0 || expiresAt <= now || expiresAt <= issuedAt) return false
        if (issuedAt > now && issuedAt - now > 60L) return false
        if (now > issuedAt && now - issuedAt > 86_400L) return false
        return expiresAt - issuedAt <= 86_400L
    }
}

/**
 * Device-local encrypted cache for the currently accepted public trust bundle.
 *
 * This file is NOT an anti-rollback anchor. Every read/write requires a freshly
 * verified signed registry anchor supplied by the caller. The verifier must
 * authenticate the anchor using the separately pinned registry key and enforce
 * its sequence/previous-digest chain before returning true.
 */
class ProtectedTrustStateStore(
    context: Context,
    private val verifyRegistryAnchor: (RegistryAnchor) -> Boolean
) {
    data class RegistryAnchor(
        val sequence: Long,
        val bundleSha256: ByteArray,
        val signedPayload: ByteArray,
        val signature: ByteArray,
        val issuedAt: Long,
        val expiresAt: Long,
        val previousBundleSha256: ByteArray?
    )

    data class TrustState(val sequence: Long, val bundleSha256: ByteArray, val bundle: ByteArray)

    class StateException(message: String) : Exception(message)

    private val file = File(context.noBackupFilesDir, "sentryiq-trust-state-v1.bin")
    private val keyAlias = "co.bichet.sentryiq.trust-state-aes-gcm.v1"

    fun load(
        anchor: RegistryAnchor,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ): TrustState = synchronized(processLock) {
        requireValidAnchor(anchor, nowEpochSeconds)
        if (!file.exists()) throw StateException("No protected trust state exists; bootstrap is required.")
        if (file.length() !in 1..MAX_ENCODED_STATE_BYTES.toLong()) {
            throw StateException("Stored trust state exceeds the permitted size.")
        }
        val state = decrypt(file.readBytes())
        if (state.sequence != anchor.sequence ||
            !MessageDigest.isEqual(state.bundleSha256, anchor.bundleSha256) ||
            !MessageDigest.isEqual(sha256(state.bundle), anchor.bundleSha256)) {
            throw StateException("Stored trust state does not match the verified registry anchor.")
        }
        state
    }

    fun save(
        bundle: ByteArray,
        anchor: RegistryAnchor,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ) = synchronized(lock) {
        requireValidAnchor(anchor, nowEpochSeconds)
        val digest = sha256(bundle)
        if (!MessageDigest.isEqual(digest, anchor.bundleSha256)) {
            throw StateException("Bundle digest does not match the verified registry anchor.")
        }
        if (file.exists()) {
            if (file.length() !in 1..MAX_ENCODED_STATE_BYTES.toLong()) {
                throw StateException("Stored trust state exceeds the permitted size.")
            }
            val current = decrypt(file.readBytes())
            if (anchor.sequence < current.sequence ||
                (anchor.sequence == current.sequence &&
                    !MessageDigest.isEqual(anchor.bundleSha256, current.bundleSha256))) {
                throw StateException("Trust-state rollback or same-sequence substitution detected.")
            }
            if (anchor.sequence > current.sequence) {
                if (current.sequence == Long.MAX_VALUE ||
                    anchor.sequence != current.sequence + 1 ||
                    anchor.previousBundleSha256 == null ||
                    !MessageDigest.isEqual(anchor.previousBundleSha256, current.bundleSha256)) {
                    throw StateException("Registry anchor skips or breaks the trusted sequence chain.")
                }
            }
        }
        val encoded = encrypt(TrustState(anchor.sequence, digest, bundle))
        val temporary = File(file.parentFile, file.name + ".tmp")
        FileOutputStream(temporary).use { stream ->
            stream.write(encoded)
            stream.fd.sync()
        }
        try {
            Files.move(
                temporary.toPath(),
                file.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } catch (error: Exception) {
            temporary.delete()
            throw StateException("Could not atomically persist trust state.")
        }

        // A successful rename is not enough: decrypt and compare the committed
        // record before reporting that the protected state transition succeeded.
        val committed = try {
            decrypt(file.readBytes())
        } catch (_: Exception) {
            throw StateException("Committed trust state could not be read back.")
        }
        if (committed.sequence != anchor.sequence ||
            !MessageDigest.isEqual(committed.bundleSha256, digest) ||
            !MessageDigest.isEqual(committed.bundle, bundle) ||
            !MessageDigest.isEqual(sha256(committed.bundle), anchor.bundleSha256)) {
            throw StateException("Committed trust state failed readback verification.")
        }
    }

    private fun requireValidAnchor(anchor: RegistryAnchor, now: Long) {
        if (anchor.sequence < 1 || anchor.bundleSha256.size != 32 ||
            anchor.signedPayload.isEmpty() || anchor.signature.isEmpty() ||
            !TrustRegistryAnchorPolicy.isFresh(anchor.issuedAt, anchor.expiresAt, now) ||
            (anchor.previousBundleSha256 != null && anchor.previousBundleSha256.size != 32) ||
            !verifyRegistryAnchor(anchor)) {
            throw StateException("Registry anchor is missing, stale, or invalid.")
        }
    }

    private fun encrypt(state: TrustState): ByteArray {
        val nonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey(), GCMParameterSpec(128, nonce))
        cipher.updateAAD(MAGIC)
        val ciphertext = cipher.doFinal(encodeState(state))
        return ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(MAGIC)
                out.writeByte(nonce.size)
                out.write(nonce)
                out.writeInt(ciphertext.size)
                out.write(ciphertext)
            }
        }.toByteArray()
    }

    private fun decrypt(encoded: ByteArray): TrustState {
        try {
            val input = DataInputStream(ByteArrayInputStream(encoded))
            val magic = ByteArray(MAGIC.size).also(input::readFully)
            if (!magic.contentEquals(MAGIC)) throw StateException("Unknown trust-state format.")
            val nonceLength = input.readUnsignedByte()
            if (nonceLength != 12) throw StateException("Invalid trust-state nonce.")
            val nonce = ByteArray(nonceLength).also(input::readFully)
            val length = input.readInt()
            if (length !in 16..(4 * 1024 * 1024) || length != input.available()) {
                throw StateException("Invalid trust-state ciphertext length.")
            }
            val ciphertext = ByteArray(length).also(input::readFully)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, nonce))
            cipher.updateAAD(MAGIC)
            return decodeState(cipher.doFinal(ciphertext))
        } catch (error: StateException) {
            throw error
        } catch (error: Exception) {
            throw StateException("Trust state is corrupt, unavailable, or unauthenticated.")
        }
    }

    private fun encodeState(state: TrustState): ByteArray =
        ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { out ->
                out.writeLong(state.sequence)
                out.write(state.bundleSha256)
                out.writeInt(state.bundle.size)
                out.write(state.bundle)
            }
        }.toByteArray()

    private fun decodeState(bytes: ByteArray): TrustState {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val sequence = input.readLong()
        val digest = ByteArray(32).also(input::readFully)
        val length = input.readInt()
        if (sequence < 1 || length !in 1..(4 * 1024 * 1024) || length != input.available()) {
            throw StateException("Invalid trust-state payload.")
        }
        val bundle = ByteArray(length).also(input::readFully)
        return TrustState(sequence, digest, bundle)
    }

    private fun secretKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    companion object {
        // Shared by all store instances in this process so concurrent callers
        // cannot race the read/validate/atomic-replace sequence.
        private val processLock = Any()
        private const val MAX_ENCODED_STATE_BYTES = 4 * 1024 * 1024 + 128
        private val MAGIC = byteArrayOf(0x53, 0x49, 0x51, 0x54, 0x53, 0x01)
    }
}
