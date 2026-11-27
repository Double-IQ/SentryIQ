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
    fun isValidInitialAnchor(sequence: ULong, previousBundleSha256: ByteArray?): Boolean =
        sequence == 1uL && previousBundleSha256 == null

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
    private val expectedOwnerId: String,
    private val trustedSignerKeys: List<RegistryAnchorSignerKey>
) {
    data class RegistryAnchor(
        val sequence: ULong,
        val bundleSha256: ByteArray,
        val signedPayload: ByteArray,
        val signature: ByteArray,
        val issuedAt: Long,
        val expiresAt: Long,
        val previousBundleSha256: ByteArray?,
        val ownerId: String,
        val signerKeyId: String
    )

    data class TrustState(val sequence: ULong, val bundleSha256: ByteArray, val bundle: ByteArray, val tufMetadata: Map<String, ByteArray> = emptyMap(), val bootstrapReceiptId: String? = null)

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

    /** Load only the exact current state or immediate predecessor of a verified new anchor. */
    fun loadPreviousState(
        anchor: RegistryAnchor,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ): TrustState? = synchronized(processLock) {
        requireValidAnchor(anchor, nowEpochSeconds)
        if (!file.exists()) {
            if (!TrustRegistryAnchorPolicy.isValidInitialAnchor(anchor.sequence, anchor.previousBundleSha256)) {
                throw StateException("No cached predecessor exists for this registry anchor.")
            }
            return@synchronized null
        }
        if (file.length() !in 1..MAX_ENCODED_STATE_BYTES.toLong()) {
            throw StateException("Stored trust state exceeds the permitted size.")
        }
        val current = decrypt(file.readBytes())
        if (!MessageDigest.isEqual(sha256(current.bundle), current.bundleSha256)) {
            throw StateException("Cached trust state digest is corrupt.")
        }
        val same = anchor.sequence == current.sequence &&
            MessageDigest.isEqual(anchor.bundleSha256, current.bundleSha256)
        val next = current.sequence < ULong.MAX_VALUE &&
            anchor.sequence == current.sequence + 1uL &&
            anchor.previousBundleSha256 != null &&
            MessageDigest.isEqual(anchor.previousBundleSha256, current.bundleSha256)
        if (!same && !next) throw StateException("Registry anchor is not current or the immediate successor.")
        current
    }

    fun save(
        bundle: ByteArray,
        anchor: RegistryAnchor,
        tufMetadata: Map<String, ByteArray> = emptyMap(),
        bootstrapReceiptId: String? = null,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ) = synchronized(processLock) {
        requireValidAnchor(anchor, nowEpochSeconds)
        if (bundle.isEmpty() || bundle.size > MAX_BUNDLE_BYTES) throw StateException("Trust bundle exceeds the permitted size.")
        validateTufMetadata(tufMetadata)
        if (bootstrapReceiptId != null && !bootstrapReceiptId.matches(Regex("^[a-f0-9]{32}$"))) {
            throw StateException("Bootstrap receipt identifier is invalid.")
        }
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
                if (current.sequence == ULong.MAX_VALUE ||
                    anchor.sequence != current.sequence + 1uL ||
                    anchor.previousBundleSha256 == null ||
                    !MessageDigest.isEqual(anchor.previousBundleSha256, current.bundleSha256)) {
                    throw StateException("Registry anchor skips or breaks the trusted sequence chain.")
                }
            }
        } else if (!TrustRegistryAnchorPolicy.isValidInitialAnchor(
                anchor.sequence,
                anchor.previousBundleSha256
            )) {
            throw StateException("Initial registry anchor must start at sequence one with no previous digest.")
        }
        val encoded = encrypt(TrustState(anchor.sequence, digest, bundle, tufMetadata, bootstrapReceiptId))
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
            !metadataEquals(committed.tufMetadata, tufMetadata) ||
            committed.bootstrapReceiptId != bootstrapReceiptId ||
            !MessageDigest.isEqual(sha256(committed.bundle), anchor.bundleSha256)) {
            throw StateException("Committed trust state failed readback verification.")
        }
    }

    private fun requireValidAnchor(anchor: RegistryAnchor, now: Long) {
        if (anchor.sequence < 1uL || anchor.bundleSha256.size != 32 ||
            anchor.signedPayload.isEmpty() || anchor.signature.isEmpty() ||
            !TrustRegistryAnchorPolicy.isFresh(anchor.issuedAt, anchor.expiresAt, now) ||
            (anchor.previousBundleSha256 != null && anchor.previousBundleSha256.size != 32)) {
            throw StateException("Registry anchor is missing, stale, or invalid.")
        }
        try {
            RegistryAnchorVerifier.verify(anchor, expectedOwnerId, trustedSignerKeys, now)
        } catch (_: Exception) {
            throw StateException("Registry anchor signature or independent pin validation failed.")
        }
    }

    private fun validateTufMetadata(metadata: Map<String, ByteArray>) {
        if (metadata.size > 64) throw StateException("Too many TUF metadata objects.")
        var total = 0
        metadata.forEach { (name, bytes) ->
            if (!name.matches(Regex("^[a-z0-9][a-z0-9._/-]{0,127}$")) ||
                bytes.isEmpty() || bytes.size > 1_048_576) {
                throw StateException("TUF metadata object name or size is invalid.")
            }
            total += bytes.size
            if (total > 3 * 1024 * 1024) throw StateException("TUF metadata exceeds the storage limit.")
        }
    }

    private fun metadataEquals(left: Map<String, ByteArray>, right: Map<String, ByteArray>): Boolean {
        if (left.keys != right.keys) return false
        return left.all { (name, bytes) -> right[name]?.let { MessageDigest.isEqual(bytes, it) } == true }
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
                out.writeLong(state.sequence.toLong())
                out.write(state.bundleSha256)
                out.writeInt(state.bundle.size)
                out.write(state.bundle)
                out.writeInt(state.tufMetadata.size)
                state.tufMetadata.toSortedMap().forEach { (name, value) ->
                    val nameBytes = name.toByteArray(Charsets.UTF_8)
                    out.writeInt(nameBytes.size); out.write(nameBytes)
                    out.writeInt(value.size); out.write(value)
                }
                out.writeBoolean(state.bootstrapReceiptId != null)
                state.bootstrapReceiptId?.let { receipt ->
                    val receiptBytes = receipt.toByteArray(Charsets.US_ASCII)
                    out.writeInt(receiptBytes.size); out.write(receiptBytes)
                }
            }
        }.toByteArray()

    private fun decodeState(bytes: ByteArray): TrustState {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val sequence = input.readLong().toULong()
        val digest = ByteArray(32).also(input::readFully)
        val length = input.readInt()
        if (sequence < 1uL || length !in 1..(4 * 1024 * 1024) || length != input.available()) {
            throw StateException("Invalid trust-state payload.")
        }
        val bundle = ByteArray(length).also(input::readFully)
        val metadata = linkedMapOf<String, ByteArray>()
        var receiptId: String? = null
        if (input.available() > 0) {
            val count = input.readInt()
            if (count !in 0..64) throw StateException("Invalid TUF metadata count.")
            var total = 0
            repeat(count) {
                val nameLength = input.readInt()
                if (nameLength !in 1..128 || nameLength > input.available()) throw StateException("Invalid TUF metadata name.")
                val name = ByteArray(nameLength).also(input::readFully).toString(Charsets.UTF_8)
                val valueLength = input.readInt()
                if (valueLength !in 1..1_048_576 || valueLength > input.available()) throw StateException("Invalid TUF metadata length.")
                val value = ByteArray(valueLength).also(input::readFully)
                total += valueLength
                if (total > 3 * 1024 * 1024 || metadata.put(name, value) != null) {
                    throw StateException("TUF metadata is duplicated or exceeds limits.")
                }
            }
            if (input.available() > 0) {
                val hasReceipt = input.readBoolean()
                if (hasReceipt) {
                    val receiptLength = input.readInt()
                    if (receiptLength != 32 || receiptLength > input.available()) throw StateException("Invalid bootstrap receipt identifier.")
                    receiptId = ByteArray(receiptLength).also(input::readFully).toString(Charsets.US_ASCII)
                    if (!receiptId.matches(Regex("^[a-f0-9]{32}$"))) throw StateException("Malformed bootstrap receipt identifier.")
                }
            }
            if (input.available() != 0) throw StateException("Trailing trust-state bytes.")
        }
        return TrustState(sequence, digest, bundle, metadata, receiptId)
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
        private const val MAX_BUNDLE_BYTES = 262_144
        private val MAGIC = byteArrayOf(0x53, 0x49, 0x51, 0x54, 0x53, 0x01)
    }
}
