package co.bichet.sentryiq.master

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypted atomic content-addressed storage for bytes already accepted by the Rust TUF verifier. */
class VerifiedTargetStore(
    context: Context,
    private val keyAlias: String = "co.bichet.sentryiq.verified-targets.v1"
) {
    class StoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val directory = File(context.noBackupFilesDir, "verified-targets")
    private val maximumTargetBytes = 16 * 1024 * 1024
    private val magic = "SIQVT1".toByteArray(Charsets.US_ASCII)

    init {
        if (!directory.exists() && !directory.mkdirs()) throw StoreException("Unable to create verified target directory.")
        directory.setReadable(false, false)
        directory.setWritable(false, false)
        directory.setExecutable(false, false)
        directory.setReadable(true, true)
        directory.setWritable(true, true)
        directory.setExecutable(true, true)
        if (!directory.isDirectory || directory.canonicalFile != directory.absoluteFile) {
            throw StoreException("Verified target directory is unsafe.")
        }
    }

    @Synchronized
    fun saveVerifiedTarget(path: String, bytes: ByteArray): String {
        validatePath(path)
        if (bytes.isEmpty() || bytes.size > maximumTargetBytes) throw StoreException("Target size is invalid.")
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, loadOrCreateKey())
        cipher.updateAAD(associatedData(path, digest))
        val ciphertext = cipher.doFinal(bytes)
        val iv = cipher.iv
        if (iv.size != 12) throw StoreException("Unexpected AES-GCM nonce size.")
        val record = ByteBuffer.allocate(magic.size + digest.size + iv.size + ciphertext.size)
            .put(magic).put(digest).put(iv).put(ciphertext).array()
        val destination = targetFile(path)
        val temporary = File.createTempFile("target-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { stream ->
                stream.write(record)
                stream.fd.sync()
            }
            java.nio.file.Files.move(
                temporary.toPath(),
                destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
            try {
                FileChannel.open(directory.toPath(), java.nio.file.StandardOpenOption.READ).use { it.force(true) }
            } catch (_: Exception) { /* Directory fsync is unavailable on some Android filesystems. */ }
        } catch (error: Exception) {
            temporary.delete()
            throw StoreException("Unable to atomically commit verified target.", error)
        }
        if (!loadVerifiedTarget(path).contentEquals(bytes)) throw StoreException("Verified target readback failed.")
        return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    @Synchronized
    fun loadVerifiedTarget(path: String): ByteArray {
        validatePath(path)
        val file = targetFile(path)
        if (!file.isFile || file.isSymbolicLinkCompat() || file.length() !in (magic.size + 32 + 12 + 16).toLong()..(maximumTargetBytes + magic.size + 32 + 12 + 16).toLong()) {
            throw StoreException("Verified target record is missing or malformed.")
        }
        val record = file.readBytes()
        val minimum = magic.size + 32 + 12 + 16
        if (record.size < minimum || !record.copyOfRange(0, magic.size).contentEquals(magic)) {
            throw StoreException("Verified target record header is invalid.")
        }
        val digest = record.copyOfRange(magic.size, magic.size + 32)
        val iv = record.copyOfRange(magic.size + 32, magic.size + 44)
        val ciphertext = record.copyOfRange(magic.size + 44, record.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, loadOrCreateKey(), GCMParameterSpec(128, iv))
        cipher.updateAAD(associatedData(path, digest))
        val plaintext = try { cipher.doFinal(ciphertext) }
            catch (error: Exception) { throw StoreException("Verified target authentication failed.", error) }
        if (!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(plaintext), digest)) {
            throw StoreException("Verified target digest mismatch.")
        }
        return plaintext
    }

    private fun validatePath(path: String) {
        if (!path.matches(Regex("^[A-Za-z0-9._/-]{1,512}$")) || path.contains("//") ||
            path.split('/').any { it == "." || it == ".." }) {
            throw StoreException("TUF target path is invalid.")
        }
    }

    private fun targetFile(path: String): File {
        val name = MessageDigest.getInstance("SHA-256").digest(path.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) } + ".target"
        return File(directory, name)
    }

    private fun associatedData(path: String, digest: ByteArray): ByteArray =
        "SENTRYIQ-VERIFIED-TARGET-V1\n".toByteArray(Charsets.UTF_8) +
            path.toByteArray(Charsets.UTF_8) + byteArrayOf(0) + digest

    private fun loadOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun File.isSymbolicLinkCompat(): Boolean =
        java.nio.file.Files.isSymbolicLink(toPath())
}
