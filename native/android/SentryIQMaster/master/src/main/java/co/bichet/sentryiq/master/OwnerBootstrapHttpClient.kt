package co.bichet.sentryiq.master

import android.util.Base64
import org.json.JSONObject
import java.net.CookieManager
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/**
 * Same-origin transport for the authenticated bootstrap endpoint.
 * Returned bytes remain untrusted until independently pinned registry/bundle
 * signatures and the TUF chain have been verified by the caller.
 */
class OwnerBootstrapHttpClient(
    baseUrl: URL,
    private val cookies: CookieManager,
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 20_000
) {
    data class Snapshot(
        val ownerId: String,
        val sequence: String,
        val bundleSha256: String,
        val canonicalBundle: ByteArray,
        val registryAnchorPayload: ByteArray,
        val registryAnchorSignature: ByteArray,
        val csrfToken: String
    )

    data class Challenge(
        val value: String,
        val purpose: String,
        val bundleSha256: String,
        val expiresAt: Long
    )

    data class ApprovalProof(
        val challenge: String,
        val bundleSha256: String,
        val rootRole: String,
        val rootKeyId: String,
        val rootFingerprint: String,
        val deviceKeysetDigest: String,
        val purpose: String,
        val signature: ByteArray
    )

    data class Receipt(val receiptId: String)

    class ClientException(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val endpoint: URL

    init {
        require(baseUrl.protocol.equals("https", ignoreCase = true))
        require(baseUrl.userInfo == null && baseUrl.query == null && baseUrl.ref == null)
        endpoint = URL(baseUrl.toString().trimEnd('/') + "/api/owner-bootstrap.php")
    }

    fun fetchSnapshot(): Snapshot {
        val json = request("GET", null, null)
        if (json.getString("protocol") != "SENTRYIQ-OWNER-BOOTSTRAP-API-V1") {
            throw ClientException("Bootstrap protocol version is unsupported.")
        }
        val bundle = decodeBase64Url(json.getString("bundle"))
        val anchor = decodeBase64Url(json.getString("registry_anchor_payload"))
        val signature = decodeBase64Url(json.getString("registry_anchor_signature"))
        val digest = json.getString("bundle_sha256")
        if (bundle.size > 262_144 || anchor.size > 4_096 || signature.size != 64 ||
            !digest.matches(Regex("^[a-f0-9]{64}$"))) {
            throw ClientException("Bootstrap snapshot response is malformed.")
        }
        return Snapshot(
            json.getString("owner_id"),
            json.getString("sequence"),
            digest,
            bundle,
            anchor,
            signature,
            json.getString("csrf_token")
        )
    }

    /** Fetch, verify the separately pinned registry anchor, validate TUF, then persist atomically. */
    fun fetchAndPersistSnapshot(
        store: ProtectedTrustStateStore,
        verifyTuf: (Snapshot) -> Unit
    ): ProtectedTrustStateStore.TrustState {
        val snapshot = fetchSnapshot()
        val anchor = decodeAnchor(snapshot)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(snapshot.canonicalBundle)
        val digestHex = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (!MessageDigest.isEqual(digest, anchor.bundleSha256) ||
            digestHex != snapshot.bundleSha256 || anchor.sequence.toString() != snapshot.sequence) {
            throw ClientException("Canonical bundle, sequence, and signed registry anchor do not agree.")
        }
        verifyTuf(snapshot)
        store.save(snapshot.canonicalBundle, anchor)
        return store.load(anchor)
    }

    private fun decodeAnchor(snapshot: Snapshot): ProtectedTrustStateStore.RegistryAnchor {
        val json = try { JSONObject(snapshot.registryAnchorPayload.toString(Charsets.UTF_8)) }
        catch (error: Exception) { throw ClientException("Signed registry anchor is invalid JSON.", error) }
        val sequenceText = json.optString("sequence")
        val sequence = sequenceText.toULongOrNull()
            ?: throw ClientException("Registry anchor sequence is invalid.")
        val bundleDigest = decodeHex(json.optString("bundle_sha256"))
        val issuedAt = exactUnsignedLong(json, "issued_at")
        val expiresAt = exactUnsignedLong(json, "expires_at")
        val ownerId = json.optString("owner_id")
        val signerKeyId = json.optString("signer_kid")
        val previousValue = json.opt("previous_bundle_sha256")
        val previous = if (previousValue == null || previousValue === JSONObject.NULL) null
            else decodeHex(previousValue as? String ?: throw ClientException("Previous bundle digest is invalid."))
        if (ownerId != snapshot.ownerId || bundleDigest.size != 32 ||
            (previous != null && previous.size != 32)) {
            throw ClientException("Registry anchor fields do not match the bootstrap snapshot.")
        }
        return ProtectedTrustStateStore.RegistryAnchor(
            sequence,
            bundleDigest,
            snapshot.registryAnchorPayload,
            snapshot.registryAnchorSignature,
            issuedAt,
            expiresAt,
            previous,
            ownerId,
            signerKeyId
        )
    }

    private fun exactUnsignedLong(json: JSONObject, key: String): Long {
        val value = json.opt(key)
        if (value !is Number) throw ClientException("Registry anchor $key is not an integer.")
        val double = value.toDouble()
        if (double < 0 || double % 1.0 != 0.0 || double > Long.MAX_VALUE.toDouble()) {
            throw ClientException("Registry anchor $key is out of range.")
        }
        return value.toLong()
    }

    private fun decodeHex(value: String): ByteArray {
        if (!value.matches(Regex("^[a-f0-9]{64}$"))) throw ClientException("Registry anchor digest is malformed.")
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    fun issueChallenge(csrfToken: String): Challenge {
        val json = request("POST", JSONObject().put("action", "challenge"), csrfToken)
        val challenge = json.getString("challenge")
        if (!challenge.matches(Regex("^[A-Za-z0-9_-]{43}$"))) {
            throw ClientException("Bootstrap challenge encoding is invalid.")
        }
        val purpose = json.getString("purpose")
        if (purpose != "bootstrap-release-root") throw ClientException("Bootstrap challenge purpose is invalid.")
        return Challenge(
            challenge,
            purpose,
            json.getString("bundle_sha256"),
            json.getLong("expires_at")
        )
    }

    fun submitApproval(proof: ApprovalProof, csrfToken: String): Receipt {
        val body = JSONObject()
            .put("action", "approve")
            .put("challenge", proof.challenge)
            .put("bundle_sha256", proof.bundleSha256)
            .put("root_role", proof.rootRole)
            .put("root_key_id", proof.rootKeyId)
            .put("root_fingerprint", proof.rootFingerprint)
            .put("device_keyset_digest", proof.deviceKeysetDigest)
            .put("purpose", proof.purpose)
            .put("signature", encodeBase64Url(proof.signature))
        val receipt = request("POST", body, csrfToken).getString("receipt_id")
        if (!receipt.matches(Regex("^[a-f0-9]{32}$"))) {
            throw ClientException("Bootstrap receipt identifier is malformed.")
        }
        return Receipt(receipt)
    }

    private fun request(method: String, body: JSONObject?, csrfToken: String?): JSONObject {
        val connection = (endpoint.openConnection() as? HttpsURLConnection)
            ?: throw ClientException("Bootstrap endpoint must use HTTPS.")
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.setRequestProperty("Accept", "application/json")
            cookies.get(URI(endpoint.toString()), emptyMap()).forEach { (name, values) ->
                values.forEach { value -> connection.addRequestProperty(name, value) }
            }
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                if (csrfToken.isNullOrBlank()) throw ClientException("Authenticated CSRF token is required.")
                connection.setRequestProperty("X-CSRF-TOKEN", csrfToken)
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val finalUrl = connection.url
            if (!finalUrl.protocol.equals("https", true) || finalUrl.host != endpoint.host ||
                finalUrl.port != endpoint.port || finalUrl.path != endpoint.path) {
                throw ClientException("Bootstrap endpoint redirected outside the authenticated origin.")
            }
            val responseHeaders = mutableMapOf<String, List<String>>()
            connection.headerFields.forEach { (name, values) ->
                if (name != null && values != null) responseHeaders[name] = values
            }
            cookies.put(URI(endpoint.toString()), responseHeaders)
            if (status != 200) throw ClientException("Bootstrap endpoint returned HTTP $status.")
            val contentType = connection.contentType ?: ""
            if (!contentType.lowercase().startsWith("application/json")) {
                throw ClientException("Bootstrap endpoint did not return JSON.")
            }
            val bytes = connection.inputStream.use { it.readBytes() }
            if (bytes.size > 300_000) throw ClientException("Bootstrap response exceeds the size limit.")
            return JSONObject(bytes.toString(Charsets.UTF_8))
        } catch (error: ClientException) {
            throw error
        } catch (error: Exception) {
            throw ClientException("Bootstrap transport failed.", error)
        } finally {
            connection.disconnect()
        }
    }

    private fun decodeBase64Url(value: String): ByteArray {
        if (!value.matches(Regex("^[A-Za-z0-9_-]+$"))) {
            throw ClientException("Bootstrap response has invalid base64url.")
        }
        val decoded = try {
            Base64.decode(value, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw ClientException("Bootstrap response has invalid base64url.", error)
        }
        if (encodeBase64Url(decoded) != value) throw ClientException("Bootstrap response has non-canonical base64url.")
        return decoded
    }

    private fun encodeBase64Url(value: ByteArray): String =
        Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
