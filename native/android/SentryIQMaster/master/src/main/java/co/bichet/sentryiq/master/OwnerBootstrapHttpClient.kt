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
        val tufMetadata: Map<String, ByteArray>,
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
    data class PreparedBootstrapState internal constructor(
        val snapshot: Snapshot,
        val anchor: ProtectedTrustStateStore.RegistryAnchor,
        val cachedState: ProtectedTrustStateStore.TrustState?,
        val verifiedTufMetadata: Map<String, ByteArray>
    )
    data class VerifiedBootstrapState internal constructor(
        val snapshot: Snapshot,
        val anchor: ProtectedTrustStateStore.RegistryAnchor,
        val trustState: ProtectedTrustStateStore.TrustState
    )

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
        val metadataJson = json.optJSONObject("tuf_metadata")
            ?: throw ClientException("Bootstrap TUF metadata is missing.")
        if (metadataJson.length() !in 4..64) throw ClientException("Bootstrap TUF metadata count is invalid.")
        val tufMetadata = linkedMapOf<String, ByteArray>()
        var totalMetadataBytes = 0
        val names = metadataJson.keys()
        while (names.hasNext()) {
            val name = names.next()
            if (!name.matches(Regex("^[a-z0-9][a-z0-9._/-]{0,127}$"))) throw ClientException("TUF metadata name is invalid.")
            val bytes = decodeBase64Url(metadataJson.getString(name))
            if (bytes.isEmpty() || bytes.size > 1_048_576) throw ClientException("TUF metadata object size is invalid.")
            totalMetadataBytes += bytes.size
            if (totalMetadataBytes > 3 * 1024 * 1024) throw ClientException("TUF metadata exceeds the response limit.")
            tufMetadata[name] = bytes
        }
        if (!listOf("root.json", "timestamp.json", "snapshot.json", "targets.json").all { it in tufMetadata }) {
            throw ClientException("Required TUF metadata roles are missing.")
        }
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
            tufMetadata,
            json.getString("csrf_token")
        )
    }

    /** Verify the delivered TUF metadata with the shared Rust core and return the exact accepted bytes. */
    fun verifyTufRefresh(
        snapshot: Snapshot,
        cachedState: ProtectedTrustStateStore.TrustState?,
        referenceTimeEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ): Map<String, ByteArray> {
        val bundle = try { JSONObject(snapshot.canonicalBundle.toString(Charsets.UTF_8)) }
            catch (error: Exception) { throw ClientException("Canonical trust bundle is invalid JSON.", error) }
        val tuf = bundle.optJSONObject("sigstore_tuf")
            ?: throw ClientException("Trust bundle TUF pin is missing.")
        val rootDigest = decodeHex(tuf.optString("root_digest"))
        val initialRoot = snapshot.tufMetadata["root.json"]
            ?: throw ClientException("Initial TUF root metadata is missing.")
        val candidateNames = snapshot.tufMetadata.keys
            .filter { it.matches(Regex("^root/[0-9]+\\.json$")) }
            .sortedBy { it.removePrefix("root/").removeSuffix(".json").toLongOrNull() ?: Long.MAX_VALUE }
        val candidateRoots = candidateNames.map { snapshot.tufMetadata.getValue(it) }
        val cached = cachedState?.tufMetadata ?: emptyMap()
        val accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot,
            rootDigest,
            candidateRoots,
            cached["timestamp.json"],
            cached["snapshot.json"],
            cached["targets.json"],
            snapshot.tufMetadata["timestamp.json"] ?: throw ClientException("Timestamp metadata is missing."),
            snapshot.tufMetadata["snapshot.json"] ?: throw ClientException("Snapshot metadata is missing."),
            snapshot.tufMetadata["targets.json"] ?: throw ClientException("Targets metadata is missing."),
            referenceTimeEpochSeconds
        )
        if (!accepted) throw ClientException("Rust TUF metadata refresh verification failed.")
        val acceptedMetadata = linkedMapOf(
            "root.json" to initialRoot,
            "timestamp.json" to snapshot.tufMetadata.getValue("timestamp.json"),
            "snapshot.json" to snapshot.tufMetadata.getValue("snapshot.json"),
            "targets.json" to snapshot.tufMetadata.getValue("targets.json")
        )
        candidateNames.forEach { name -> acceptedMetadata[name] = snapshot.tufMetadata.getValue(name) }
        return acceptedMetadata
    }

    /** Verify downloaded target bytes against signed top-level and delegated TUF metadata. */
    fun verifyTargetBytes(
        targetBytes: ByteArray,
        targetPath: String,
        snapshot: Snapshot,
        cachedState: ProtectedTrustStateStore.TrustState?,
        referenceTimeEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ): Boolean {
        val bundle = try { JSONObject(snapshot.canonicalBundle.toString(Charsets.UTF_8)) }
            catch (error: Exception) { throw ClientException("Canonical trust bundle is invalid JSON.", error) }
        val tuf = bundle.optJSONObject("sigstore_tuf")
            ?: throw ClientException("Trust bundle TUF pin is missing.")
        val rootDigest = decodeHex(tuf.optString("root_digest"))
        val initialRoot = snapshot.tufMetadata["root.json"]
            ?: throw ClientException("Initial TUF root metadata is missing.")
        val candidateRoots = snapshot.tufMetadata.keys
            .filter { it.matches(Regex("^root/[0-9]+\\.json$")) }
            .sortedBy { it.removePrefix("root/").removeSuffix(".json").toLongOrNull() ?: Long.MAX_VALUE }
            .map { snapshot.tufMetadata.getValue(it) }
        val roles = snapshot.tufMetadata["delegated-order.json"]?.let {
            try { org.json.JSONArray(it.toString(Charsets.UTF_8)) }
            catch (error: Exception) { throw ClientException("Delegated TUF role order is invalid.", error) }
        }?.let { array -> List(array.length()) { index -> array.getString(index) } } ?: emptyList()
        val delegated = roles.map { role ->
            if (!role.matches(Regex("^[a-zA-Z0-9._-]{1,128}$"))) throw ClientException("Delegated TUF role name is invalid.")
            snapshot.tufMetadata["delegated/$role.json"]
                ?: throw ClientException("Delegated TUF metadata is missing.")
        }
        val cached = cachedState?.tufMetadata ?: emptyMap()
        return SentryIQTufTrustVerifier.verifyTargetBytes(
            initialRoot,
            rootDigest,
            candidateRoots,
            cached["timestamp.json"],
            cached["snapshot.json"],
            cached["targets.json"],
            snapshot.tufMetadata["timestamp.json"] ?: throw ClientException("Timestamp metadata is missing."),
            snapshot.tufMetadata["snapshot.json"] ?: throw ClientException("Snapshot metadata is missing."),
            snapshot.tufMetadata["targets.json"] ?: throw ClientException("Targets metadata is missing."),
            roles,
            delegated,
            targetPath,
            targetBytes,
            referenceTimeEpochSeconds
        )
    }

    /** Fetch, verify the separately pinned registry anchor, validate TUF, then persist atomically. */
    fun fetchAndVerifySnapshot(
        store: ProtectedTrustStateStore,
        verifyTuf: (Snapshot, ProtectedTrustStateStore.TrustState?) -> Map<String, ByteArray>
    ): PreparedBootstrapState {
        val snapshot = fetchSnapshot()
        val anchor = decodeAnchor(snapshot)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(snapshot.canonicalBundle)
        val digestHex = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (!MessageDigest.isEqual(digest, anchor.bundleSha256) ||
            digestHex != snapshot.bundleSha256 || anchor.sequence.toString() != snapshot.sequence) {
            throw ClientException("Canonical bundle, sequence, and signed registry anchor do not agree.")
        }
        val cachedState = store.loadPreviousState(anchor)
        val verifiedMetadata = verifyTuf(snapshot, cachedState)
        if (!listOf("root.json", "timestamp.json", "snapshot.json", "targets.json").all { it in verifiedMetadata } ||
            verifiedMetadata.any { (name, bytes) -> snapshot.tufMetadata[name]?.let { MessageDigest.isEqual(bytes, it) } != true }) {
            throw ClientException("TUF verifier returned metadata different from the downloaded snapshot.")
        }
        return PreparedBootstrapState(snapshot, anchor, cachedState, verifiedMetadata)
    }

    fun fetchAndVerifyTUFState(
        store: ProtectedTrustStateStore
    ): PreparedBootstrapState = fetchAndVerifySnapshot(store) { snapshot, cachedState ->
        verifyTufRefresh(snapshot, cachedState)
    }

    /** Persist the candidate only after the server accepts the owner's one-use signature. */
    fun submitApprovalAndPersist(
        proof: ApprovalProof,
        csrfToken: String,
        preparedState: PreparedBootstrapState,
        store: ProtectedTrustStateStore
    ): Pair<Receipt, VerifiedBootstrapState> {
        val receipt = submitApproval(proof, csrfToken)
        store.save(preparedState.snapshot.canonicalBundle, preparedState.anchor, preparedState.verifiedTufMetadata, receipt.receiptId)
        return receipt to VerifiedBootstrapState(
            preparedState.snapshot,
            preparedState.anchor,
            store.load(preparedState.anchor)
        )
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

    fun fetchTarget(path: String): ByteArray {
        if (!path.matches(Regex("^[A-Za-z0-9._/-]{1,512}$")) || path.contains("//") ||
            path.split('/').any { it == "." || it == ".." }) {
            throw ClientException("TUF target path is invalid.")
        }
        val json = request("GET", null, null, targetPath = path, maxResponseBytes = 22_400_000)
        if (json.getString("protocol") != "SENTRYIQ-OWNER-BOOTSTRAP-API-V1" ||
            json.getString("target_path") != path) {
            throw ClientException("TUF target response does not match the request.")
        }
        val target = decodeBase64Url(json.getString("target"))
        if (target.isEmpty() || target.size > 16 * 1024 * 1024) {
            throw ClientException("TUF target exceeds the permitted size.")
        }
        return target
    }

    fun fetchAndVerifyTarget(
        path: String,
        snapshot: Snapshot,
        cachedState: ProtectedTrustStateStore.TrustState?
    ): ByteArray {
        val bytes = fetchTarget(path)
        if (!verifyTargetBytes(bytes, path, snapshot, cachedState)) {
            throw ClientException("Downloaded TUF target failed signed length/hash/delegation verification.")
        }
        return bytes
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

    private fun request(
        method: String,
        body: JSONObject?,
        csrfToken: String?,
        targetPath: String? = null,
        maxResponseBytes: Int = 4_200_000
    ): JSONObject {
        val requestUrl = if (targetPath == null) endpoint else
            URL(endpoint.toString() + "?target=" + java.net.URLEncoder.encode(targetPath, "UTF-8"))
        val connection = (requestUrl.openConnection() as? HttpsURLConnection)
            ?: throw ClientException("Bootstrap endpoint must use HTTPS.")
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.setRequestProperty("Accept", "application/json")
            cookies.get(URI(requestUrl.toString()), emptyMap()).forEach { (name, values) ->
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
            cookies.put(URI(requestUrl.toString()), responseHeaders)
            if (status != 200) throw ClientException("Bootstrap endpoint returned HTTP $status.")
            val contentType = connection.contentType ?: ""
            if (!contentType.lowercase().startsWith("application/json")) {
                throw ClientException("Bootstrap endpoint did not return JSON.")
            }
            val bytes = connection.inputStream.use { it.readBytes() }
            if (bytes.size > maxResponseBytes) throw ClientException("Bootstrap response exceeds the size limit.")
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
