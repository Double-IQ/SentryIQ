package co.bichet.sentryiq.master

import android.app.AlertDialog
import android.text.InputType
import android.widget.EditText
import android.widget.LinearLayout
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

/**
 * Native confirmation + per-use OS authentication for one already-validated trust root.
 * The caller must obtain all display fields and the signed transcript from its
 * independently validated candidate bundle; this UI never treats server labels as trust.
 */
class OwnerFingerprintApprovalPrompt(
    private val keyStore: AndroidKeystoreMasterKeyStore
) {
    data class RootDetails(
        val role: String,
        val keyId: String,
        val algorithm: String,
        val bundleFingerprintSha256: String,
        val fingerprintSha256: String,
        val provenance: String,
        val permittedPurpose: String,
        val forbiddenPurposes: String,
        val expiresAtUtc: String
    )

    fun present(
        activity: FragmentActivity,
        details: RootDetails,
        canonicalBundle: ByteArray,
        ownerIdentifier: String,
        deviceKeysetDigest: String,
        purpose: String,
        challenge: ByteArray,
        expiresAt: Long,
        verifyCandidateTrustChain: (ByteArray, String, String, ByteArray, ByteArray, String) -> Boolean,
        onApproved: (OwnerFingerprintApprovalCeremony.ApprovalProof) -> Unit,
        onCancelled: () -> Unit,
        onError: (Throwable) -> Unit
    ) {
        require(details.role.isNotBlank() && details.keyId.isNotBlank())
        require(details.algorithm == "ES256")
        require(details.bundleFingerprintSha256.matches(Regex("^[a-fA-F0-9]{64}$")))
        require(details.fingerprintSha256.matches(Regex("^[a-fA-F0-9]{64}$")))
        require(details.provenance.isNotBlank() && details.permittedPurpose.isNotBlank())
        val message = listOf(
            "Role: ${details.role}",
            "Key ID: ${details.keyId}",
            "Algorithm: ${details.algorithm}",
            "Trust-bundle SHA-256: ${details.bundleFingerprintSha256.lowercase()}",
            "Root-key SHA-256: ${details.fingerprintSha256.lowercase()}",
            "Source: ${details.provenance}",
            "Permitted purpose: ${details.permittedPurpose}",
            "Forbidden purposes: ${details.forbiddenPurposes}",
            "Expires: ${details.expiresAtUtc}",
            "",
            "Compare this full fingerprint with your independent out-of-band record before continuing."
        ).joinToString("\n")

        val fields = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 8, 48, 0)
        }
        val bundleFingerprintInput = EditText(activity).apply {
            hint = "Enter independent trust-bundle SHA-256"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            isSingleLine = true
        }
        val rootFingerprintInput = EditText(activity).apply {
            hint = "Enter independent root-key SHA-256"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            isSingleLine = true
        }
        fields.addView(bundleFingerprintInput)
        fields.addView(rootFingerprintInput)

        AlertDialog.Builder(activity)
            .setTitle("Review trust-root approval")
            .setMessage(message)
            .setView(fields)
            .setPositiveButton("Confirm fingerprints") { _, _ ->
                val bundleMatch = bundleFingerprintInput.text.toString().trim().equals(details.bundleFingerprintSha256, ignoreCase = true)
                val rootMatch = rootFingerprintInput.text.toString().trim().equals(details.fingerprintSha256, ignoreCase = true)
                if (!bundleMatch || !rootMatch) {
                    onError(IllegalArgumentException("Independent fingerprint confirmation did not match."))
                    return@setPositiveButton
                }
                try {
                    val enteredBundle = bundleFingerprintInput.text.toString().trim()
                    val enteredRoot = rootFingerprintInput.text.toString().trim()
                    val prepared = OwnerFingerprintApprovalCeremony.prepare(
                        canonicalBundle,
                        enteredBundle,
                        ownerIdentifier,
                        details.role,
                        details.keyId,
                        enteredRoot,
                        deviceKeysetDigest,
                        purpose,
                        challenge,
                        expiresAt,
                        { enteredBundle },
                        { enteredRoot },
                        verifyCandidateTrustChain
                    )
                    val operation = keyStore.beginSigningOperation(prepared.transcript)
                    val prompt = BiometricPrompt(
                        activity,
                        activity.mainExecutor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                try {
                                    val authenticated = result.cryptoObject?.signature
                                        ?: throw IllegalStateException("Authenticated CryptoObject did not return its signature.")
                                    val proof = OwnerFingerprintApprovalCeremony.complete(
                                        prepared,
                                        requireFreshUserVerification = {},
                                        sign = { transcriptToSign ->
                                            if (!java.security.MessageDigest.isEqual(transcriptToSign, prepared.transcript)) {
                                                throw IllegalStateException("Prepared approval transcript changed.")
                                            }
                                            keyStore.completeSigningOperation(operation, authenticated)
                                        }
                                    )
                                    onApproved(proof)
                                } catch (error: Throwable) {
                                    onError(error)
                                }
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                                    onCancelled()
                                } else {
                                    onError(IllegalStateException("Owner authentication failed: $errString"))
                                }
                            }
                        }
                    )
                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Authenticate owner approval")
                        .setSubtitle("Approve ${details.role} · ${details.keyId}")
                        .setDescription("The hardware-backed master key will sign this exact approval.")
                        .setAllowedAuthenticators(
                            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                                BiometricManager.Authenticators.DEVICE_CREDENTIAL
                        )
                        .build()
                    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(operation.cryptoObjectSignature))
                } catch (error: Throwable) {
                    onError(error)
                }
            }
            .setNegativeButton("Cancel") { _, _ -> onCancelled() }
            .setOnCancelListener { onCancelled() }
            .show()
    }
}
