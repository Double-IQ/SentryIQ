package co.bichet.sentryiq.master

import android.app.AlertDialog
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.Signature

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
        val fingerprintSha256: String,
        val provenance: String,
        val permittedPurpose: String,
        val forbiddenPurposes: String,
        val expiresAtUtc: String
    )

    fun present(
        activity: FragmentActivity,
        details: RootDetails,
        transcript: ByteArray,
        onApproved: (ByteArray) -> Unit,
        onCancelled: () -> Unit,
        onError: (Throwable) -> Unit
    ) {
        require(details.role.isNotBlank() && details.keyId.isNotBlank())
        require(details.algorithm == "ES256")
        require(details.fingerprintSha256.matches(Regex("^[a-fA-F0-9]{64}$")))
        require(details.provenance.isNotBlank() && details.permittedPurpose.isNotBlank())
        val message = listOf(
            "Role: ${details.role}",
            "Key ID: ${details.keyId}",
            "Algorithm: ${details.algorithm}",
            "SHA-256 fingerprint: ${details.fingerprintSha256.lowercase()}",
            "Source: ${details.provenance}",
            "Permitted purpose: ${details.permittedPurpose}",
            "Forbidden purposes: ${details.forbiddenPurposes}",
            "Expires: ${details.expiresAtUtc}",
            "",
            "Compare this full fingerprint with your independent out-of-band record before continuing."
        ).joinToString("\n")

        AlertDialog.Builder(activity)
            .setTitle("Review trust-root approval")
            .setMessage(message)
            .setPositiveButton("Confirm fingerprint") { _, _ ->
                try {
                    val operation = keyStore.beginSigningOperation(transcript)
                    val prompt = BiometricPrompt(
                        activity,
                        activity.mainExecutor,
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                try {
                                    val authenticated = result.cryptoObject?.signature
                                        ?: throw IllegalStateException("Authenticated CryptoObject did not return its signature.")
                                    onApproved(keyStore.completeSigningOperation(operation, authenticated))
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
