#if canImport(UIKit)
import CryptoKit
import Foundation
import LocalAuthentication
import UIKit

/// Native, explicit fingerprint entry and OS-authenticated approval for one trust root.
@MainActor
public final class OwnerFingerprintApprovalPresenter {
    public struct RootDetails {
        public let role: String
        public let keyID: String
        public let algorithm: String
        public let candidateRootFingerprint: String
        public let provenance: String
        public let permittedPurpose: String
        public let forbiddenPurposes: String
        public let expiresAtUTC: String

        public init(
            role: String, keyID: String, algorithm: String = "ES256",
            candidateRootFingerprint: String, provenance: String,
            permittedPurpose: String, forbiddenPurposes: String, expiresAtUTC: String
        ) {
            self.role = role
            self.keyID = keyID
            self.algorithm = algorithm
            self.candidateRootFingerprint = candidateRootFingerprint
            self.provenance = provenance
            self.permittedPurpose = permittedPurpose
            self.forbiddenPurposes = forbiddenPurposes
            self.expiresAtUTC = expiresAtUTC
        }
    }

    private let keyStore: SecureEnclaveMasterKeyStore

    public init(keyStore: SecureEnclaveMasterKeyStore) {
        self.keyStore = keyStore
    }

    public func present(
        from presenter: UIViewController,
        details: RootDetails,
        canonicalBundle: Data,
        ownerIdentifier: String,
        rootRole: String,
        rootKeyID: String,
        deviceKeysetDigest: String,
        purpose: String,
        challenge: Data,
        expiresAt: UInt64,
        verifiedState: OwnerBootstrapHTTPClient.VerifiedBootstrapState,
        completion: @escaping (Result<OwnerFingerprintApprovalCeremony.ApprovalProof, Error>) -> Void
    ) {
        guard ownerIdentifier == verifiedState.snapshot.ownerID,
              canonicalBundle == verifiedState.snapshot.canonicalBundle else {
            completion(.failure(OwnerFingerprintApprovalCeremony.CeremonyError.invalidCandidateTrustChain))
            return
        }
        let contextVerifier = TrustBundleApprovalContextVerifier(verifiedState: verifiedState)
        let bundleFingerprint = SHA256.hash(data: canonicalBundle)
            .map { String(format: "%02x", $0) }.joined()
        let message = [
            "Role: \(details.role)",
            "Key ID: \(details.keyID)",
            "Algorithm: \(details.algorithm)",
            "Candidate root SHA-256: \(details.candidateRootFingerprint)",
            "Trust-bundle SHA-256: \(bundleFingerprint)",
            "Source: \(details.provenance)",
            "Permitted purpose: \(details.permittedPurpose)",
            "Forbidden purposes: \(details.forbiddenPurposes)",
            "Expires: \(details.expiresAtUTC)",
            "",
            "Compare both full fingerprints with your independent out-of-band record and enter them below."
        ].joined(separator: "\n")

        let alert = UIAlertController(
            title: "Review trust-root approval",
            message: message,
            preferredStyle: .alert
        )
        alert.addTextField { field in
            field.placeholder = "Independent trust-bundle SHA-256"
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
            field.keyboardType = .asciiCapable
        }
        alert.addTextField { field in
            field.placeholder = "Independent root SHA-256"
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
            field.keyboardType = .asciiCapable
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
            completion(.failure(CancellationError()))
        })
        alert.addAction(UIAlertAction(title: "Verify and approve", style: .default) { [weak self] _ in
            guard let self,
                  let enteredBundle = alert.textFields?.first?.text,
                  let enteredRoot = alert.textFields?.dropFirst().first?.text else {
                completion(.failure(OwnerFingerprintApprovalCeremony.CeremonyError.invalidFingerprint))
                return
            }
            do {
                let prepared = try OwnerFingerprintApprovalCeremony.prepare(
                    canonicalBundle: canonicalBundle,
                    outOfBandFingerprint: enteredBundle,
                    ownerIdentifier: ownerIdentifier,
                    rootRole: rootRole,
                    rootKeyID: rootKeyID,
                    outOfBandRootFingerprint: enteredRoot,
                    deviceKeysetDigest: deviceKeysetDigest,
                    purpose: purpose,
                    challenge: challenge,
                    expiresAt: expiresAt,
                    confirmFingerprint: { enteredBundle },
                    confirmRootFingerprint: { enteredRoot },
                    verifyCandidateTrustChain: { bundle, role, keyID, root, keyset, purpose in
                        contextVerifier.verify(
                            canonicalBundle: bundle,
                            rootRole: role,
                            rootKeyID: keyID,
                            rootFingerprint: root,
                            deviceKeysetDigest: keyset,
                            purpose: purpose
                        )
                    }
                )
                let context = LAContext()
                context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Approve this exact SentryIQ trust root") { success, error in
                    Task { @MainActor in
                        guard success else {
                            completion(.failure(error ?? NSError(domain: "SentryIQ.OwnerApproval", code: 1)))
                            return
                        }
                        do {
                            let proof = try OwnerFingerprintApprovalCeremony.complete(
                                prepared,
                                requireFreshUserVerification: {},
                                sign: { transcript in try self.keyStore.sign(transcript, context: context) }
                            )
                            completion(.success(proof))
                        } catch {
                            completion(.failure(error))
                        }
                    }
                }
            } catch {
                completion(.failure(error))
            }
        })
        presenter.present(alert, animated: true)
    }
}
#endif
