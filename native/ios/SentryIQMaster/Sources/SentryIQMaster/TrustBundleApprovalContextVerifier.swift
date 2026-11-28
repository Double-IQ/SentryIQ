import CryptoKit
import Foundation

/// Re-checks the selected approval context against the exact bundle already
/// authenticated by the pinned registry anchor and TUF verifier before owner activation.
public struct TrustBundleApprovalContextVerifier {
    private let verified: OwnerBootstrapHTTPClient.PreparedBootstrapState

    public init(verifiedState: OwnerBootstrapHTTPClient.PreparedBootstrapState) {
        self.verified = verifiedState
    }

    public func verify(
        canonicalBundle: Data,
        rootRole: String,
        rootKeyID: String,
        rootFingerprint: Data,
        deviceKeysetDigest: Data,
        purpose: String
    ) -> Bool {
        guard let snapshotSequence = UInt64(verified.snapshot.sequence) else { return false }
        guard canonicalBundle == verified.snapshot.canonicalBundle,
              Data(SHA256.hash(data: canonicalBundle)) == verified.anchor.bundleSHA256,
              verified.anchor.sequence == snapshotSequence,
              verified.snapshot.bundleSHA256 == verified.anchor.bundleSHA256.map({ String(format: "%02x", $0) }).joined(),
              verified.anchor.ownerID == verified.snapshot.ownerID,
              rootRole == "release-authorisation",
              purpose == "bootstrap-release-root",
              verified.verifiedTUFMetadata["root.json"] != nil,
              verified.verifiedTUFMetadata["timestamp.json"] != nil,
              verified.verifiedTUFMetadata["snapshot.json"] != nil,
              verified.verifiedTUFMetadata["targets.json"] != nil,
              let bundle = try? JSONSerialization.jsonObject(with: canonicalBundle) as? [String: Any],
              bundle["owner_id"] as? String == verified.snapshot.ownerID,
              let release = bundle["release_authorisation"] as? [String: Any],
              let keys = release["keys"] as? [[String: Any]],
              let selected = keys.first(where: { $0["kid"] as? String == rootKeyID }),
              selected["purpose"] as? String == "release-authorisation",
              selected["alg"] as? String == "ES256",
              let rootPEM = selected["public_key_pem"] as? String,
              let rootDER = try? P256PublicKeyEncoding.subjectPublicKeyInfoDER(fromPEM: rootPEM),
              constantTimeEqual(Data(SHA256.hash(data: rootDER)), rootFingerprint),
              let master = bundle["master_keyset"] as? [String: Any],
              let signing = master["signing"] as? [String: Any],
              let agreement = master["key_agreement"] as? [String: Any],
              let assurance = master["hardware_assurance"] as? String,
              let signingID = signing["kid"] as? String,
              let signingAlgorithm = signing["alg"] as? String,
              let signingPEM = signing["public_key_pem"] as? String,
              let agreementID = agreement["kid"] as? String,
              let agreementAlgorithm = agreement["alg"] as? String,
              let agreementPEM = agreement["public_key_pem"] as? String,
              signingAlgorithm == "ES256", agreementAlgorithm == "ECDH-ES",
              let signingRaw = try? P256PublicKeyEncoding.rawRepresentation(fromSubjectPublicKeyInfoPEM: signingPEM),
              let agreementRaw = try? P256PublicKeyEncoding.rawRepresentation(fromSubjectPublicKeyInfoPEM: agreementPEM) else {
            return false
        }
        let digest = MasterKeysetDigest.compute(
            signingKeyID: signingID,
            signingPublicKeyRaw: signingRaw,
            agreementKeyID: agreementID,
            agreementPublicKeyRaw: agreementRaw,
            hardwareAssurance: assurance
        )
        guard let digestBytes = Data(hexString: digest) else { return false }
        return constantTimeEqual(digestBytes, deviceKeysetDigest)
    }

    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }
}

private extension Data {
    init?(hexString: String) {
        guard hexString.count == 64 else { return nil }
        var output = Data()
        var index = hexString.startIndex
        for _ in 0..<32 {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            output.append(byte)
            index = next
        }
        self = output
    }
}
