import CryptoKit
import Foundation

/// Proof that the owner approved the exact candidate trust-bundle fingerprint.
/// The caller must validate the candidate bundle before invoking this ceremony.
public enum OwnerFingerprintApprovalCeremony {
    public enum CeremonyError: Error { case invalidFingerprint, fingerprintMismatch, invalidChallenge, expiredChallenge, invalidOwnerIdentifier }
    public struct ApprovalProof { public let fingerprint: String; public let challenge: Data; public let expiresAt: UInt64; public let signature: Data }

    /// Confirmation must come from native UI; fresh verification must invoke OS biometrics/passcode;
    /// sign must use the dedicated hardware-backed master signing key.
    public static func approve(canonicalBundle: Data, outOfBandFingerprint: String, ownerIdentifier: String, challenge: Data, expiresAt: UInt64, now: UInt64 = UInt64(Date().timeIntervalSince1970), confirmFingerprint: String, requireFreshUserVerification: () throws -> Void, sign: (Data) throws -> Data) throws -> ApprovalProof {
        guard !ownerIdentifier.isEmpty, !ownerIdentifier.contains("\n"), !ownerIdentifier.contains("\r") else { throw CeremonyError.invalidOwnerIdentifier }
        guard challenge.count == 32 else { throw CeremonyError.invalidChallenge }
        guard expiresAt > now, expiresAt - now <= 300 else { throw CeremonyError.expiredChallenge }
        let digest = Data(SHA256.hash(data: canonicalBundle))
        let expected = try decodeFingerprint(outOfBandFingerprint)
        let confirmed = try decodeFingerprint(confirmFingerprint)
        guard constantTimeEqual(digest, expected), constantTimeEqual(digest, confirmed) else { throw CeremonyError.fingerprintMismatch }
        let transcript = makeTranscript(ownerIdentifier: ownerIdentifier, digest: digest, challenge: challenge, expiresAt: expiresAt)
        try requireFreshUserVerification()
        let signature = try sign(transcript)
        guard !signature.isEmpty else { throw CeremonyError.invalidChallenge }
        return ApprovalProof(fingerprint: formatFingerprint(digest), challenge: challenge, expiresAt: expiresAt, signature: signature)
    }

    private static func decodeFingerprint(_ value: String) throws -> Data {
        let hex = value.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "").lowercased()
        guard hex.count == 64, hex.allSatisfy({ $0.isHexDigit }) else { throw CeremonyError.invalidFingerprint }
        var result = Data(); var index = hex.startIndex
        for _ in 0..<32 { let next = hex.index(index, offsetBy: 2); guard let byte = UInt8(hex[index..<next], radix: 16) else { throw CeremonyError.invalidFingerprint }; result.append(byte); index = next }
        return result
    }
    private static func formatFingerprint(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool { guard lhs.count == rhs.count else { return false }; var diff: UInt8 = 0; for i in lhs.indices { diff |= lhs[i] ^ rhs[i] }; return diff == 0 }
    private static func makeTranscript(ownerIdentifier: String, digest: Data, challenge: Data, expiresAt: UInt64) -> Data {
        var out = Data("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1\n".utf8); let owner = Data(ownerIdentifier.utf8)
        append(UInt32(owner.count), to: &out); out.append(owner); out.append(digest); append(UInt32(challenge.count), to: &out); out.append(challenge); append(expiresAt, to: &out); return out
    }
    private static func append(_ value: UInt32, to out: inout Data) { out.append(UInt8((value >> 24) & 255)); out.append(UInt8((value >> 16) & 255)); out.append(UInt8((value >> 8) & 255)); out.append(UInt8(value & 255)) }
    private static func append(_ value: UInt64, to out: inout Data) { for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((value >> UInt64(shift)) & 255)) } }
}