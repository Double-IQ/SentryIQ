import CryptoKit
import Foundation

/// Proof that the owner approved one exact trust bundle, root role, root key,
/// device keyset and operation. Candidate TUF verification must precede this call.
public enum OwnerFingerprintApprovalCeremony {
    public enum CeremonyError: Error {
        case invalidFingerprint, fingerprintMismatch, invalidChallenge, expiredChallenge
        case invalidOwnerIdentifier, invalidContext, invalidCandidateTrustChain
    }

    public struct ApprovalProof {
        public let bundleFingerprint: String
        public let rootRole: String
        public let rootKeyID: String
        public let rootFingerprint: String
        public let deviceKeysetDigest: String
        public let purpose: String
        public let challenge: Data
        public let expiresAt: UInt64
        public let signature: Data
    }

    public struct PreparedApproval {
        public let bundleFingerprint: String
        public let rootRole: String
        public let rootKeyID: String
        public let rootFingerprint: String
        public let deviceKeysetDigest: String
        public let purpose: String
        public let challenge: Data
        public let expiresAt: UInt64
        public let transcript: Data
    }

    /// Validate the candidate and both owner-entered fingerprints before OS authentication.
    public static func prepare(
        canonicalBundle: Data,
        outOfBandFingerprint: String,
        ownerIdentifier: String,
        rootRole: String,
        rootKeyID: String,
        outOfBandRootFingerprint: String,
        deviceKeysetDigest: String,
        purpose: String,
        challenge: Data,
        expiresAt: UInt64,
        now: UInt64 = UInt64(Date().timeIntervalSince1970),
        confirmFingerprint: () throws -> String,
        confirmRootFingerprint: () throws -> String,
        verifyCandidateTrustChain: (Data, String, String, Data, Data, String) throws -> Bool
    ) throws -> PreparedApproval {
        guard validOwnerIdentifier(ownerIdentifier) else {
            throw CeremonyError.invalidOwnerIdentifier
        }
        guard validToken(rootRole), validToken(rootKeyID), validToken(purpose),
              challenge.count == 32 else { throw CeremonyError.invalidContext }
        guard expiresAt > now, expiresAt - now <= 300 else { throw CeremonyError.expiredChallenge }
        let bundleDigest = Data(SHA256.hash(data: canonicalBundle))
        let expectedBundle = try decodeFingerprint(outOfBandFingerprint)
        let expectedRoot = try decodeFingerprint(outOfBandRootFingerprint)
        let keysetDigest = try decodeFingerprint(deviceKeysetDigest)
        guard try verifyCandidateTrustChain(canonicalBundle, rootRole, rootKeyID, expectedRoot, keysetDigest, purpose) else {
            throw CeremonyError.invalidCandidateTrustChain
        }
        let confirmedBundle = try decodeFingerprint(confirmFingerprint())
        let confirmedRoot = try decodeFingerprint(confirmRootFingerprint())
        guard constantTimeEqual(bundleDigest, expectedBundle),
              constantTimeEqual(bundleDigest, confirmedBundle),
              constantTimeEqual(expectedRoot, confirmedRoot) else {
            throw CeremonyError.fingerprintMismatch
        }
        let transcript = makeTranscript(
            ownerIdentifier: ownerIdentifier, bundleDigest: bundleDigest,
            rootRole: rootRole, rootKeyID: rootKeyID, rootFingerprint: expectedRoot,
            deviceKeysetDigest: keysetDigest, purpose: purpose,
            challenge: challenge, expiresAt: expiresAt
        )
        return PreparedApproval(
            bundleFingerprint: formatFingerprint(bundleDigest),
            rootRole: rootRole,
            rootKeyID: rootKeyID,
            rootFingerprint: formatFingerprint(expectedRoot),
            deviceKeysetDigest: formatFingerprint(keysetDigest),
            purpose: purpose,
            challenge: challenge,
            expiresAt: expiresAt,
            transcript: transcript
        )
    }

    /// Sign a prepared transcript only after the platform reports fresh user authentication.
    public static func complete(
        _ prepared: PreparedApproval,
        now: UInt64 = UInt64(Date().timeIntervalSince1970),
        requireFreshUserVerification: () throws -> Void,
        sign: (Data) throws -> Data
    ) throws -> ApprovalProof {
        guard prepared.expiresAt > now, prepared.expiresAt - now <= 300 else {
            throw CeremonyError.expiredChallenge
        }
        try requireFreshUserVerification()
        let signature = try sign(prepared.transcript)
        guard !signature.isEmpty else { throw CeremonyError.invalidContext }
        return ApprovalProof(
            bundleFingerprint: prepared.bundleFingerprint,
            rootRole: prepared.rootRole,
            rootKeyID: prepared.rootKeyID,
            rootFingerprint: prepared.rootFingerprint,
            deviceKeysetDigest: prepared.deviceKeysetDigest,
            purpose: prepared.purpose,
            challenge: prepared.challenge,
            expiresAt: prepared.expiresAt,
            signature: signature
        )
    }

    /// Synchronous wrapper retained for deterministic unit tests and non-UI adapters.
    public static func approve(
        canonicalBundle: Data,
        outOfBandFingerprint: String,
        ownerIdentifier: String,
        rootRole: String,
        rootKeyID: String,
        outOfBandRootFingerprint: String,
        deviceKeysetDigest: String,
        purpose: String,
        challenge: Data,
        expiresAt: UInt64,
        now: UInt64 = UInt64(Date().timeIntervalSince1970),
        confirmFingerprint: () throws -> String,
        confirmRootFingerprint: () throws -> String,
        verifyCandidateTrustChain: (Data, String, String, Data, Data, String) throws -> Bool,
        requireFreshUserVerification: () throws -> Void,
        sign: (Data) throws -> Data
    ) throws -> ApprovalProof {
        let prepared = try prepare(
            canonicalBundle: canonicalBundle,
            outOfBandFingerprint: outOfBandFingerprint,
            ownerIdentifier: ownerIdentifier,
            rootRole: rootRole,
            rootKeyID: rootKeyID,
            outOfBandRootFingerprint: outOfBandRootFingerprint,
            deviceKeysetDigest: deviceKeysetDigest,
            purpose: purpose,
            challenge: challenge,
            expiresAt: expiresAt,
            now: now,
            confirmFingerprint: confirmFingerprint,
            confirmRootFingerprint: confirmRootFingerprint,
            verifyCandidateTrustChain: verifyCandidateTrustChain
        )
        return try complete(
            prepared,
            now: now,
            requireFreshUserVerification: requireFreshUserVerification,
            sign: sign
        )
    }

    private static func validOwnerIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256 &&
        value.utf8.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) ||
            ($0 >= 48 && $0 <= 57) || $0 == 46 || $0 == 95 || $0 == 58 || $0 == 45 }
    }

    private static func validToken(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 &&
        value.utf8.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) ||
            ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 46 || $0 == 95 }
    }

    private static func decodeFingerprint(_ value: String) throws -> Data {
        let hex = value.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: " ", with: "").lowercased()
        guard hex.count == 64, hex.allSatisfy({ $0.isHexDigit }) else { throw CeremonyError.invalidFingerprint }
        var result = Data(); var index = hex.startIndex
        for _ in 0..<32 {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { throw CeremonyError.invalidFingerprint }
            result.append(byte); index = next
        }
        return result
    }

    private static func formatFingerprint(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for i in lhs.indices { diff |= lhs[i] ^ rhs[i] }
        return diff == 0
    }

    private static func appendField(_ value: String, to out: inout Data) {
        let bytes = Data(value.utf8)
        append(UInt32(bytes.count), to: &out)
        out.append(bytes)
    }

    private static func makeTranscript(
        ownerIdentifier: String, bundleDigest: Data, rootRole: String, rootKeyID: String,
        rootFingerprint: Data, deviceKeysetDigest: Data, purpose: String,
        challenge: Data, expiresAt: UInt64
    ) -> Data {
        var out = Data("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n".utf8)
        appendField(ownerIdentifier, to: &out)
        out.append(bundleDigest)
        appendField(rootRole, to: &out)
        appendField(rootKeyID, to: &out)
        out.append(rootFingerprint)
        out.append(deviceKeysetDigest)
        appendField(purpose, to: &out)
        append(UInt32(challenge.count), to: &out)
        out.append(challenge)
        append(expiresAt, to: &out)
        return out
    }

    private static func append(_ value: UInt32, to out: inout Data) {
        out.append(UInt8((value >> 24) & 255)); out.append(UInt8((value >> 16) & 255))
        out.append(UInt8((value >> 8) & 255)); out.append(UInt8(value & 255))
    }

    private static func append(_ value: UInt64, to out: inout Data) {
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8((value >> UInt64(shift)) & 255))
        }
    }
}
