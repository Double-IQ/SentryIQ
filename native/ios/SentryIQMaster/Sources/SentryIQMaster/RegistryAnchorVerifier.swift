import CryptoKit
import Foundation

public struct RegistryAnchorSignerKey {
    public let keyID: String
    public let role: String
    public let algorithm: String
    public let subjectPublicKeyInfoDER: Data

    public init(keyID: String, role: String, algorithm: String, subjectPublicKeyInfoDER: Data) {
        self.keyID = keyID
        self.role = role
        self.algorithm = algorithm
        self.subjectPublicKeyInfoDER = subjectPublicKeyInfoDER
    }
}

/**
 Verifies the canonical registry-anchor envelope using only separately pinned keys.
 The trust store still enforces local sequence/previous-digest continuity on save.
 */
public enum RegistryAnchorVerifier {
    public static func makeVerifier(
        expectedOwnerID: String,
        trustedSignerKeys: [RegistryAnchorSignerKey]
    ) -> (TrustRegistryAnchor) -> Bool {
        { anchor in
            do {
                try verify(
                    anchor,
                    expectedOwnerID: expectedOwnerID,
                    trustedSignerKeys: trustedSignerKeys
                )
                return true
            } catch {
                return false
            }
        }
    }

    public static func verify(
        _ anchor: TrustRegistryAnchor,
        expectedOwnerID: String,
        trustedSignerKeys: [RegistryAnchorSignerKey],
        now: UInt64 = UInt64(Date().timeIntervalSince1970)
    ) throws {
        guard validIdentifier(expectedOwnerID, maximumLength: 256),
              anchor.ownerID == expectedOwnerID,
              validIdentifier(anchor.signerKeyID, maximumLength: 128),
              anchor.sequence > 0,
              anchor.bundleSHA256.count == 32,
              anchor.signature.count == 64,
              anchor.previousBundleSHA256 == nil || anchor.previousBundleSHA256?.count == 32,
              TrustRegistryAnchorPolicy.isFresh(issuedAt: anchor.issuedAt, expiresAt: anchor.expiresAt, now: now),
              anchor.signedPayload == canonicalPayload(anchor) else {
            throw VerificationError.invalidEnvelope
        }

        var keysByID: [String: RegistryAnchorSignerKey] = [:]
        for key in trustedSignerKeys {
            guard validIdentifier(key.keyID, maximumLength: 128),
                  keysByID[key.keyID] == nil else {
                throw VerificationError.ambiguousSignerSet
            }
            keysByID[key.keyID] = key
        }
        guard let signer = keysByID[anchor.signerKeyID],
              signer.role == "registry-anchor",
              signer.algorithm == "ES256" else {
            throw VerificationError.untrustedSigner
        }

        let raw = [UInt8](anchor.signature)
        let halfOrder = [UInt8](Data(hex: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")!)
        guard raw.count == 64,
              raw[0..<32].contains(where: { $0 != 0 }),
              compare(Array(raw[32..<64]), halfOrder) <= 0,
              raw[32..<64].contains(where: { $0 != 0 }) else {
            throw VerificationError.nonCanonicalSignature
        }

        // CryptoKit's DER initializer is iOS 14+, while this package supports iOS 13.
        // Accept only the exact SubjectPublicKeyInfo prefix for id-ecPublicKey / prime256v1.
        let subjectPublicKeyInfoPrefix = Data(hex: "3039301306072a8648ce3d020106082a8648ce3d03010703420004")!
        guard signer.subjectPublicKeyInfoDER.starts(with: subjectPublicKeyInfoPrefix) else {
            throw VerificationError.invalidSignerKey
        }
        let rawPublicKey = signer.subjectPublicKeyInfoDER.dropFirst(subjectPublicKeyInfoPrefix.count)
        guard rawPublicKey.count == 64 else { throw VerificationError.invalidSignerKey }
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: Data(rawPublicKey))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: anchor.signature)
        guard publicKey.isValidSignature(signature, for: anchor.signedPayload) else {
            throw VerificationError.invalidSignature
        }
    }

    private enum VerificationError: Error {
        case invalidEnvelope
        case ambiguousSignerSet
        case untrustedSigner
        case invalidSignerKey
        case nonCanonicalSignature
        case invalidSignature
    }

    private static func validIdentifier(_ value: String, maximumLength: Int) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumLength else { return false }
        return value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) ||
            ($0 >= 97 && $0 <= 122) || $0 == 46 || $0 == 95 || $0 == 58 || $0 == 45
        }
    }

    private static func canonicalPayload(_ anchor: TrustRegistryAnchor) -> Data {
        let previous = anchor.previousBundleSHA256.map { "\"\($0.hexString)\"" } ?? "null"
        let json = "{\"bundle_sha256\":\"\(anchor.bundleSHA256.hexString)\",\"expires_at\":\(anchor.expiresAt),\"issued_at\":\(anchor.issuedAt),\"owner_id\":\"\(anchor.ownerID)\",\"previous_bundle_sha256\":\(previous),\"schema_version\":1,\"sequence\":\"\(anchor.sequence)\",\"signer_kid\":\"\(anchor.signerKeyID)\",\"type\":\"SENTRYIQ-REGISTRY-ANCHOR\"}"
        return Data(json.utf8)
    }

    private static func compare(_ left: [UInt8], _ right: [UInt8]) -> Int {
        for index in 0..<min(left.count, right.count) {
            if left[index] != right[index] { return left[index] < right[index] ? -1 : 1 }
        }
        return left.count == right.count ? 0 : (left.count < right.count ? -1 : 1)
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
