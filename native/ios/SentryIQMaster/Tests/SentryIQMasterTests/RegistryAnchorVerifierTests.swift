import CryptoKit
import XCTest
@testable import SentryIQMaster

final class RegistryAnchorVerifierTests: XCTestCase {
    private let now: UInt64 = 1_800_000_000
    private let ownerID = "owner-test-001"
    private let signerID = "registry-test-1"
    private let bundleDigest = String(repeating: "11", count: 32)

    private func lowS(_ signature: Data) -> Data {
        let bytes = [UInt8](signature)
        let halfOrder = [UInt8](Data(hex: "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")!)
        let s = Array(bytes[32..<64])
        if s.lexicographicallyPrecedes(halfOrder) || s == halfOrder {
            return signature
        }
        let order = [UInt8](Data(hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")!)
        var normalized = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            let value = Int(order[index]) - Int(s[index]) - borrow
            borrow = value < 0 ? 1 : 0
            normalized[index] = UInt8(value < 0 ? value + 256 : value)
        }
        return Data(bytes[0..<32] + normalized)
    }

    private func makeAnchor(key: P256.Signing.PrivateKey) throws -> TrustRegistryAnchor {
        let payload = Data(("{\"bundle_sha256\":\"" + bundleDigest +
            "\",\"expires_at\":1800003600,\"issued_at\":1799999990,\"owner_id\":\"" + ownerID +
            "\",\"previous_bundle_sha256\":null,\"schema_version\":1,\"sequence\":\"1\",\"signer_kid\":\"" +
            signerID + "\",\"type\":\"SENTRYIQ-REGISTRY-ANCHOR\"}").utf8)
        let signature = lowS(try key.signature(for: payload).rawRepresentation)
        return TrustRegistryAnchor(
            sequence: 1,
            bundleSHA256: Data(repeating: 0x11, count: 32),
            signedPayload: payload,
            signature: signature,
            issuedAt: now - 10,
            expiresAt: now + 3600,
            previousBundleSHA256: nil,
            ownerID: ownerID,
            signerKeyID: signerID
        )
    }

    func testSharedRegistryAnchorCanonicalizationFixtureMatchesNativePayload() throws {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../../../../tests/fixtures/registry-anchor-canonicalization.json")
            .standardizedFileURL
        let fixtureData = try Data(contentsOf: fixtureURL)
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: fixtureData) as? [String: Any])
        let expectedCanonical = try XCTUnwrap(fixture["canonical"] as? String)
        let expectedDigest = try XCTUnwrap(fixture["sha256"] as? String)

        let anchor = try makeAnchor(key: P256.Signing.PrivateKey())
        let actualCanonical = try XCTUnwrap(String(data: anchor.signedPayload, encoding: .utf8))
        XCTAssertEqual(actualCanonical, expectedCanonical)
        let actualDigest = SHA256.hash(data: Data(actualCanonical.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        XCTAssertEqual(actualDigest, expectedDigest)
    }

    func testVerifiesSignatureFromIndependentlyPinnedRegistrySigner() throws {
        let key = P256.Signing.PrivateKey()
        let anchor = try makeAnchor(key: key)
        let signer = RegistryAnchorSignerKey(
            keyID: signerID,
            role: "registry-anchor",
            algorithm: "ES256",
            subjectPublicKeyInfoDER: key.publicKey.derRepresentation
        )
        XCTAssertNoThrow(try RegistryAnchorVerifier.verify(
            anchor,
            expectedOwnerID: ownerID,
            trustedSignerKeys: [signer],
            now: now
        ))
    }

    func testRejectsWrongOwnerRoleAndDuplicateSignerSet() throws {
        let key = P256.Signing.PrivateKey()
        let anchor = try makeAnchor(key: key)
        let signer = RegistryAnchorSignerKey(
            keyID: signerID,
            role: "registry-anchor",
            algorithm: "ES256",
            subjectPublicKeyInfoDER: key.publicKey.derRepresentation
        )
        XCTAssertThrowsError(try RegistryAnchorVerifier.verify(
            anchor, expectedOwnerID: "other-owner", trustedSignerKeys: [signer], now: now
        ))
        let wrongRole = RegistryAnchorSignerKey(
            keyID: signerID, role: "release-authorisation", algorithm: "ES256",
            subjectPublicKeyInfoDER: key.publicKey.derRepresentation
        )
        XCTAssertThrowsError(try RegistryAnchorVerifier.verify(
            anchor, expectedOwnerID: ownerID, trustedSignerKeys: [wrongRole], now: now
        ))
        XCTAssertThrowsError(try RegistryAnchorVerifier.verify(
            anchor, expectedOwnerID: ownerID, trustedSignerKeys: [signer, signer], now: now
        ))
    }

    func testRejectsPayloadFieldSubstitutionAndExpiredAnchor() throws {
        let key = P256.Signing.PrivateKey()
        let anchor = try makeAnchor(key: key)
        let signer = RegistryAnchorSignerKey(
            keyID: signerID, role: "registry-anchor", algorithm: "ES256",
            subjectPublicKeyInfoDER: key.publicKey.derRepresentation
        )
        let changed = TrustRegistryAnchor(
            sequence: anchor.sequence,
            bundleSHA256: Data(repeating: 0x22, count: 32),
            signedPayload: anchor.signedPayload,
            signature: anchor.signature,
            issuedAt: anchor.issuedAt,
            expiresAt: anchor.expiresAt,
            previousBundleSHA256: anchor.previousBundleSHA256,
            ownerID: anchor.ownerID,
            signerKeyID: anchor.signerKeyID
        )
        XCTAssertThrowsError(try RegistryAnchorVerifier.verify(
            changed, expectedOwnerID: ownerID, trustedSignerKeys: [signer], now: now
        ))
        XCTAssertThrowsError(try RegistryAnchorVerifier.verify(
            anchor, expectedOwnerID: ownerID, trustedSignerKeys: [signer], now: now + 4000
        ))
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
}
