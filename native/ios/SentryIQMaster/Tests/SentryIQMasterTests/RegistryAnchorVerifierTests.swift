import CryptoKit
import XCTest
@testable import SentryIQMaster

final class RegistryAnchorVerifierTests: XCTestCase {
    private let now: UInt64 = 1_800_000_000
    private let ownerID = "owner-test-001"
    private let signerID = "registry-test-1"
    private let bundleDigest = String(repeating: "11", count: 32)

    private func makeAnchor(key: P256.Signing.PrivateKey) throws -> TrustRegistryAnchor {
        let payload = Data(("{\"bundle_sha256\":\"" + bundleDigest +
            "\",\"expires_at\":1800003600,\"issued_at\":1799999990,\"owner_id\":\"" + ownerID +
            "\",\"previous_bundle_sha256\":null,\"schema_version\":1,\"sequence\":\"1\",\"signer_kid\":\"" +
            signerID + "\",\"type\":\"SENTRYIQ-REGISTRY-ANCHOR\"}").utf8)
        let signature = try key.signature(for: payload)
        return TrustRegistryAnchor(
            sequence: 1,
            bundleSHA256: Data(repeating: 0x11, count: 32),
            signedPayload: payload,
            signature: signature.rawRepresentation,
            issuedAt: now - 10,
            expiresAt: now + 3600,
            previousBundleSHA256: nil,
            ownerID: ownerID,
            signerKeyID: signerID
        )
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
