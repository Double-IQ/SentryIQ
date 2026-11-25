import CryptoKit
import Foundation
import XCTest
@testable import SentryIQMaster

final class OwnerFingerprintApprovalCeremonyTests: XCTestCase {
    private let bundle = Data("canonical-trust-bundle".utf8)
    private let root = Data("independent-release-root".utf8)
    private let keyset = Data("device-keyset-public-identifiers".utf8)
    private let challenge = Data(repeating: 0x5a, count: 32)
    private let expiry: UInt64 = 1_700_000_200
    private let now: UInt64 = 1_700_000_000
    private func fp(_ data: Data) -> String { Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined() }

    private func approve(bundleFP: String? = nil, rootFP: String? = nil, owner: String = "owner-123",
        role: String = "release-authorisation", purpose: String = "bootstrap-release-root",
        expires: UInt64? = nil, verify: @escaping (Data) throws -> Bool = { _ in true },
        fresh: @escaping () throws -> Void = {}, sign: @escaping (Data) throws -> Data = { _ in Data([0x30, 1]) }
    ) throws -> OwnerFingerprintApprovalCeremony.ApprovalProof {
        try OwnerFingerprintApprovalCeremony.approve(canonicalBundle: bundle,
            outOfBandFingerprint: bundleFP ?? fp(bundle), ownerIdentifier: owner,
            rootRole: role, rootKeyID: "release-root-1", outOfBandRootFingerprint: fp(root),
            deviceKeysetDigest: fp(keyset), purpose: purpose, challenge: challenge,
            expiresAt: expires ?? expiry, now: now, confirmFingerprint: fp(bundle),
            confirmRootFingerprint: rootFP ?? fp(root), verifyCandidateTrustChain: verify,
            requireFreshUserVerification: fresh, sign: sign)
    }

    func testProofBindsAllApprovalContext() throws {
        var transcript = Data(); var fresh = false
        let proof = try approve(fresh: { fresh = true }, sign: { transcript = $0; return Data([0x30, 1]) })
        XCTAssertTrue(fresh); XCTAssertEqual(proof.bundleFingerprint, fp(bundle))
        XCTAssertEqual(proof.rootRole, "release-authorisation"); XCTAssertEqual(proof.rootKeyId, "release-root-1")
        XCTAssertEqual(proof.rootFingerprint, fp(root)); XCTAssertEqual(proof.deviceKeysetDigest, fp(keyset))
        XCTAssertEqual(proof.purpose, "bootstrap-release-root"); XCTAssertEqual(proof.challenge, challenge)
        XCTAssertEqual(proof.expiresAt, expiry)

        var expected = Data("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n".utf8)
        func field(_ s: String) { let b = Data(s.utf8); expected.append(contentsOf: [0,0,0,UInt8(b.count)]); expected.append(b) }
        field("owner-123"); expected.append(Data(SHA256.hash(data: bundle)))
        field("release-authorisation"); field("release-root-1")
        expected.append(Data(SHA256.hash(data: root))); expected.append(Data(SHA256.hash(data: keyset)))
        field("bootstrap-release-root"); expected.append(contentsOf: [0,0,0,32]); expected.append(challenge)
        for shift in stride(from: 56, through: 0, by: -8) { expected.append(UInt8((expiry >> UInt64(shift)) & 255)) }
        XCTAssertEqual(transcript, expected)
    }

    func testWrongRootFingerprintFailsBeforeAuthenticationOrSigning() {
        var fresh = false; var signed = false
        XCTAssertThrowsError(try approve(rootFP: String(repeating: "0", count: 64),
            fresh: { fresh = true }, sign: { _ in signed = true; return Data([1]) }))
        XCTAssertFalse(fresh); XCTAssertFalse(signed)
    }
    func testWrongBundleFingerprintFailsClosed() { XCTAssertThrowsError(try approve(bundleFP: String(repeating: "0", count: 64))) }
    func testWrongOwnerAndMalformedContextFailClosed() {
        XCTAssertThrowsError(try approve(owner: "")); XCTAssertThrowsError(try approve(role: "release authorisation"))
        XCTAssertThrowsError(try approve(purpose: ""))
    }
    func testExpiredChallengeAndInvalidCandidateFailBeforeSigning() {
        var signed = false
        XCTAssertThrowsError(try approve(expires: now))
        XCTAssertThrowsError(try approve(verify: { _ in false }, sign: { _ in signed = true; return Data([1]) }))
        XCTAssertFalse(signed)
    }
    func testFreshUserVerificationMustSucceedBeforeSigning() {
        var signed = false
        XCTAssertThrowsError(try approve(fresh: { throw NSError(domain: "biometric", code: 1) },
            sign: { _ in signed = true; return Data([1]) }))
        XCTAssertFalse(signed)
    }
}
