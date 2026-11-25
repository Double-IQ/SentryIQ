import CryptoKit
import Foundation
import XCTest
@testable import SentryIQMaster

final class OwnerFingerprintApprovalCeremonyTests: XCTestCase {
    func testApprovalBindsFingerprintChallengeOwnerAndExpiry() throws {
        let bundle = Data("canonical-trust-bundle".utf8)
        let fingerprint = SHA256.hash(data: bundle).map { String(format: "%02x", $0) }.joined()
        let challenge = Data(repeating: 0x5a, count: 32)
        let expiry: UInt64 = 1_700_000_200
        var signedTranscript = Data()
        var verified = false

        let proof = try OwnerFingerprintApprovalCeremony.approve(
            canonicalBundle: bundle,
            outOfBandFingerprint: fingerprint,
            ownerIdentifier: "owner-123",
            challenge: challenge,
            expiresAt: expiry,
            now: 1_700_000_000,
            confirmFingerprint: fingerprint,
            requireFreshUserVerification: { verified = true },
            sign: { message in signedTranscript = message; return Data([0x30, 0x01]) }
        )

        XCTAssertTrue(verified)
        XCTAssertEqual(proof.fingerprint, fingerprint)
        XCTAssertEqual(proof.challenge, challenge)
        XCTAssertEqual(proof.expiresAt, expiry)
        XCTAssertEqual(proof.signature, Data([0x30, 0x01]))

        var expected = Data("SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1\n".utf8)
        let owner = Data("owner-123".utf8)
        expected.append(contentsOf: [0, 0, 0, UInt8(owner.count)])
        expected.append(owner)
        expected.append(Data(SHA256.hash(data: bundle)))
        expected.append(contentsOf: [0, 0, 0, 32])
        expected.append(challenge)
        for shift in stride(from: 56, through: 0, by: -8) {
            expected.append(UInt8((expiry >> UInt64(shift)) & 0xff))
        }
        XCTAssertEqual(signedTranscript, expected)
    }

    func testFingerprintMismatchFailsBeforeUserVerificationOrSigning() {
        let bundle = Data("candidate".utf8)
        let valid = SHA256.hash(data: bundle).map { String(format: "%02x", $0) }.joined()
        var verificationCalled = false
        var signingCalled = false

        XCTAssertThrowsError(try OwnerFingerprintApprovalCeremony.approve(
            canonicalBundle: bundle,
            outOfBandFingerprint: String(repeating: "0", count: 64),
            ownerIdentifier: "owner-123",
            challenge: Data(repeating: 1, count: 32),
            expiresAt: 1_700_000_200,
            now: 1_700_000_000,
            confirmFingerprint: valid,
            requireFreshUserVerification: { verificationCalled = true },
            sign: { _ in signingCalled = true; return Data([1]) }
        ))
        XCTAssertFalse(verificationCalled)
        XCTAssertFalse(signingCalled)
    }

    func testExpiredChallengeFailsClosed() {
        let bundle = Data("candidate".utf8)
        let fingerprint = SHA256.hash(data: bundle).map { String(format: "%02x", $0) }.joined()
        XCTAssertThrowsError(try OwnerFingerprintApprovalCeremony.approve(
            canonicalBundle: bundle,
            outOfBandFingerprint: fingerprint,
            ownerIdentifier: "owner-123",
            challenge: Data(repeating: 1, count: 32),
            expiresAt: 1_700_000_000,
            now: 1_700_000_000,
            confirmFingerprint: fingerprint,
            requireFreshUserVerification: {},
            sign: { _ in Data([1]) }
        ))
    }
}
