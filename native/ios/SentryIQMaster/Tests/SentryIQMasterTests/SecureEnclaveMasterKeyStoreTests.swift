import CryptoKit
import Foundation
import XCTest
@testable import SentryIQMaster

final class SecureEnclaveMasterKeyStoreTests: XCTestCase {
    func testMasterKeysetDigestMatchesCrossPlatformGoldenVector() {
        let digest = MasterKeysetDigest.compute(
            signingKeyID: "master-signing-abc",
            signingPublicKeyRaw: Data(repeating: 0x01, count: 64),
            agreementKeyID: "master-key-agreement-def",
            agreementPublicKeyRaw: Data(repeating: 0x02, count: 64),
            hardwareAssurance: "secure-enclave"
        )
        XCTAssertEqual(digest, "ff40c999ecdbeacc424f4c012a242a29cef1339f34b1692c9a1714518008e813")
    }

    func testPublicKeyPEMUsesP256SubjectPublicKeyInfo() throws {
        let key = P256.Signing.PrivateKey()
        let raw = key.publicKey.rawRepresentation
        let pem = try P256PublicKeyEncoding.subjectPublicKeyInfoPEM(fromRawRepresentation: raw)

        XCTAssertTrue(pem.hasPrefix("-----BEGIN PUBLIC KEY-----\n"))
        XCTAssertTrue(pem.hasSuffix("-----END PUBLIC KEY-----\n"))

        let body = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        let der = try XCTUnwrap(Data(base64Encoded: body))
        let expectedPrefix = Data([
            0x30, 0x59, 0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00, 0x04
        ])
        XCTAssertEqual(der.prefix(expectedPrefix.count), expectedPrefix)
        XCTAssertEqual(der.suffix(64), raw)
    }

    func testKeyIdentifiersAreStableAndRoleSeparated() {
        let raw = Data(repeating: 0x42, count: 64)
        let signing = P256PublicKeyEncoding.keyID(prefix: "master-signing", rawRepresentation: raw)
        let agreement = P256PublicKeyEncoding.keyID(prefix: "master-key-agreement", rawRepresentation: raw)

        XCTAssertEqual(signing, P256PublicKeyEncoding.keyID(prefix: "master-signing", rawRepresentation: raw))
        XCTAssertNotEqual(signing, agreement)
        XCTAssertTrue(signing.hasPrefix("master-signing-"))
    }

    func testLowSNormalizationPreservesValidES256Signature() throws {
        let message = Data("SentryIQ trust-bundle test".utf8)
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: message)
        let normalized = try P256PublicKeyEncoding.normalizeES256Signature(signature.rawRepresentation)
        let normalizedSignature = try P256.Signing.ECDSASignature(rawRepresentation: normalized)

        XCTAssertEqual(normalized.count, 64)
        XCTAssertTrue(key.publicKey.isValidSignature(normalizedSignature, for: message))
        let halfOrder = Data([
            0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
            0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
        ])
        XCTAssertFalse(halfOrder.lexicographicallyPrecedes(Data(normalized.suffix(32))))
    }

    func testHighSFormNormalizesToEquivalentLowSForm() throws {
        let message = Data("SentryIQ ECDSA malleability test".utf8)
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: message)
        let low = try P256PublicKeyEncoding.normalizeES256Signature(signature.rawRepresentation)
        let high = highS(fromLowS: low)
        let normalized = try P256PublicKeyEncoding.normalizeES256Signature(high)

        XCTAssertEqual(normalized, low)
        let checked = try P256.Signing.ECDSASignature(rawRepresentation: normalized)
        XCTAssertTrue(key.publicKey.isValidSignature(checked, for: message))
    }

    func testInvalidSignatureLengthIsRejected() {
        XCTAssertThrowsError(try P256PublicKeyEncoding.normalizeES256Signature(Data(repeating: 0, count: 63)))
    }

    func testNonP256PublicKeyLengthIsRejected() {
        XCTAssertThrowsError(try P256PublicKeyEncoding.subjectPublicKeyInfoPEM(fromRawRepresentation: Data(repeating: 0, count: 65)))
    }

    private func highS(fromLowS signature: Data) -> Data {
        let order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
        ]
        let s = Array(signature.suffix(32))
        var result = order
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(order[index]) - Int(s[index]) - borrow
            borrow = value < 0 ? 1 : 0
            if borrow == 1 { value += 256 }
            result[index] = UInt8(value)
        }
        return Data(signature.prefix(32)) + Data(result)
    }
}
