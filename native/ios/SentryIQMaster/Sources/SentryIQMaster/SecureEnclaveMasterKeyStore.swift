import CryptoKit
import Foundation
import LocalAuthentication
import Security

public enum MasterKeyStoreError: Error {
    case secureEnclaveUnavailable
    case passcodeRequired
    case keychain(OSStatus)
    case corruptKeyArchive
    case incompleteKeyArchive
    case invalidPublicKey
    case invalidSignature
}

/// Public-only representation exported to the shared trust-bundle protocol.
public struct MasterPublicKeyDescriptor: Codable, Equatable {
    public let kid: String
    public let alg: String
    public let publicKeyPEM: String

    enum CodingKeys: String, CodingKey {
        case kid
        case alg
        case publicKeyPEM = "public_key_pem"
    }

    public init(kid: String, alg: String, publicKeyPEM: String) {
        self.kid = kid
        self.alg = alg
        self.publicKeyPEM = publicKeyPEM
    }
}

public struct MasterPublicKeySet: Codable, Equatable {
    public let signing: MasterPublicKeyDescriptor
    public let keyAgreement: MasterPublicKeyDescriptor
    public let hardwareAssurance: String

    enum CodingKeys: String, CodingKey {
        case signing
        case keyAgreement = "key_agreement"
        case hardwareAssurance = "hardware_assurance"
    }

    public init(
        signing: MasterPublicKeyDescriptor,
        keyAgreement: MasterPublicKeyDescriptor,
        hardwareAssurance: String = "secure-enclave"
    ) {
        self.signing = signing
        self.keyAgreement = keyAgreement
        self.hardwareAssurance = hardwareAssurance
    }
}

/// Creates and uses separate Secure Enclave P-256 keys for master signing and ECDH.
/// Existing identity is loaded only by loadExisting(); key creation is a separate,
/// explicit first-run operation so restore/migration cannot silently replace a master.
public final class SecureEnclaveMasterKeyStore {
    private struct KeyArchive: Codable {
        let signingKey: Data
        let agreementKey: Data
    }

    private static let processLock = NSLock()
    private let keychainService: String
    private let keychainAccount = "owner-master-keyset-v1"

    public init(keychainService: String = "co.bichet.sentryiq.master-companion") {
        self.keychainService = keychainService
    }

    /// Loads an existing device-bound master keyset. Missing or invalid state fails closed.
    public func loadExisting(context: LAContext? = nil) throws -> MasterPublicKeySet {
        guard SecureEnclave.isAvailable else {
            throw MasterKeyStoreError.secureEnclaveUnavailable
        }

        Self.processLock.lock()
        defer { Self.processLock.unlock() }

        guard let archive = try readArchive() else {
            throw MasterKeyStoreError.incompleteKeyArchive
        }
        return try publicKeySet(from: archive, context: context)
    }

    /// Explicit first-run creation. The caller must only invoke this after the
    /// owner has approved initial master-device setup. It is never called by sign()
    /// or deriveKey(), so a missing key after restore/reinstall cannot auto-regenerate.
    public func createInitialMasterKeyset(context: LAContext? = nil) throws -> MasterPublicKeySet {
        guard SecureEnclave.isAvailable else {
            throw MasterKeyStoreError.secureEnclaveUnavailable
        }

        Self.processLock.lock()
        defer { Self.processLock.unlock() }

        if let existing = try readArchive() {
            return try publicKeySet(from: existing, context: context)
        }

        let signing = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: makeAccessControl(),
            authenticationContext: context
        )
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: makeAccessControl(),
            authenticationContext: context
        )
        let candidate = KeyArchive(
            signingKey: signing.dataRepresentation,
            agreementKey: agreement.dataRepresentation
        )
        let persisted = try saveOrLoadExisting(candidate)
        return try publicKeySet(from: persisted, context: context)
    }

    private func publicKeySet(from archive: KeyArchive, context: LAContext?) throws -> MasterPublicKeySet {
        let signing = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: archive.signingKey,
            authenticationContext: context
        )
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: archive.agreementKey,
            authenticationContext: context
        )
        return try Self.publicKeySet(
            signingRaw: signing.publicKey.rawRepresentation,
            agreementRaw: agreement.publicKey.rawRepresentation
        )
    }

    /// Signs data with the non-exportable Secure Enclave signing key.
    /// Returned bytes are canonical ES256 JOSE r||s with low-S normalization.
    public func sign(_ message: Data, context: LAContext) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw MasterKeyStoreError.secureEnclaveUnavailable
        }
        guard let archive = try readArchive() else {
            throw MasterKeyStoreError.incompleteKeyArchive
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: archive.signingKey,
            authenticationContext: context
        )
        let signature = try key.signature(for: message)
        return try P256PublicKeyEncoding.normalizeES256Signature(signature.rawRepresentation)
    }

    /// Performs P-256 ECDH and derives a 32-byte key with HKDF-SHA256.
    /// Raw shared-secret bytes are never returned to the caller.
    public func deriveKey(
        peerPublicKeyRaw: Data,
        salt: Data,
        sharedInfo: Data,
        context: LAContext
    ) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw MasterKeyStoreError.secureEnclaveUnavailable
        }
        guard let archive = try readArchive() else {
            throw MasterKeyStoreError.incompleteKeyArchive
        }
        let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerPublicKeyRaw)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: archive.agreementKey,
            authenticationContext: context
        )
        let sharedSecret = try key.sharedSecretFromKeyAgreement(with: peer)
        let derived = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: sharedInfo,
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error
        ) else {
            if let error {
                throw error.takeRetainedValue()
            }
            throw MasterKeyStoreError.passcodeRequired
        }
        return access
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private func readArchive() throws -> KeyArchive? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw MasterKeyStoreError.keychain(status)
        }
        do {
            return try JSONDecoder().decode(KeyArchive.self, from: data)
        } catch {
            throw MasterKeyStoreError.corruptKeyArchive
        }
    }

    private func saveOrLoadExisting(_ archive: KeyArchive) throws -> KeyArchive {
        let data = try JSONEncoder().encode(archive)
        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        query[kSecAttrSynchronizable as String] = false

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            return archive
        }
        if status == errSecDuplicateItem, let existing = try readArchive() {
            return existing
        }
        throw MasterKeyStoreError.keychain(status)
    }

    private static func publicKeySet(
        signingRaw: Data,
        agreementRaw: Data
    ) throws -> MasterPublicKeySet {
        guard signingRaw.count == 64, agreementRaw.count == 64,
              signingRaw != agreementRaw else {
            throw MasterKeyStoreError.invalidPublicKey
        }
        let signing = MasterPublicKeyDescriptor(
            kid: P256PublicKeyEncoding.keyID(prefix: "master-signing", rawRepresentation: signingRaw),
            alg: "ES256",
            publicKeyPEM: try P256PublicKeyEncoding.subjectPublicKeyInfoPEM(fromRawRepresentation: signingRaw)
        )
        let agreement = MasterPublicKeyDescriptor(
            kid: P256PublicKeyEncoding.keyID(prefix: "master-key-agreement", rawRepresentation: agreementRaw),
            alg: "ECDH-ES",
            publicKeyPEM: try P256PublicKeyEncoding.subjectPublicKeyInfoPEM(fromRawRepresentation: agreementRaw)
        )
        return MasterPublicKeySet(signing: signing, keyAgreement: agreement)
    }
}

/// Encoding helpers shared by the iOS adapter and its deterministic unit tests.
public enum P256PublicKeyEncoding {
    private static let subjectPublicKeyInfoPrefix = Data([
        0x30, 0x59, 0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00
    ])

    private static let curveOrder: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ]

    private static let halfCurveOrder: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
        0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
    ]

    public static func keyID(prefix: String, rawRepresentation: Data) -> String {
        let digest = SHA256.hash(data: rawRepresentation)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return "\(prefix)-\(hex)"
    }

    public static func subjectPublicKeyInfoPEM(fromRawRepresentation raw: Data) throws -> String {
        guard raw.count == 64 else {
            throw MasterKeyStoreError.invalidPublicKey
        }
        let x963 = Data([0x04]) + raw
        let der = subjectPublicKeyInfoPrefix + x963
        let base64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(base64)-----END PUBLIC KEY-----\n"
    }

    public static func normalizeES256Signature(_ raw: Data) throws -> Data {
        guard raw.count == 64 else {
            throw MasterKeyStoreError.invalidSignature
        }
        let r = Array(raw.prefix(32))
        var s = Array(raw.suffix(32))
        let zero = [UInt8](repeating: 0, count: 32)
        guard r != zero, r.lexicographicallyPrecedes(curveOrder),
              s != zero, s.lexicographicallyPrecedes(curveOrder) else {
            throw MasterKeyStoreError.invalidSignature
        }

        if halfCurveOrder.lexicographicallyPrecedes(s) {
            s = subtract(s, from: curveOrder)
        }
        return Data(r + s)
    }

    private static func subtract(_ subtrahend: [UInt8], from minuend: [UInt8]) -> [UInt8] {
        var result = minuend
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var value = Int(minuend[index]) - Int(subtrahend[index]) - borrow
            borrow = value < 0 ? 1 : 0
            if borrow == 1 {
                value += 256
            }
            result[index] = UInt8(value)
        }
        return result
    }
}
