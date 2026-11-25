import Foundation
import Security

public struct TrustRegistryAnchor {
    public let sequence: UInt64
    public let bundleSHA256: Data
    public let signedPayload: Data
    public let signature: Data

    public init(sequence: UInt64, bundleSHA256: Data, signedPayload: Data, signature: Data) {
        self.sequence = sequence
        self.bundleSHA256 = bundleSHA256
        self.signedPayload = signedPayload
        self.signature = signature
    }
}

public struct ProtectedTrustState {
    public let sequence: UInt64
    public let bundleSHA256: Data
    public let bundle: Data
}

/**
 Keychain-backed cache for the accepted public trust bundle.

 The Keychain item is device-only and accessible only while unlocked. It is not
 itself an anti-rollback anchor: every operation requires an independently
 verified signed registry anchor and exact sequence/digest match.
 */
public final class ProtectedTrustStateStore {
    public enum StoreError: Error {
        case invalidRegistryAnchor
        case missingState
        case keychain(OSStatus)
        case corruptState
        case rollbackDetected
        case digestMismatch
    }

    private struct Archive: Codable {
        let sequence: UInt64
        let bundleSHA256: Data
        let bundle: Data
    }

    private let service: String
    private let account = "accepted-trust-bundle-v1"
    private let verifyRegistryAnchor: (TrustRegistryAnchor) -> Bool

    public init(
        service: String = "co.bichet.sentryiq.master-companion",
        verifyRegistryAnchor: @escaping (TrustRegistryAnchor) -> Bool
    ) {
        self.service = service
        self.verifyRegistryAnchor = verifyRegistryAnchor
    }

    public func load(anchor: TrustRegistryAnchor) throws -> ProtectedTrustState {
        try validate(anchor)
        guard let data = try readItem() else { throw StoreError.missingState }
        let archive: Archive
        do { archive = try JSONDecoder().decode(Archive.self, from: data) }
        catch { throw StoreError.corruptState }

        guard archive.sequence == anchor.sequence,
              archive.bundleSHA256 == anchor.bundleSHA256,
              Data(SHA256Digest.hash(archive.bundle)) == anchor.bundleSHA256 else {
            throw StoreError.rollbackDetected
        }
        return ProtectedTrustState(
            sequence: archive.sequence,
            bundleSHA256: archive.bundleSHA256,
            bundle: archive.bundle
        )
    }

    public func save(bundle: Data, anchor: TrustRegistryAnchor) throws {
        try validate(anchor)
        let digest = Data(SHA256Digest.hash(bundle))
        guard digest == anchor.bundleSHA256 else { throw StoreError.digestMismatch }

        if let currentData = try readItem() {
            guard let current = try? JSONDecoder().decode(Archive.self, from: currentData) else {
                throw StoreError.corruptState
            }
            if anchor.sequence < current.sequence ||
                (anchor.sequence == current.sequence && anchor.bundleSHA256 != current.bundleSHA256) {
                throw StoreError.rollbackDetected
            }
        }

        let archive = Archive(
            sequence: anchor.sequence,
            bundleSHA256: digest,
            bundle: bundle
        )
        let encoded = try JSONEncoder().encode(archive)
        try writeItem(encoded)
    }

    private func validate(_ anchor: TrustRegistryAnchor) throws {
        guard anchor.sequence > 0,
              anchor.bundleSHA256.count == 32,
              !anchor.signedPayload.isEmpty,
              !anchor.signature.isEmpty,
              verifyRegistryAnchor(anchor) else {
            throw StoreError.invalidRegistryAnchor
        }
    }

    private func readItem() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw StoreError.keychain(status)
        }
        return data
    }

    private func writeItem(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var insertion = query
            attributes.forEach { insertion[$0.key] = $0.value }
            let addStatus = SecItemAdd(insertion as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw StoreError.keychain(addStatus) }
        } else if status != errSecSuccess {
            throw StoreError.keychain(status)
        }
    }
}

private enum SHA256Digest {
    static func hash(_ data: Data) -> [UInt8] {
        // CommonCrypto is available on iOS and avoids a dependency on a third-party package.
        var digest = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &digest)
        }
        return digest
    }
}
