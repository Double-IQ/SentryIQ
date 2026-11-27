import CryptoKit
import Foundation
import Security

enum TrustRegistryAnchorPolicy {
    static func isValidInitialAnchor(sequence: UInt64, previousBundleSHA256: Data?) -> Bool {
        sequence == 1 && previousBundleSHA256 == nil
    }

    static func isFresh(issuedAt: UInt64, expiresAt: UInt64, now: UInt64) -> Bool {
        guard issuedAt > 0, expiresAt > now, expiresAt > issuedAt else { return false }
        if issuedAt > now && issuedAt - now > 60 { return false }
        if now > issuedAt && now - issuedAt > 86_400 { return false }
        return expiresAt - issuedAt <= 86_400
    }
}

public struct TrustRegistryAnchor {
    public let sequence: UInt64
    public let bundleSHA256: Data
    public let signedPayload: Data
    public let signature: Data
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let previousBundleSHA256: Data?
    public let ownerID: String
    public let signerKeyID: String

    public init(sequence: UInt64, bundleSHA256: Data, signedPayload: Data, signature: Data, issuedAt: UInt64, expiresAt: UInt64, previousBundleSHA256: Data?, ownerID: String, signerKeyID: String) {
        self.sequence = sequence
        self.bundleSHA256 = bundleSHA256
        self.signedPayload = signedPayload
        self.signature = signature
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.previousBundleSHA256 = previousBundleSHA256
        self.ownerID = ownerID
        self.signerKeyID = signerKeyID
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

    private static let processLock = NSRecursiveLock()
    private let service: String
    private let account = "accepted-trust-bundle-v1"
    private let expectedOwnerID: String
    private let trustedSignerKeys: [RegistryAnchorSignerKey]

    public init(
        service: String = "co.bichet.sentryiq.master-companion",
        expectedOwnerID: String,
        trustedSignerKeys: [RegistryAnchorSignerKey]
    ) {
        self.service = service
        self.expectedOwnerID = expectedOwnerID
        self.trustedSignerKeys = trustedSignerKeys
    }

    public func load(anchor: TrustRegistryAnchor, now: UInt64 = UInt64(Date().timeIntervalSince1970)) throws -> ProtectedTrustState {
        Self.processLock.lock()
        defer { Self.processLock.unlock() }
        try validate(anchor, now: now)
        guard let data = try readItem() else { throw StoreError.missingState }
        let archive: Archive
        do { archive = try JSONDecoder().decode(Archive.self, from: data) }
        catch { throw StoreError.corruptState }

        guard archive.sequence == anchor.sequence,
              archive.bundleSHA256 == anchor.bundleSHA256,
              Data(SHA256.hash(data: archive.bundle)) == anchor.bundleSHA256 else {
            throw StoreError.rollbackDetected
        }
        return ProtectedTrustState(
            sequence: archive.sequence,
            bundleSHA256: archive.bundleSHA256,
            bundle: archive.bundle
        )
    }

    public func save(bundle: Data, anchor: TrustRegistryAnchor, now: UInt64 = UInt64(Date().timeIntervalSince1970)) throws {
        Self.processLock.lock()
        defer { Self.processLock.unlock() }
        try validate(anchor, now: now)
        let digest = Data(SHA256.hash(data: bundle))
        guard digest == anchor.bundleSHA256 else { throw StoreError.digestMismatch }

        if let currentData = try readItem() {
            guard let current = try? JSONDecoder().decode(Archive.self, from: currentData) else {
                throw StoreError.corruptState
            }
            if anchor.sequence < current.sequence ||
                (anchor.sequence == current.sequence && anchor.bundleSHA256 != current.bundleSHA256) {
                throw StoreError.rollbackDetected
            }
            if anchor.sequence > current.sequence {
                guard current.sequence < UInt64.max,
                      anchor.sequence == current.sequence + 1,
                      anchor.previousBundleSHA256 == current.bundleSHA256 else {
                    throw StoreError.rollbackDetected
                }
            }
        } else if !TrustRegistryAnchorPolicy.isValidInitialAnchor(
            sequence: anchor.sequence,
            previousBundleSHA256: anchor.previousBundleSHA256
        ) {
            throw StoreError.rollbackDetected
        }

        let archive = Archive(
            sequence: anchor.sequence,
            bundleSHA256: digest,
            bundle: bundle
        )
        let encoded = try JSONEncoder().encode(archive)
        try writeItem(encoded)

        // Treat a successful Keychain API return as provisional until the
        // committed record can be read back and independently checked.
        guard let committedData = try readItem(),
              let committed = try? JSONDecoder().decode(Archive.self, from: committedData),
              committed.sequence == archive.sequence,
              committed.bundleSHA256 == archive.bundleSHA256,
              committed.bundle == archive.bundle,
              Data(SHA256.hash(data: committed.bundle)) == anchor.bundleSHA256 else {
            throw StoreError.corruptState
        }
    }

    private func validate(_ anchor: TrustRegistryAnchor, now: UInt64) throws {
        guard anchor.sequence > 0,
              anchor.bundleSHA256.count == 32,
              !anchor.signedPayload.isEmpty,
              !anchor.signature.isEmpty,
              TrustRegistryAnchorPolicy.isFresh(issuedAt: anchor.issuedAt, expiresAt: anchor.expiresAt, now: now),
              anchor.previousBundleSHA256 == nil || anchor.previousBundleSHA256?.count == 32 else {
            throw StoreError.invalidRegistryAnchor
        }
        do {
            try RegistryAnchorVerifier.verify(
                anchor,
                expectedOwnerID: expectedOwnerID,
                trustedSignerKeys: trustedSignerKeys,
                now: now
            )
        } catch {
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
        guard data.count <= 4 * 1024 * 1024 + 128 else { throw StoreError.corruptState }
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
