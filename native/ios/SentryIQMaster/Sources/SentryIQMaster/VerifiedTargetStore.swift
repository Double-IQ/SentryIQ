import CryptoKit
import Darwin
import Foundation
import Security

/// Encrypted, atomic content-addressed storage for bytes already accepted by the Rust TUF verifier.
public final class VerifiedTargetStore {
    public enum StoreError: Error {
        case invalidPath
        case invalidSize
        case keychain(OSStatus)
        case corruptRecord
        case fileSystem(Int32)
    }

    private static let keyLock = NSRecursiveLock()
    private let directory: URL
    private let service: String
    private let account = "verified-target-aes-gcm-v1"
    private let maximumTargetBytes = 16 * 1024 * 1024

    public init(
        directory: URL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SentryIQ/VerifiedTargets", isDirectory: true),
        service: String = "co.bichet.sentryiq.master-companion"
    ) throws {
        self.directory = directory
        self.service = service
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        var directoryInfo = stat()
        guard lstat(directory.path, &directoryInfo) == 0,
              (directoryInfo.st_mode & S_IFMT) == S_IFDIR else {
            throw StoreError.corruptRecord
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var protectedDirectory = directory
        try protectedDirectory.setResourceValues(values)
    }

    @discardableResult
    public func saveVerifiedTarget(path: String, bytes: Data) throws -> String {
        try validatePath(path)
        guard !bytes.isEmpty, bytes.count <= maximumTargetBytes else { throw StoreError.invalidSize }
        let digest = Data(SHA256.hash(data: bytes))
        let key = try loadOrCreateKey()
        let sealed = try AES.GCM.seal(bytes, using: key, authenticating: associatedData(path: path, digest: digest))
        guard let combined = sealed.combined else { throw StoreError.corruptRecord }
        var record = Data("SIQVT1".utf8)
        record.append(digest)
        record.append(combined)
        let destination = targetURL(path: path)
        try atomicWrite(record, to: destination)
        guard try loadVerifiedTarget(path: path) == bytes else { throw StoreError.corruptRecord }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public func loadVerifiedTarget(path: String) throws -> Data {
        try validatePath(path)
        let url = targetURL(path: path)
        var info = stat()
        guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 6 + 32 + 28,
              info.st_size <= maximumTargetBytes + 6 + 32 + 28 else {
            throw StoreError.corruptRecord
        }
        let record = try Data(contentsOf: url)
        guard record.prefix(6) == Data("SIQVT1".utf8) else { throw StoreError.corruptRecord }
        let digest = Data(record[6..<38])
        let sealedBytes = Data(record.dropFirst(38))
        let box = try AES.GCM.SealedBox(combined: sealedBytes)
        let plaintext = try AES.GCM.open(box, using: loadOrCreateKey(), authenticating: associatedData(path: path, digest: digest))
        guard Data(SHA256.hash(data: plaintext)) == digest else { throw StoreError.corruptRecord }
        return plaintext
    }

    private func validatePath(_ path: String) throws {
        guard path.range(of: "^[A-Za-z0-9._/-]{1,512}$", options: .regularExpression) != nil,
              !path.contains("//"),
              !path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) else {
            throw StoreError.invalidPath
        }
    }

    private func targetURL(path: String) -> URL {
        let name = Data(SHA256.hash(data: Data(path.utf8))).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent(name + ".target", isDirectory: false)
    }

    private func associatedData(path: String, digest: Data) -> Data {
        var value = Data("SENTRYIQ-VERIFIED-TARGET-V1\n".utf8)
        value.append(Data(path.utf8))
        value.append(0)
        value.append(digest)
        return value
    }

    private func atomicWrite(_ data: Data, to destination: URL) throws {
        let temporary = directory.appendingPathComponent(UUID().uuidString + ".tmp")
        do {
            try data.write(to: temporary, options: [])
            let handle = try FileHandle(forWritingTo: temporary)
            try handle.synchronize()
            try handle.close()
            var existing = stat()
            if lstat(destination.path, &existing) == 0 && (existing.st_mode & S_IFMT) == S_IFLNK {
                throw StoreError.corruptRecord
            }
            guard rename(temporary.path, destination.path) == 0 else {
                throw StoreError.fileSystem(errno)
            }
            let directoryFD = open(directory.path, O_RDONLY)
            if directoryFD >= 0 {
                _ = fsync(directoryFD)
                _ = close(directoryFD)
            }
        } catch {
            _ = unlink(temporary.path)
            throw error
        }
    }

    private func loadOrCreateKey() throws -> SymmetricKey {
        Self.keyLock.lock()
        defer { Self.keyLock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound else { throw StoreError.keychain(status) }
        var bytes = Data(count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard randomStatus == errSecSuccess else { throw StoreError.keychain(randomStatus) }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus == errSecDuplicateItem { return try loadOrCreateKey() }
        guard addStatus == errSecSuccess else { throw StoreError.keychain(addStatus) }
        return SymmetricKey(data: bytes)
    }
}
