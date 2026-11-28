import CryptoKit
import Foundation
import WebKit

/// Same-origin transport for the authenticated bootstrap endpoint.
/// Responses remain untrusted until the caller verifies the registry anchor,
/// canonical bundle, and TUF chain against independently pinned keys.
public final class OwnerBootstrapHTTPClient {
    public struct Snapshot {
        public let ownerID: String
        public let sequence: String
        public let bundleSHA256: String
        public let canonicalBundle: Data
        public let registryAnchorPayload: Data
        public let registryAnchorSignature: Data
        public let tufMetadata: [String: Data]
        public let csrfToken: String
    }

    public struct Challenge {
        public let value: String
        public let bytes: Data
        public let purpose: String
        public let bundleSHA256: String
        public let expiresAt: UInt64
    }

    public struct ApprovalProof {
        public let challenge: String
        public let bundleSHA256: String
        public let rootRole: String
        public let rootKeyID: String
        public let rootFingerprint: String
        public let deviceKeysetDigest: String
        public let purpose: String
        public let signature: Data
    }

    public struct Receipt {
        public let receiptID: String
    }

    public struct PreparedBootstrapState {
        public let snapshot: Snapshot
        public let anchor: TrustRegistryAnchor
        public let cachedState: ProtectedTrustState?
        public let verifiedTUFMetadata: [String: Data]
    }

    public struct VerifiedBootstrapState {
        public let snapshot: Snapshot
        public let anchor: TrustRegistryAnchor
        public let trustState: ProtectedTrustState
    }

    public enum BootstrapResult {
        case approvalRequired(PreparedBootstrapState)
        case alreadyAccepted(VerifiedBootstrapState)
    }

    public enum ClientError: Error {
        case invalidOrigin
        case invalidResponse
        case httpStatus(Int)
        case invalidEncoding
        case missingSessionCookie
    }

    private let endpoint: URL
    private let session: URLSession

    /// Pass the URLSession that shares the authenticated SentryIQ session cookie.
    /// Copies only the secure, HttpOnly session cookie for this exact HTTPS host
    /// from the authenticated WKWebView into URLSession's shared cookie store.
    public static func synchronizeSessionCookie(
        from webView: WKWebView,
        origin: URL,
        sessionCookieName: String,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        guard origin.scheme?.lowercased() == "https",
              let host = origin.host, !host.isEmpty,
              origin.user == nil, origin.password == nil,
              origin.query == nil, origin.fragment == nil,
              sessionCookieName.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil,
              let currentURL = webView.url,
              currentURL.scheme?.lowercased() == "https",
              currentURL.host?.lowercased() == host.lowercased(),
              (currentURL.port ?? 443) == (origin.port ?? 443) else {
            completion(.failure(ClientError.invalidOrigin))
            return
        }
        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
            let endpointPath = "/api/owner-bootstrap.php"
            let matching = cookies.filter { cookie in
                let domain = cookie.domain.hasPrefix(".") ? String(cookie.domain.dropFirst()) : cookie.domain
                let pathMatches = endpointPath == cookie.path || endpointPath.hasPrefix(cookie.path.hasSuffix("/") ? cookie.path : cookie.path + "/")
                return cookie.name == sessionCookieName
                    && domain == host
                    && cookie.isSecure
                    && cookie.isHTTPOnly
                    && pathMatches
                    && (cookie.expiresDate == nil || cookie.expiresDate! > Date())
            }
            guard let sessionCookie = matching.max(by: { $0.path.count < $1.path.count }) else {
                completion(.failure(ClientError.missingSessionCookie))
                return
            }
            HTTPCookieStorage.shared.setCookie(sessionCookie)
            completion(.success(()))
        }
    }

    /// Remove only the configured session cookie from the native URLSession cookie store.
    /// Call on lock, logout, explicit session expiry, and authentication failure.
    /// This intentionally leaves the WebView's browser session intact on lock.
    public static func clearNativeSessionCookie(
        origin: URL,
        sessionCookieName: String,
        cookieStorage: HTTPCookieStorage = .shared
    ) {
        guard origin.scheme?.lowercased() == "https",
              let host = origin.host, !host.isEmpty,
              sessionCookieName.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil else {
            return
        }
        let endpointPath = "/api/owner-bootstrap.php"
        let cookies = cookieStorage.cookies ?? []
        for cookie in cookies {
            let domain = cookie.domain.hasPrefix(".") ? String(cookie.domain.dropFirst()) : cookie.domain
            let pathMatches = endpointPath == cookie.path ||
                endpointPath.hasPrefix(cookie.path.hasSuffix("/") ? cookie.path : cookie.path + "/")
            if cookie.name == sessionCookieName && domain == host && cookie.isSecure && cookie.isHTTPOnly && pathMatches {
                cookieStorage.deleteCookie(cookie)
            }
        }
    }

    public init(baseURL: URL, session: URLSession = .shared) throws {
        guard baseURL.scheme?.lowercased() == "https",
              let host = baseURL.host, !host.isEmpty,
              baseURL.user == nil, baseURL.password == nil,
              baseURL.query == nil, baseURL.fragment == nil else {
            throw ClientError.invalidOrigin
        }
        self.endpoint = baseURL.appendingPathComponent("api/owner-bootstrap.php")
        self.session = session
    }

    public func fetchSnapshot(
        completion: @escaping (Result<Snapshot, Error>) -> Void
    ) {
        request(method: "GET", body: nil, csrfToken: nil) { result in
            completion(result.flatMap { object in
                do {
                    guard try Self.string(object, "protocol") == "SENTRYIQ-OWNER-BOOTSTRAP-API-V1" else {
                        throw ClientError.invalidResponse
                    }
                    let bundle = try Self.decodeBase64URL(Self.string(object, "bundle"))
                    let anchor = try Self.decodeBase64URL(Self.string(object, "registry_anchor_payload"))
                    let signature = try Self.decodeBase64URL(Self.string(object, "registry_anchor_signature"))
                    let digest = try Self.string(object, "bundle_sha256")
                    guard let encodedMetadata = object["tuf_metadata"] as? [String: String],
                          encodedMetadata.count >= 4, encodedMetadata.count <= 64 else {
                        throw ClientError.invalidResponse
                    }
                    var tufMetadata: [String: Data] = [:]
                    var totalMetadataBytes = 0
                    for (name, encoded) in encodedMetadata {
                        guard name.range(of: "^[a-z0-9][a-z0-9._/-]{0,127}$", options: .regularExpression) != nil else {
                            throw ClientError.invalidResponse
                        }
                        let bytes = try Self.decodeBase64URL(encoded)
                        guard !bytes.isEmpty, bytes.count <= 1_048_576 else { throw ClientError.invalidResponse }
                        totalMetadataBytes += bytes.count
                        guard totalMetadataBytes <= 2 * 1024 * 1024 else { throw ClientError.invalidResponse }
                        tufMetadata[name] = bytes
                    }
                    guard ["root.json", "timestamp.json", "snapshot.json", "targets.json"].allSatisfy({ tufMetadata[$0] != nil }),
                          bundle.count <= 262_144, anchor.count <= 4_096,
                          signature.count == 64, digest.count == 64 else {
                        throw ClientError.invalidResponse
                    }
                    return .success(Snapshot(
                        ownerID: try Self.string(object, "owner_id"),
                        sequence: try Self.string(object, "sequence"),
                        bundleSHA256: digest,
                        canonicalBundle: bundle,
                        registryAnchorPayload: anchor,
                        registryAnchorSignature: signature,
                        tufMetadata: tufMetadata,
                        csrfToken: try Self.string(object, "csrf_token")
                    ))
                } catch { return .failure(error) }
            })
        }
    }

    /// Verify the delivered TUF metadata with the shared Rust core and return the exact accepted bytes.
    public static func verifyTUFRefresh(
        snapshot: Snapshot,
        cachedState: ProtectedTrustState?,
        referenceTime: UInt64 = UInt64(Date().timeIntervalSince1970)
    ) throws -> [String: Data] {
        guard referenceTime <= UInt64(Int64.max),
              let bundle = try JSONSerialization.jsonObject(with: snapshot.canonicalBundle) as? [String: Any],
              let tuf = bundle["sigstore_tuf"] as? [String: Any],
              let rootDigestText = tuf["root_digest"] as? String else {
            throw ClientError.invalidResponse
        }
        let rootDigest = try decodeHex(rootDigestText)
        guard let initialRoot = snapshot.tufMetadata["root.json"] else {
            throw ClientError.invalidResponse
        }
        let candidateNames = snapshot.tufMetadata.keys.filter {
            $0.range(of: "^root/[0-9]+\\.json$", options: .regularExpression) != nil
        }.sorted {
            let left = Int($0.dropFirst(5).dropLast(5)) ?? 0
            let right = Int($1.dropFirst(5).dropLast(5)) ?? 0
            return left < right
        }
        let candidateRoots = candidateNames.compactMap { snapshot.tufMetadata[$0] }
        let cached = cachedState?.tufMetadata ?? [:]
        let accepted = SentryIQTufTrustVerifier.verifyMetadataRefresh(
            initialRoot: initialRoot,
            expectedInitialRootSHA256: rootDigest,
            candidateRoots: candidateRoots,
            cachedTimestamp: cached["timestamp.json"],
            cachedSnapshot: cached["snapshot.json"],
            cachedTargets: cached["targets.json"],
            newTimestamp: snapshot.tufMetadata["timestamp.json"]!,
            newSnapshot: snapshot.tufMetadata["snapshot.json"]!,
            newTargets: snapshot.tufMetadata["targets.json"]!,
            referenceTimeUnixSeconds: Int64(referenceTime)
        )
        guard accepted else { throw ClientError.invalidResponse }
        var acceptedMetadata: [String: Data] = [
            "root.json": initialRoot,
            "timestamp.json": snapshot.tufMetadata["timestamp.json"]!,
            "snapshot.json": snapshot.tufMetadata["snapshot.json"]!,
            "targets.json": snapshot.tufMetadata["targets.json"]!
        ]
        for name in candidateNames { acceptedMetadata[name] = snapshot.tufMetadata[name] }
        return acceptedMetadata
    }

    /// Verify downloaded target bytes against signed top-level and delegated TUF metadata.
    private static func verifyTargetBytes(
        _ targetBytes: Data,
        targetPath: String,
        snapshot: Snapshot,
        cachedState: ProtectedTrustState?,
        referenceTime: UInt64 = UInt64(Date().timeIntervalSince1970)
    ) throws -> Bool {
        guard referenceTime <= UInt64(Int64.max),
              let bundle = try JSONSerialization.jsonObject(with: snapshot.canonicalBundle) as? [String: Any],
              let tuf = bundle["sigstore_tuf"] as? [String: Any],
              let rootDigestText = tuf["root_digest"] as? String,
              let initialRoot = snapshot.tufMetadata["root.json"] else {
            throw ClientError.invalidResponse
        }
        let rootDigest = try decodeHex(rootDigestText)
        let candidateNames = snapshot.tufMetadata.keys.filter {
            $0.range(of: "^root/[0-9]+\\.json$", options: .regularExpression) != nil
        }.sorted {
            (Int($0.dropFirst(5).dropLast(5)) ?? 0) < (Int($1.dropFirst(5).dropLast(5)) ?? 0)
        }
        let candidateRoots = candidateNames.compactMap { snapshot.tufMetadata[$0] }
        let roles: [String]
        if let orderBytes = snapshot.tufMetadata["delegated-order.json"] {
            roles = try JSONDecoder().decode([String].self, from: orderBytes)
        } else {
            roles = []
        }
        let delegated = try roles.map { role -> Data in
            guard role.range(of: "^[a-z0-9._-]{1,128}$", options: .regularExpression) != nil,
                  let metadata = snapshot.tufMetadata["delegated/\\(role).json"] else {
                throw ClientError.invalidResponse
            }
            return metadata
        }
        let cached = cachedState?.tufMetadata ?? [:]
        return SentryIQTufTrustVerifier.verifyTargetBytes(
            initialRoot: initialRoot,
            expectedInitialRootSHA256: rootDigest,
            candidateRoots: candidateRoots,
            cachedTimestamp: cached["timestamp.json"],
            cachedSnapshot: cached["snapshot.json"],
            cachedTargets: cached["targets.json"],
            newTimestamp: snapshot.tufMetadata["timestamp.json"]!,
            newSnapshot: snapshot.tufMetadata["snapshot.json"]!,
            newTargets: snapshot.tufMetadata["targets.json"]!,
            delegatedRoles: roles,
            delegatedMetadata: delegated,
            targetPath: targetPath,
            targetBytes: targetBytes,
            referenceTimeUnixSeconds: Int64(referenceTime)
        )
    }

    /// Fetch, verify the separately pinned registry anchor, validate TUF, then persist atomically.
    public func fetchAndVerifySnapshot(
        using store: ProtectedTrustStateStore,
        verifyTuf: @escaping (Snapshot, ProtectedTrustState?) throws -> [String: Data],
        completion: @escaping (Result<PreparedBootstrapState, Error>) -> Void
    ) {
        fetchSnapshot { result in
            completion(result.flatMap { snapshot in
                do {
                    let anchor = try Self.decodeAnchor(snapshot)
                    guard Data(SHA256.hash(data: snapshot.canonicalBundle)) == anchor.bundleSHA256,
                          snapshot.bundleSHA256 == Self.encodeHex(anchor.bundleSHA256),
                          snapshot.sequence == String(anchor.sequence) else {
                        throw ClientError.invalidResponse
                    }
                    let cachedState = try store.loadPreviousState(for: anchor)
                    let verifiedMetadata = try verifyTuf(snapshot, cachedState)
                    guard ["root.json", "timestamp.json", "snapshot.json", "targets.json"].allSatisfy({ verifiedMetadata[$0] != nil }),
                          verifiedMetadata.allSatisfy({ snapshot.tufMetadata[$0.key] == $0.value }) else {
                        throw ClientError.invalidResponse
                    }
                    return .success(PreparedBootstrapState(
                        snapshot: snapshot,
                        anchor: anchor,
                        cachedState: cachedState,
                        verifiedTUFMetadata: verifiedMetadata
                    ))
                } catch { return .failure(error) }
            })
        }
    }

    public func fetchAndVerifyTUFState(
        using store: ProtectedTrustStateStore,
        completion: @escaping (Result<BootstrapResult, Error>) -> Void
    ) {
        fetchAndVerifySnapshot(using: store, verifyTuf: { snapshot, cachedState in
            try Self.verifyTUFRefresh(snapshot: snapshot, cachedState: cachedState)
        }) { result in
            completion(result.flatMap { prepared in
                if let cached = prepared.cachedState,
                   cached.sequence == prepared.anchor.sequence,
                   cached.bundleSHA256 == prepared.anchor.bundleSHA256,
                   let receiptID = cached.bootstrapReceiptID {
                    do {
                        try store.save(
                            bundle: prepared.snapshot.canonicalBundle,
                            anchor: prepared.anchor,
                            tufMetadata: prepared.verifiedTUFMetadata,
                            bootstrapReceiptID: receiptID
                        )
                        let trustState = try store.load(anchor: prepared.anchor)
                        return .success(.alreadyAccepted(VerifiedBootstrapState(
                            snapshot: prepared.snapshot,
                            anchor: prepared.anchor,
                            trustState: trustState
                        )))
                    } catch { return .failure(error) }
                }
                return .success(.approvalRequired(prepared))
            })
        }
    }

    private static func decodeAnchor(_ snapshot: Snapshot) throws -> TrustRegistryAnchor {
        guard let object = try JSONSerialization.jsonObject(with: snapshot.registryAnchorPayload) as? [String: Any],
              let sequenceText = object["sequence"] as? String,
              let sequence = UInt64(sequenceText),
              let digestText = object["bundle_sha256"] as? String,
              let digest = try? decodeHex(digestText),
              let issuedAt = integer(object["issued_at"]),
              let expiresAt = integer(object["expires_at"]),
              let ownerID = object["owner_id"] as? String,
              let signerKeyID = object["signer_kid"] as? String else {
            throw ClientError.invalidResponse
        }
        let previous: Data?
        if object["previous_bundle_sha256"] is NSNull { previous = nil }
        else if let text = object["previous_bundle_sha256"] as? String { previous = try decodeHex(text) }
        else { throw ClientError.invalidResponse }
        guard ownerID == snapshot.ownerID, digest.count == 32,
              previous == nil || previous?.count == 32 else { throw ClientError.invalidResponse }
        return TrustRegistryAnchor(
            sequence: sequence,
            bundleSHA256: digest,
            signedPayload: snapshot.registryAnchorPayload,
            signature: snapshot.registryAnchorSignature,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            previousBundleSHA256: previous,
            ownerID: ownerID,
            signerKeyID: signerKeyID
        )
    }

    private static func integer(_ value: Any?) -> UInt64? {
        guard let number = value as? NSNumber, number.doubleValue >= 0,
              number.doubleValue.rounded(.towardZero) == number.doubleValue else { return nil }
        return number.uint64Value
    }

    private static func encodeHex(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }

    private static func decodeHex(_ value: String) throws -> Data {
        guard value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else {
            throw ClientError.invalidEncoding
        }
        var bytes = Data()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { throw ClientError.invalidEncoding }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    public func fetchTarget(
        path: String,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        guard path.range(of: "^[A-Za-z0-9._/-]{1,512}$", options: .regularExpression) != nil,
              !path.hasPrefix("/"),
              !path.hasSuffix("/"),
              !path.contains("//"),
              !path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }),
              var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false) else {
            completion(.failure(ClientError.invalidResponse)); return
        }
        components.queryItems = [URLQueryItem(name: "target", value: path)]
        guard let url = components.url else { completion(.failure(ClientError.invalidResponse)); return }
        request(url: url, method: "GET", body: nil, csrfToken: nil, maxResponseBytes: 22_400_000) { result in
            completion(result.flatMap { object in
                do {
                    guard try Self.string(object, "protocol") == "SENTRYIQ-OWNER-BOOTSTRAP-API-V1",
                          try Self.string(object, "target_path") == path else {
                        throw ClientError.invalidResponse
                    }
                    let target = try Self.decodeBase64URL(Self.string(object, "target"))
                    guard !target.isEmpty, target.count <= 16 * 1024 * 1024 else {
                        throw ClientError.invalidResponse
                    }
                    return .success(target)
                } catch { return .failure(error) }
            })
        }
    }

    public func fetchAndVerifyTarget(
        path: String,
        verifiedState: VerifiedBootstrapState,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        fetchTarget(path: path) { result in
            completion(result.flatMap { bytes in
                do {
                    guard try Self.verifyTargetBytes(
                        bytes,
                        targetPath: path,
                        snapshot: verifiedState.snapshot,
                        cachedState: verifiedState.trustState
                    ) else { throw ClientError.invalidResponse }
                    return .success(bytes)
                } catch { return .failure(error) }
            })
        }
    }

    public func fetchVerifyAndPersistTarget(
        path: String,
        verifiedState: VerifiedBootstrapState,
        targetStore: VerifiedTargetStore,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        fetchAndVerifyTarget(path: path, verifiedState: verifiedState) { result in
            completion(result.flatMap { bytes in
                do { return .success(try targetStore.saveVerifiedTarget(path: path, bytes: bytes)) }
                catch { return .failure(error) }
            })
        }
    }

    public func issueChallenge(
        csrfToken: String,
        completion: @escaping (Result<Challenge, Error>) -> Void
    ) {
        request(method: "POST", body: ["action": "challenge"], csrfToken: csrfToken) { result in
            completion(result.flatMap { object in
                do {
                    let challenge = try Self.string(object, "challenge")
                    guard challenge.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
                        throw ClientError.invalidResponse
                    }
                    let purpose = try Self.string(object, "purpose")
                    guard purpose == "bootstrap-release-root" else { throw ClientError.invalidResponse }
                    return .success(Challenge(
                        value: challenge,
                        bytes: try Self.decodeBase64URL(challenge),
                        purpose: purpose,
                        bundleSHA256: try Self.string(object, "bundle_sha256"),
                        expiresAt: try Self.uint64(object, "expires_at")
                    ))
                } catch { return .failure(error) }
            })
        }
    }

    public func submitApproval(
        _ proof: ApprovalProof,
        csrfToken: String,
        completion: @escaping (Result<Receipt, Error>) -> Void
    ) {
        let body: [String: Any] = [
            "action": "approve",
            "challenge": proof.challenge,
            "bundle_sha256": proof.bundleSHA256,
            "root_role": proof.rootRole,
            "root_key_id": proof.rootKeyID,
            "root_fingerprint": proof.rootFingerprint,
            "device_keyset_digest": proof.deviceKeysetDigest,
            "purpose": proof.purpose,
            "signature": Self.encodeBase64URL(proof.signature)
        ]
        request(method: "POST", body: body, csrfToken: csrfToken) { result in
            completion(result.flatMap { object in
                do {
                    let receipt = try Self.string(object, "receipt_id")
                    guard receipt.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
                        throw ClientError.invalidResponse
                    }
                    return .success(Receipt(receiptID: receipt))
                } catch { return .failure(error) }
            })
        }
    }

    /// Persist the candidate only after the server has accepted the owner's one-use signature.
    public func submitApproval(
        _ proof: ApprovalProof,
        csrfToken: String,
        preparedState: PreparedBootstrapState,
        using store: ProtectedTrustStateStore,
        completion: @escaping (Result<(Receipt, VerifiedBootstrapState), Error>) -> Void
    ) {
        submitApproval(proof, csrfToken: csrfToken) { result in
            completion(result.flatMap { receipt in
                do {
                    try store.save(
                        bundle: preparedState.snapshot.canonicalBundle,
                        anchor: preparedState.anchor,
                        tufMetadata: preparedState.verifiedTUFMetadata,
                        bootstrapReceiptID: receipt.receiptID
                    )
                    let trustState = try store.load(anchor: preparedState.anchor)
                    return .success((
                        receipt,
                        VerifiedBootstrapState(
                            snapshot: preparedState.snapshot,
                            anchor: preparedState.anchor,
                            trustState: trustState
                        )
                    ))
                } catch { return .failure(error) }
            })
        }
    }

    public func submitApproval(
        _ proof: OwnerFingerprintApprovalCeremony.ApprovalProof,
        challenge: Challenge,
        csrfToken: String,
        preparedState: PreparedBootstrapState,
        using store: ProtectedTrustStateStore,
        completion: @escaping (Result<(Receipt, VerifiedBootstrapState), Error>) -> Void
    ) {
        guard proof.challenge == challenge.bytes,
              proof.bundleFingerprint == challenge.bundleSHA256,
              proof.purpose == challenge.purpose,
              proof.expiresAt == challenge.expiresAt else {
            completion(.failure(ClientError.invalidResponse))
            return
        }
        let transportProof = ApprovalProof(
            challenge: challenge.value,
            bundleSHA256: proof.bundleFingerprint,
            rootRole: proof.rootRole,
            rootKeyID: proof.rootKeyID,
            rootFingerprint: proof.rootFingerprint,
            deviceKeysetDigest: proof.deviceKeysetDigest,
            purpose: proof.purpose,
            signature: proof.signature
        )
        submitApproval(
            transportProof,
            csrfToken: csrfToken,
            preparedState: preparedState,
            using: store,
            completion: completion
        )
    }

    private func request(
        url: URL? = nil,
        method: String,
        body: [String: Any]?,
        csrfToken: String?,
        maxResponseBytes: Int = 4_200_000,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        var request = URLRequest(url: url ?? endpoint)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            if let csrfToken { request.setValue(csrfToken, forHTTPHeaderField: "X-CSRF-TOKEN") }
            do { request.httpBody = try JSONSerialization.data(withJSONObject: body) }
            catch { completion(.failure(error)); return }
        }

        session.dataTask(with: request) { data, response, error in
            if let error { completion(.failure(error)); return }
            guard let response = response as? HTTPURLResponse,
                  response.url?.scheme?.lowercased() == "https",
                  response.url?.host?.lowercased() == self.endpoint.host?.lowercased(),
                  response.url?.port == self.endpoint.port,
                  response.url == request.url,
                  response.mimeType?.lowercased() == "application/json" else {
                completion(.failure(ClientError.invalidResponse)); return
            }
            guard response.statusCode == 200 else {
                completion(.failure(ClientError.httpStatus(response.statusCode))); return
            }
            guard let data, data.count <= maxResponseBytes,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(ClientError.invalidResponse)); return
            }
            completion(.success(object))
        }.resume()
    }

    private static func string(_ object: [String: Any], _ key: String) throws -> String {
        guard let value = object[key] as? String, !value.isEmpty else { throw ClientError.invalidResponse }
        return value
    }

    private static func uint64(_ object: [String: Any], _ key: String) throws -> UInt64 {
        if let number = object[key] as? NSNumber, number.doubleValue >= 0,
           number.doubleValue.rounded(.towardZero) == number.doubleValue {
            return number.uint64Value
        }
        throw ClientError.invalidResponse
    }

    private static func decodeBase64URL(_ value: String) throws -> Data {
        guard value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
            throw ClientError.invalidEncoding
        }
        let base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padded = base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: padded),
              encodeBase64URL(data) == value else { throw ClientError.invalidEncoding }
        return data
    }

    private static func encodeBase64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
