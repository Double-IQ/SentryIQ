import Foundation

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
        public let csrfToken: String
    }

    public struct Challenge {
        public let value: String
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

    public enum ClientError: Error {
        case invalidOrigin
        case invalidResponse
        case httpStatus(Int)
        case invalidEncoding
    }

    private let endpoint: URL
    private let session: URLSession

    /// Pass the URLSession that shares the authenticated SentryIQ session cookie.
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
                    guard bundle.count <= 262_144, anchor.count <= 4_096,
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
                        csrfToken: try Self.string(object, "csrf_token")
                    ))
                } catch { return .failure(error) }
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
                    return .success(Challenge(
                        value: challenge,
                        purpose: try Self.string(object, "purpose"),
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

    private func request(
        method: String,
        body: [String: Any]?,
        csrfToken: String?,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        var request = URLRequest(url: endpoint)
        request.httpMethod = method
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
                  response.url?.path == self.endpoint.path,
                  response.mimeType?.lowercased() == "application/json" else {
                completion(.failure(ClientError.invalidResponse)); return
            }
            guard response.statusCode == 200 else {
                completion(.failure(ClientError.httpStatus(response.statusCode))); return
            }
            guard let data, data.count <= 300_000,
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
