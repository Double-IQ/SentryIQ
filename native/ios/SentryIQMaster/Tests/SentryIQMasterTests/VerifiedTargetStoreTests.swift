import XCTest
@testable import SentryIQMaster

final class VerifiedTargetStoreTests: XCTestCase {
    func testVerifiedTargetIsEncryptedAndAtomicallyReadBack() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SentryIQ-VerifiedTargetTests", isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try VerifiedTargetStore(
            directory: directory,
            service: "co.bichet.sentryiq.verified-target-tests"
        )
        let path = "release/manifest.json"
        let bytes = Data(#"{"version":1,"payload":"verified"}"#.utf8)
        let digest = try store.saveVerifiedTarget(path: path, bytes: bytes)
        XCTAssertEqual(digest.count, 64)
        XCTAssertEqual(try store.loadVerifiedTarget(path: path), bytes)
    }

    func testVerifiedTargetStoreRejectsTraversalPaths() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SentryIQ-VerifiedTargetTests", isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try VerifiedTargetStore(
            directory: directory,
            service: "co.bichet.sentryiq.verified-target-tests"
        )
        XCTAssertThrowsError(try store.saveVerifiedTarget(path: "../outside", bytes: Data([1])))
        XCTAssertThrowsError(try store.saveVerifiedTarget(path: "/absolute/path", bytes: Data([1])))
    }
}
