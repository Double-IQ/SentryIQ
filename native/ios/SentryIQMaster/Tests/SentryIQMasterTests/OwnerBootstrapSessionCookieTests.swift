import Foundation
import XCTest
@testable import SentryIQMaster

final class OwnerBootstrapSessionCookieTests: XCTestCase {
    func testClearsOnlyConfiguredSecureHttpOnlyCookieFromNativeStorage() throws {
        let storage = HTTPCookieStorage.sharedCookieStorage(forGroupContainerIdentifier: "sentryiq-session-cookie-tests")
        storage.cookies?.forEach(storage.deleteCookie)
        defer { storage.cookies?.forEach(storage.deleteCookie) }

        let session = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example",
            .path: "/",
            .name: "SID",
            .value: "abcDEF0123456789_-",
            .secure: "TRUE",
            .httponly: "TRUE"
        ]))
        let unrelated = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example",
            .path: "/",
            .name: "theme",
            .value: "dark"
        ]))
        storage.setCookie(session)
        storage.setCookie(unrelated)

        OwnerBootstrapHTTPClient.clearNativeSessionCookie(
            origin: URL(string: "https://sentryiq.example")!,
            sessionCookieName: "SID",
            cookieStorage: storage
        )

        XCTAssertFalse(storage.cookies?.contains(where: { $0.name == "SID" }) ?? false)
        XCTAssertTrue(storage.cookies?.contains(where: { $0.name == "theme" }) ?? false)
    }

    func testInvalidOriginOrCookieNameFailsClosedWithoutDeletingCookies() throws {
        let storage = HTTPCookieStorage.sharedCookieStorage(forGroupContainerIdentifier: "sentryiq-session-cookie-invalid-tests")
        storage.cookies?.forEach(storage.deleteCookie)
        defer { storage.cookies?.forEach(storage.deleteCookie) }
        let session = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example",
            .path: "/",
            .name: "SID",
            .value: "abcDEF0123456789_-",
            .secure: "TRUE",
            .httponly: "TRUE"
        ]))
        storage.setCookie(session)

        OwnerBootstrapHTTPClient.clearNativeSessionCookie(
            origin: URL(string: "http://sentryiq.example")!,
            sessionCookieName: "SID",
            cookieStorage: storage
        )
        OwnerBootstrapHTTPClient.clearNativeSessionCookie(
            origin: URL(string: "https://sentryiq.example")!,
            sessionCookieName: "bad/name",
            cookieStorage: storage
        )

        XCTAssertTrue(storage.cookies?.contains(where: { $0.name == "SID" }) ?? false)
    }
}
