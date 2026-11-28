import Foundation
import XCTest
@testable import SentryIQMaster

final class OwnerBootstrapSessionCookieTests: XCTestCase {
    private let httpOnlyKey = HTTPCookiePropertyKey(rawValue: "HttpOnly")

    func testSelectsOnlySingleSecureHttpOnlySameHostCookie() throws {
        let cookie = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example",
            .path: "/",
            .name: "SID",
            .value: "abcDEF0123456789_-",
            .secure: "TRUE",
            httpOnlyKey: "TRUE"
        ]))
        XCTAssertEqual(
            OwnerBootstrapHTTPClient.selectSessionCookie(
                [cookie], name: "SID", host: "sentryiq.example",
                endpointPath: "/api/owner-bootstrap.php"
            )?.value,
            "abcDEF0123456789_-"
        )
        XCTAssertNil(OwnerBootstrapHTTPClient.selectSessionCookie(
            [cookie], name: "SID", host: "other.example",
            endpointPath: "/api/owner-bootstrap.php"
        ))
    }

    func testRejectsAmbiguousDuplicateCookiesAndInsecureCookie() throws {
        let rootPathCookie = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example", .path: "/", .name: "SID",
            .value: "abcDEF0123456789_-", .secure: "TRUE", httpOnlyKey: "TRUE"
        ]))
        let apiPathCookie = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example", .path: "/api", .name: "SID",
            .value: "xyzDEF0123456789_-", .secure: "TRUE", httpOnlyKey: "TRUE"
        ]))
        XCTAssertNil(OwnerBootstrapHTTPClient.selectSessionCookie(
            [rootPathCookie, apiPathCookie], name: "SID", host: "sentryiq.example",
            endpointPath: "/api/owner-bootstrap.php"
        ))
        let insecure = try XCTUnwrap(HTTPCookie(properties: [
            .domain: "sentryiq.example", .path: "/", .name: "SID",
            .value: "abcDEF0123456789_-"
        ]))
        XCTAssertNil(OwnerBootstrapHTTPClient.selectSessionCookie(
            [insecure], name: "SID", host: "sentryiq.example",
            endpointPath: "/api/owner-bootstrap.php"
        ))
    }

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
            httpOnlyKey: "TRUE"
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
            httpOnlyKey: "TRUE"
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
