# Phase 3.1 — Native authenticated-session bridge integration

**Status:** Library bridge primitives implemented; consuming native app integration remains open.
**Scope:** Transfer the current authenticated SentryIQ web session to the native bootstrap HTTP client without exposing the PHP session cookie to JavaScript.

## Server-side session-cookie identifier

The authenticated web UI exposes the active PHP cookie name in a non-secret HTML metadata field:

`<meta name="sentryiq-session-cookie-name" content="...">`

The value is produced from `session_name()` after the PHP security bootstrap has configured and started the session. The cookie name is not a credential; the cookie value remains HttpOnly and is never placed in HTML or JavaScript.

Native app configuration must read this field from the loaded same-origin SentryIQ page. It must not assume `PHPSESSID`, since a host may configure a different session name.

## Android bridge

`OwnerBootstrapHttpClient.synchronizeAuthenticatedSessionCookie(...)`:

- requires an HTTPS origin and a valid configured cookie name;
- confirms that the current WebView URL is same-origin with the configured origin;
- reads cookies for the bootstrap endpoint and selects only the exact configured session-cookie name;
- rejects missing, duplicate, or unsafe session-cookie values;
- transfers that one cookie into a native `java.net.CookieManager` with Secure and HttpOnly attributes; the web session cookie remains `SameSite=Strict` at the PHP/WebView boundary, while SameSite is not a property enforced by Java's native HTTP cookie jar;
- never copies unrelated WebView cookies.

The native app must call this bridge after the web login succeeds and before creating/sending bootstrap requests. Keep the native cookie jar in memory for the authenticated session and call `OwnerBootstrapHttpClient.clearNativeSessionCookie(origin, sessionCookieName, nativeCookieJar)` when the vault locks, on logout, session-expiry, WebView teardown, and authentication failure. This removes only the configured cookie and leaves unrelated cookies untouched.

The parser has JVM regression tests for selection, missing/duplicate cookie rejection, unsafe values, and name mismatch.

## iOS bridge

`OwnerBootstrapHTTPClient.synchronizeSessionCookie(from:origin:sessionCookieName:completion:)` selects only the exact named secure, HttpOnly cookie for the HTTPS host and API path. The native caller should invoke it after WebView authentication and before bootstrap transport.

The native app must pass the exact `HTTPCookieStorage` configured on its bootstrap `URLSession` to `synchronizeSessionCookie(..., cookieStorage:)`; the default `.shared` is suitable only when the URLSession uses shared storage. This avoids copying the cookie into a store the HTTP client never reads. On lock/logout/session expiry/authentication failure, call `OwnerBootstrapHTTPClient.clearNativeSessionCookie(origin:sessionCookieName:cookieStorage:)` to remove only the configured native session cookie. Lock intentionally leaves the WebView cookie intact; explicit logout should also invoke the application's normal web logout. Do not log, persist, export, or place cookie values in the JavaScript bridge.

## App-level integration requirement

The repository currently contains native companion libraries and UI approval components, not a complete iOS/Android app shell with a login WebView lifecycle. Cookie clearing helpers and unit tests are implemented, but the bridge is not yet connected to an actual login screen or lock/logout lifecycle. The consuming app must:

1. Load the SentryIQ login page in its same-origin WebView.
2. Detect successful authentication from the trusted navigation flow (not arbitrary JavaScript messages).
3. Read the cookie-name metadata from the authenticated page.
4. Copy only the named session cookie to the native HTTP transport.
5. Perform bootstrap snapshot/challenge/approval operations through the native client.
6. Clear the native cookie jar on lock, logout, session-expiry, WebView teardown, and authentication failure.

This integration must be tested on a real device. The PHP cookie attributes, platform WebView cookie semantics, and native HTTP cookie handling must be verified together before Phase 3.1 can close.
