# Phase 2.5 — Public HTTP asset measurement protocol

**Status:** Design artifact complete; implementation and production acceptance remain unauthorised.  
**Target origin:** https://sentryiq.bichet.co.za  
**Measurement operator:** One specialised HelioHost verifier.  
**Expected state:** Independently verified format-3 manifest plus detached release authorisation.  
**Safety:** No live production measurement, host configuration, key, or deployment was changed by this design.

## 1. Objective and evidence boundary

The HelioHost verifier must measure the actual public HTTP bytes delivered by the canonical SentryIQ origin and compare them with the independently authorised format-3 manifest. It must also validate the response properties that influence browser interpretation and caching.

A successful check proves only that the verifier observed specified response bytes and headers from the canonical origin at a particular time and network vantage point. It does not prove:
- Every browser, ISP, CDN edge, or geographic cache served identical bytes.
- A compromised browser or OS executed only the measured bytes.
- The application host contains no unexpected private files.
- Dynamic PHP output is byte-identical to a static package file.
- The measured source code is benign.

Public HTTP measurement and private filesystem measurement remain separate evidence classes. Unknown or unexpected private webroot files require the qualified private inspection channel in Phase 2.6; public HTTP probing alone cannot enumerate an arbitrary webroot.

## 2. Inputs and preconditions

The measurement worker accepts no arbitrary target URL or filesystem path. Inputs are:
- A fresh, one-use phone challenge.
- The exact canonical target origin: https://sentryiq.bichet.co.za.
- The format-3 manifest and detached release-authorisation record, both verified independently under Phase 2.2/2.3.
- The GitHub/Sigstore provenance claims bound to the exact source commit and artifact digests.
- A pinned, versioned HTTP response-header policy profile.
- A fixed verifier build and measurement policy version.

Before making requests, the worker validates:
1. Manifest canonical serialization, schema, version, repository ID, source ref/commit, workflow identity, and deployment profile.
2. Release authorisation signature, trusted key ID, exact manifest and ZIP digests, sequence, policy version, and validity.
3. All public asset paths, URL mappings, expected sizes/digests, content types, cache classes, and required flags.
4. The exact origin host, scheme, port, and path. No manifest field can change the origin to an arbitrary domain.
5. Challenge freshness and replay state.

The verifier never downloads an unauthenticated manifest and then treats it as expected state.

## 3. URL and path canonicalisation

Every public asset URL is constructed from the fixed canonical origin and one validated manifest path. It is not accepted as an arbitrary absolute URL.

Required rules:
- HTTPS only, exact host sentryiq.bichet.co.za, port 443, no userinfo, query, fragment, or alternate authority.
- Relative POSIX path only; no leading slash, backslash, empty segment, dot segment, traversal segment, NUL, control character, percent escape, encoded slash/backslash, or ambiguous Unicode normalisation.
- Reject duplicate paths, case-fold collisions, path aliases, and paths that normalise to the same URL.
- Encode each validated path segment exactly once using a reviewed RFC 3986 path-segment encoder. Never encode the slash separator as part of a segment and never decode/re-encode attacker-controlled input.
- Reject semicolon/path-parameter syntax and unsupported reserved characters unless the schema explicitly permits them.
- Do not follow an asset URL outside the exact canonical origin.
- A URL must map to exactly one manifest file entry and one asset policy class.

The origin is fixed in verifier policy, not supplied by a release manifest or phone challenge. TLS certificate and hostname verification are mandatory. The worker does not disable certificate validation or fall back to HTTP.

## 4. Request profile

For each asset, send a deterministic unauthenticated GET:
- Method: GET only. HEAD is not sufficient evidence of response body bytes.
- Host: canonical host.
- Accept-Encoding: identity to request the canonical uncompressed representation.
- Accept: */* or the exact declared media-type preference from the profile.
- Fixed verifier User-Agent identifying the protocol/version, not a browser impersonation.
- Cache-Control: no-cache, no-store, no-transform and Pragma: no-cache.
- No cookies, Authorization, application session, referrer, user-specific headers, or user-data request parameters.
- No query string or cache-busting parameter unless a future profile explicitly defines a safe variant test.

The worker records the request profile and selected response headers in evidence. The request profile is versioned so later implementations can reproduce the same observation.

## 5. Redirect policy

**Default policy: any redirect is a failed measurement.**

- Do not automatically follow redirects.
- Record the 3xx status and a sanitised Location classification, not a signed URL or sensitive query string.
- Reject same-origin redirects as well as cross-origin redirects by default; a redirect can alter the measured resource or introduce cache/path ambiguity.
- If a future canonical deployment requires one redirect, it must be explicitly declared in a versioned policy with exact source path, exact destination path, exact same-origin requirement, bounded hop count, and separate tests. The verifier must revalidate TLS/host/path at every hop and measure the final response.
- Reject protocol downgrade, host change, port change, userinfo, fragment, encoded traversal, and redirect loops.
- A successful response must be HTTP 200. Reject 201, 202, 204, 206, 304, and all other non-200 statuses for a byte-verified asset.

This deliberately avoids the ambiguity of a CDN or origin silently redirecting a security-critical script to another host or path.

## 6. Response body and digest validation

For a byte-verified static asset:
1. Require HTTP 200.
2. Require response body to complete without transport error or truncation.
3. Enforce a per-asset and aggregate response-size ceiling from policy before buffering or hashing.
4. Require Content-Encoding to be absent or identity under the initial profile. A server/CDN that ignores the identity request and returns gzip/Brotli is recorded as unsupported/failure rather than silently hashing an implementation-dependent decoded representation.
5. If Content-Length is present, require it to equal the observed body length. A missing Content-Length is allowed only if the body completed successfully and the manifest size matches.
6. Compare observed byte length and SHA-256 with the exact manifest entry.
7. Reject any mismatch, empty body for a non-empty asset, or body that exceeds declared size/limits.

The digest is over the exact identity-encoded entity bytes received by the verifier. Transfer framing (for example, chunked transfer encoding) is not part of the entity digest. The manifest does not use a sidecar checksum as an expected digest.

If production hosting cannot provide a stable identity representation, a future format/profile may define explicit deterministic decoding of an allowed content encoding. That requires pinned decoder behaviour, compressed and decoded size limits, and tests. Do not improvise decompression in the first implementation.

## 7. Content type and browser interpretation

Each HTTP asset entry declares its expected media type. Compare the response Content-Type media type case-insensitively after parsing; ignore only explicitly allowed parameters such as a valid UTF-8 charset for text assets.

Examples:
- JavaScript modules: approved JavaScript media type.
- CSS: text/css.
- Web manifest: approved JSON/webmanifest media type.
- WASM: application/wasm.
- SVG: image/svg+xml.
- Icons/images/fonts: media type appropriate to the manifest declaration.
- Static HTML: text/html.

Fail on:
- Missing or unexpected Content-Type.
- HTML returned where JavaScript/CSS/WASM is expected (including an authentication or error page).
- MIME type that triggers unsafe sniffing or browser interpretation.
- X-Content-Type-Options missing or not nosniff where required by the profile.
- Content-Disposition or other unexpected headers that change how an asset is handled, unless explicitly permitted.

The policy does not infer a media type from a filename alone; it compares the manifest declaration, file type policy, and actual response header.

## 8. Cache and content-negotiation variants

A hash check of one response can miss a stale or differently negotiated cached variant. The initial policy therefore requires two observations for each required security-critical static asset:

1. **Revalidation request:** fixed identity encoding, no-cache/no-store request directives.
2. **Ordinary request:** same origin/path and fixed User-Agent/Accept profile without revalidation directives, still requesting identity encoding.

The response body digest, size, content type, and relevant security headers must match between the two observations. A mismatch indicates stale cache, content negotiation, or inconsistent delivery and fails the measurement.

Record, but do not trust as integrity evidence:
- Age, ETag, Last-Modified, Via, Vary, Cache-Control, Expires, and cache-provider diagnostic headers.
- Presence of Vary: * or variation on Cookie, Authorization, User-Agent, Accept-Language, or other unapproved dimensions fails the initial static-asset profile.
- Vary: Accept-Encoding is allowed only if identity representation is returned consistently for the request profile and both observations match.
- Cache-provider headers such as CF-Cache-Status are diagnostic only; no Cloudflare deployment is assumed or required.

Expected response cache policy depends on asset class:
- Content-addressed/versioned static JS/CSS/WASM/fonts/images may use long-lived immutable caching if their URLs are immutable and the manifest maps the exact digest.
- HTML entrypoints and dynamic routes must use the reviewed revalidation/no-store profile; they must not be cached as immutable.
- PWA manifest and service-worker script must revalidate promptly and must not be treated as long-lived immutable assets unless their URL/versioning strategy explicitly makes that safe.
- Authenticated, recovery, session, and user-data endpoints must use no-store policy and are not static asset inventory entries.

A mismatch in either request variant is a failed result. Do not select the more favourable response or average two digests.

## 9. Security response headers

Headers are checked against a separately versioned sentryiq-web-security-v1 profile, not arbitrary values supplied by the application response.

The profile must define:
- HSTS on HTTPS responses, including the approved max-age and subdomain policy.
- Content Security Policy, including script/style restrictions, nonce/hash policy, and frame-ancestors.
- X-Content-Type-Options: nosniff.
- Referrer-Policy, with one canonical value matching Apache and PHP configuration.
- Permissions-Policy restrictions for unused device/browser capabilities.
- Frame protections, COOP/COEP/CORP where compatible with application functionality.
- Cache-Control policy by route/asset class.
- Any cross-origin resource policy required for WASM/fonts or other assets.

The verifier records the exact observed header values needed to diagnose a mismatch, after length/control-character filtering. It must not include cookies, authorization values, session IDs, or other secret-bearing headers in the report.

A header mismatch is a policy failure even when the file digest matches. A matching header does not prove that the browser enforced it or that the browser runtime is uncompromised.

The repository audit previously found a disagreement between .htaccess and PHP Referrer-Policy values. The canonical profile must choose one value and the application implementation must enforce it consistently before the verifier can pass.

## 10. Dynamic HTML and route handling

Dynamic PHP responses are not compared with the source PHP file digest. The format-3 manifest distinguishes:
- Static HTML files whose exact response bytes are inventoried.
- Dynamic HTML routes whose server-side template/code is inventoried separately and whose HTTP response is validated by route policy.

For a dynamic HTML entrypoint:
- Fetch only manifest-declared route paths using a no-session, unauthenticated request profile.
- Require the expected status, Content-Type, cache policy, CSP and other security headers.
- Extract first-party script, stylesheet, modulepreload, manifest, icon, font, and WASM references using a bounded parser that does not execute JavaScript.
- Resolve references against the canonical origin and require each security-critical first-party reference to map to a manifest-listed HTTP asset.
- Reject unlisted first-party executable resources, duplicate/ambiguous references, protocol-relative URLs, unexpected external scripts, javascript: URLs, malformed encodings, and references escaping the declared path policy.
- Dynamic nonce values may vary, but the CSP nonce and inline script/hash rules must satisfy the reviewed CSP profile. Nonces are never persisted in the report.
- The route's response body is not treated as an immutable asset digest unless the route is declared static and byte-stable.

The current repository baseline lacks a tracked PWA manifest/service worker. The verifier must not invent or require assets that have not been implemented. Once introduced, the web manifest, service worker, precache manifest, icons, and all referenced shell resources become required manifest entries and must be measured.

## 11. Expected assets and unexpected surface

The manifest is the authoritative expected set. The worker:
- Measures every required http_assets entry; no optional asset may be silently skipped if policy marks it security-critical.
- Records each expected path exactly once.
- Detects missing paths and duplicate route mappings.
- Compares observed first-party resource references from declared entrypoints with the manifest allowlist.
- Reports unlisted first-party scripts/styles/WASM/service-worker resources as unexpected.
- Does not crawl arbitrary application URLs, follow untrusted links, submit forms, or request authenticated/user-specific routes.

Public HTTP cannot enumerate all possible paths on the server. Therefore:
- The report must state that unknown unreferenced files/routes are outside HTTP-only enumeration.
- Complete unexpected webroot-file detection requires the separate qualified read-only filesystem inventory in Phase 2.6.
- A report cannot claim "no unexpected files exist" when only the manifest's known URL set was checked.
- If a policy requires full deployment inventory and the private channel is unavailable, the overall outcome is insufficient/fail, not full pass.

## 12. Evidence report fields

For each measured asset, preserve:
- Manifest asset ID/path and expected digest/size/media type.
- Request profile identifier and observation type (revalidation/ordinary).
- HTTP status, observed digest/size, parsed Content-Type and Content-Encoding.
- Redirect count (must be zero under the initial profile).
- Relevant cache and security-header policy results.
- Measurement timestamp and stable failure reason code, if any.

The signed aggregate report also binds:
- Canonical origin and deployment profile.
- Release version, source commit, release sequence, manifest digest, ZIP digest, and release-authorisation record digest.
- Verifier identity/key ID, verifier policy version, challenge nonce/ID, issued-at and expiry.
- Count of expected, measured, failed, and unmeasurable assets.
- Explicit scope limitation: public HTTP measurement does not enumerate all unknown webroot paths or prove private runtime integrity.

Do not include full response bodies, query strings, cookies, user data, credentials, private config values, or unfiltered response headers.

## 13. Failure and retry semantics

- TLS validation failure, DNS failure, timeout, oversized response, invalid status, redirect, wrong MIME, unsupported encoding, digest/size mismatch, header mismatch, cache variant mismatch, unlisted executable reference, or missing required asset results in a failed measurement.
- Retry only bounded transient transport errors under a fixed retry budget and jitter policy. A retry cannot convert a policy mismatch into a pass.
- If the origin is unavailable, issue an unavailable/fail report bound to the challenge; never reuse a prior successful report.
- If the worker crashes or a challenge expires before completion, no success report is issued.
- If any required asset is not measured, overall status cannot be full pass.
- Alerts are independent operational notifications and do not replace the signed report.

## 14. Existing Node C implementation — baseline and limitations

The repository's legacy IntegrityNodeC and IntegrityPublicAssetPolicy provide useful starting patterns:
- Both the external manifest and ZIP are verified as GitHub/Sigstore subjects before the manifest is trusted.
- Format-2 public_http_files or derived static public_files are selected; dynamic PHP and private runtime files are excluded from byte-for-byte HTTP comparison.
- The fetcher uses HTTPS, certificate/hostname verification, a 10 MB body cap, no redirect following, and requires HTTP 200.
- A separate injected origin-header verifier is required.
- Existing tests reject dynamic PHP/private paths, duplicate paths, and oversized asset lists.

They do not satisfy the new protocol unchanged:
- Format 2 does not define the full format-3 HTTP mapping, cache class, expected MIME type, or route policy.
- The fetch seam returns body bytes only; the current fetcher does not retain structured response headers or Content-Type/Content-Encoding/Content-Length evidence.
- It does not perform the two-observation cache/negotiation comparison.
- It does not compare HTML resource references with a canonical manifest allowlist.
- It does not establish complete unexpected-file enumeration.
- The current path checks do not implement all format-3 Unicode/case-fold/encoded-path collision rules.
- The code is tied to integrity-c identity and legacy report contracts.

Preserve it as regression/reference code until the replacement protocol and tests are complete. Do not deploy it unchanged as the HelioHost service.

## 15. Test matrix

1. Exact expected bytes and size return pass for each allowed media type.
2. Changed bytes, truncated body, oversized body, wrong size, and digest mismatch fail.
3. TLS invalid certificate, hostname mismatch, non-HTTPS, wrong host, wrong port, and DNS/transport failure fail.
4. Same-origin and cross-origin redirects, redirect loops, encoded traversal, and protocol downgrade fail.
5. HTTP 201/202/204/206/304/3xx/4xx/5xx fail.
6. Wrong/missing Content-Type, HTML login page, unsafe MIME sniffing, and unexpected Content-Disposition fail.
7. Gzip/Brotli/non-identity Content-Encoding fails under the initial identity-only profile.
8. Content-Length mismatch, chunk truncation, and body cap exceedance fail.
9. Revalidation and ordinary request body/header differences fail.
10. Unapproved Vary dimensions, Vary star, stale cache variants, and immutable caching on dynamic entrypoints fail.
11. Required HSTS/CSP/nosniff/Referrer-Policy/Permissions-Policy/cache headers mismatch fails.
12. Dynamic PHP source is never compared with its HTTP response body.
13. Dynamic entrypoint references to unlisted JS/CSS/WASM/service-worker resources fail.
14. Duplicate/case-colliding/encoded/Unicode-normalisation-colliding paths fail.
15. Missing PWA assets are reported according to the active deployment profile; no unimplemented service worker is assumed.
16. An HTTP-only report explicitly records inability to enumerate unknown unreferenced webroot files.
17. A partial measurement or one unmeasured required asset cannot produce full pass.
18. Challenge replay, expired challenge, worker crash, retry exhaustion, and origin outage never reuse stale success.

## 16. Completion and next step

Phase 2.5 is complete as a protocol design. It specifies deterministic request construction, URL/path policy, redirect rejection, body/digest/size checks, content type, identity encoding, cache/negotiation variants, security headers, dynamic HTML treatment, unexpected-resource scope, signed evidence, and failure semantics.

Next: Phase 2.6 defines what private server-side files/configuration HelioHost can safely inspect and the limits of a read-only collector. No source implementation or production host probing is authorised by this design.
