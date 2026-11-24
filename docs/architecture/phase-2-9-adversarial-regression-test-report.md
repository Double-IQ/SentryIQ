# Phase 2.9 — Adversarial release/verifier regression test report

**Status:** Existing-code adversarial regression additions committed; target-protocol acceptance tests specified and gated on implementation.  
**Scope:** Repository-only tests and read-only CI workflow updates.  
**No production code:** No runtime PHP classes, release workflow, credentials, keys, trust roots, host configuration, or deployment were changed.

## 1. Summary

The current repository contains a mature but legacy A/B/C integrity test cluster, native GitHub/Sigstore provenance tests, updater rollback/archive tests, and private-host collector tests. It does not yet contain the format-3 release-authorisation verifier, single HelioHost report protocol, durable challenge-consumption store, or master-phone gate. Tests cannot honestly claim those future contracts are implemented.

This change strengthens the executable regression baseline:
- Modified signed report payloads are rejected.
- Modified detached signatures are rejected.
- A signer key that is not pinned under the claimed identity is rejected.
- Duplicate signer identities are rejected.
- Expired reports are rejected.
- Unsafe/injected public asset paths and URL aliases are rejected.
- Unknown or absent package paths are rejected.
- Empty/invalid signed public inventories fail closed.
- The native regression workflow now explicitly runs the report-signer adversarial tests across its PHP matrix.

Existing tests already cover additional attack cases, including public-origin content mismatch, attestation failure before any origin fetch, origin outage as signed rejection, header mismatch, private collector file mismatch, unexpected files, symlinked ancestors, directory replacement races, private root/webroot separation, unsafe signing-key permissions, and malformed request context.

## 2. Changes in this PR

### 2.1 Report signature and freshness tests

Extended tests/integrity_report_signer.test.php to:
- Mutate the exact signed payload bytes while preserving the original signature; verification must fail.
- Flip a bit in the detached Ed25519 signature; verification must fail.
- Verify a report against a different public key pinned under the same node identity; verification must fail.
- Submit two reports from the same node identity; the legacy two-node policy must reject duplicate identity.
- Advance the test clock beyond the five-minute report expiry; verification must fail.

These tests use ephemeral in-memory test keys only. They do not create or provision any production key.

### 2.2 Public asset path-injection tests

Extended tests/integrity_public_asset_policy.test.php to reject:
- Parent traversal and dot segments.
- Absolute paths.
- Backslashes and repeated separators.
- Percent-encoded path traversal.
- Query strings and fragments embedded in manifest paths.
- NUL/control-character paths.
- Paths absent from the package inventory.
- HTTP assets absent from the signed public file list.
- Empty or non-list public inventories.

### 2.3 CI wiring

Updated .github/workflows/native-sigstore-integrity-node.yml to lint and execute tests/integrity_report_signer.test.php in its read-only PHP 8.1–8.5 regression matrix. The workflow remains repository-only and does not contact or provision remote nodes.

## 3. Existing adversarial coverage retained

| Threat | Existing coverage |
|---|---|
| Release provenance tamper / wrong repository / ref / commit / workflow / subject digest | tests/sigstore_provenance.test.php and tests/release_trust_policy.test.php |
| Native Sigstore certificate identity and actual v0.1.2 attestation | tests/fulcio_certificate_claims.test.php and tests/native_release_attestation.integration.php |
| Updater rollback, same-version retarget, archive traversal and symlink boundary | tests/update_rollback.test.php and tests/update_archive_boundary.test.php |
| Public file digest mismatch | tests/integrity_node_c.test.php |
| Release manifest or ZIP attestation failure before origin access | tests/integrity_node_c.test.php |
| Public origin outage and direct alert | tests/integrity_node_c.test.php |
| Origin security-header mismatch and redirect rejection | tests/integrity_node_c.test.php and tests/integrity_origin_security_header_verifier.test.php |
| Private file digest mismatch, unexpected file, symlinked ancestor, directory race | tests/private_host_attestation_collector.test.php |
| Private evidence signature/storage and permission constraints | tests/integrity_node_evidence_store.test.php |
| Local monotonic release pin and rollback/retarget rejection | tests/integrity_node_release_state.test.php |
| Unsafe/duplicate public asset path and PHP/private-file exclusion | tests/integrity_public_asset_policy.test.php |

## 4. Known legacy limitations — not represented as passing target controls

The current code remains the old format-2 and A/B/C implementation. The new Phase 2 designs are contracts, not executable classes. In particular:

1. **Cross-request replay:** IntegrityReportVerifier checks that reports contain the caller's expected nonce and are within their time window, but it does not persist a durable one-use challenge-consumption record across verification calls. Re-submission of the same valid reports can therefore be accepted by a later invocation if the caller supplies the same expected nonce. Phase 2.7 requires durable one-use challenge state and phone-side replay rejection. This is an explicit target implementation/test gate, not a control claimed as present.
2. **One verifier, not two nodes:** The legacy report verifier requires two distinct A/B/C identities. The target architecture requires one specialised HelioHost verifier and a master-phone trust pin. The old two-node approval contract must not be reused unchanged.
3. **No format-3 release authorisation:** Current tests cover GitHub/Sigstore provenance and format-2 policy. They cannot test the separate owner-controlled release-authorisation signature until that verifier exists.
4. **HTTP response metadata:** IntegrityNodeC's fetch seam returns body bytes only. It does not provide the complete structured status/header/content-type/content-encoding/cache-variant evidence required by Phase 2.5.
5. **Private host boundary:** The legacy private collector runs on the application host and signs its own result. Tests can exercise its local file checks, but they do not prove HelioHost isolation or provider-controlled snapshots.
6. **Phone-side gate:** No master-phone verification component exists yet. No test can claim the PWA or native companion enforces Phase 2.8.

These gaps must be addressed when the corresponding target components are implemented. Do not modify the legacy classes merely to make the future protocol appear complete.

## 5. Required target acceptance tests when implementation exists

The future implementation must add tests that exercise the actual format-3/release-authorisation/HelioHost/phone classes:
- Durable challenge nonce consumption across requests, concurrent workers, process restarts, and report retrieval.
- Replayed challenge ID, nonce, report digest, report sequence, and release sequence rejected.
- Forged release-authorisation signature, unknown/revoked release key, wrong manifest digest, wrong ZIP digest, and unauthorised rollback rejected.
- Forged HelioHost signature, wrong key ID, stale report, wrong challenge, wrong target origin, wrong release binding, and policy downgrade rejected.
- Missing/changed/unexpected public asset, redirect, wrong content type, compression/cache variant mismatch, and security-header mismatch rejected.
- Private file mismatch, unavailable private inspection, symlink/race, unexpected executable file, and insufficient assurance rejected.
- Verifier outage, stale queue, interrupted worker, state rollback, and alert failure never produce a pass.
- Phone-side operation permit cannot be replayed, widened, or used for another operation; PWA cannot set VERIFIED state.
- Secret-bearing configuration is not read, hashed, or included in report evidence.

## 6. Validation and status

The branch adds only:
- Two test-file changes.
- One read-only CI workflow update.
- This test coverage/limitations report.
- The design implementation plan update.

The PR's PHP matrix must pass before these regression additions are considered validated. No production deployment, release publication, host probing, secret handling, key generation, or trust-baseline initialisation occurred.

Phase 2.9 is closed as an adversarial baseline test expansion and acceptance-test definition. Target protocol-specific replay, release-authorisation, report, and phone-gate tests remain mandatory when those components are implemented; their absence is explicitly recorded rather than hidden.

**Next planned phase:** Phase 3 — master phone and device lifecycle, beginning with owner decisions on native companion/platform and key suite. Phase 3 implementation must not start until the Phase 1.10 owner decisions and the design review gates recorded in Phases 2.2–2.8 are resolved.
