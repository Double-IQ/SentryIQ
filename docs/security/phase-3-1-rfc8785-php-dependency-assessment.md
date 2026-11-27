# Phase 3.1 — PHP RFC 8785 dependency assessment

**Status:** Qualification assessment; no dependency selected for production.
**Reviewed:** 2026-11-25
**Scope:** Canonical JSON used by the PHP trust-bundle validator and registry-anchor verifier.

## Decision

Do not add a third-party canonicalization dependency to the application yet. The repository currently has no Composer manifest, lockfile, vendor autoloader, or Composer-based application CI. Introducing a Composer dependency would therefore also introduce a dependency-management and deployment change, not merely replace one serializer.

Keep the existing fixed-schema canonical serializer explicitly non-production-qualified. Its present safety argument is narrow: the trust-bundle validator rejects unknown object members at every schema level, all permitted member names are ASCII, floating-point values are rejected, and integer fields are bounded by the schema. This restricted profile avoids the general JCS cases most likely to diverge (arbitrary Unicode property ordering and ECMAScript floating-point serialization). It is not a general RFC 8785 implementation and must not be reused for arbitrary JSON.

A candidate package must pass the upstream RFC 8785 corpus, Appendix B number vectors, I-JSON invalid-input cases, the project's fixed-schema cross-language fixtures, and a dependency/supply-chain review before adoption.

## Candidate review

### 1. `mbolli/php-ron` — strongest candidate for a controlled evaluation

- Packagist currently lists v0.5.0, MIT, PHP >= 8.3, and `ext-hash` / `ext-mbstring`.
- The repository contains a dedicated RFC 8785 parser/canonicalizer, UTF-16 code-unit key sorting (including supplementary-plane handling), duplicate decoded-name checks, lone-surrogate checks, and explicit I-JSON rejection.
- Its test suite consumes the upstream RFC 8785 corpus, expected canonical bytes and SHA-256 values, Appendix B IEEE-754 number vectors, and invalid I-JSON cases. Its project CI covers PHP 8.3, 8.4, and 8.5.
- The package repository is young, has one maintainer, and currently reports no GitHub stars. Its Composer manifest declares post-install and post-update scripts for initializing test submodules. The script is a no-op when installed as a dependency (no `.git` directory), but install-time scripts still require explicit review and should be disabled during initial evaluation.
- The package is broader than required (RON parser/renderer plus JCS), so only its dedicated `Ron::canonicalJson()` surface should be considered if it is ever adopted.

References:
- https://packagist.org/packages/mbolli/php-ron
- https://github.com/mbolli/php-ron
- Reviewed source commit: `0b88aed885d23659b8a22769cf46efe345db18d0`

**Disposition:** candidate for isolated conformance evaluation; not approved as a production dependency.

### 2. `truschery/kanon` — do not adopt

- Packagist lists v1.0.1, MIT, PHP >= 8.2, and no runtime dependencies.
- Its published README describes property sorting by byte values rather than RFC 8785's required UTF-16 code-unit ordering. UTF-8 byte ordering and UTF-16 ordering differ for supplementary-plane characters relative to BMP characters; this is a material canonicalization mismatch.
- The repository's latest commit shown during this review is from 2026-03-12 and the published test examples do not establish coverage of the official Appendix B number corpus or full upstream RFC 8785 vectors.

References:
- https://packagist.org/packages/truschery/kanon
- https://github.com/truschery/kanon
- Reviewed source commit: `abd8fbd3ca39a6a05a40e1d1e49cf868a887dc60`

**Disposition:** rejected for this protocol.

### 3. `root23/php-json-canonicalization` — do not adopt

- Packagist reports version 1.0.1 from 2023, no license information for the latest version, one GitHub star, and no dependents.
- Its older release and unclear licensing are insufficient for a security-critical production dependency.

References:
- https://packagist.org/packages/root23/php-json-canonicalization
- https://github.com/root23/php-json-canonicalization

**Disposition:** rejected for this protocol.

## Required qualification before adoption

1. Establish the application's supported PHP runtime and introduce Composer only through a separately reviewed dependency-management change (manifest, lockfile, CI install, deployment packaging, and no unreviewed install scripts).
2. Pin an exact reviewed release and integrity hash; do not consume a branch or floating version.
3. Run the candidate's complete upstream RFC 8785 corpus and Appendix B vectors in CI, not merely its own unit-test command.
4. Add project-owned negative vectors for duplicate decoded member names, malformed UTF-8, lone surrogates, non-finite numbers, invalid I-JSON, and supplementary-plane property-name ordering.
5. Run the trust-bundle and registry-anchor golden fixtures through the same canonicalizer and compare exact bytes and SHA-256 digests across PHP, Swift, and Kotlin.
6. Review release provenance, maintainer continuity, dependency graph, license, install scripts, and vulnerability/advisory history.
7. Keep production trust-root initialization blocked until the selected dependency and its exact version pass independent security review.

## Protocol reference

RFC 8785 requires recursive object sorting by UTF-16 code units, ECMAScript-compatible primitive serialization, and I-JSON input constraints. A byte-wise key sort or a serializer that only removes whitespace is not sufficient.

- https://www.rfc-editor.org/rfc/rfc8785.html

This assessment does not generate keys, change trust roots, add a Composer dependency, or authorize deployment.

## 2026-11-27 isolated candidate evaluation

The project now has an isolated Composer harness under tests/jcs-candidate/. It does not add Composer to the application or alter runtime deployment dependencies. The harness resolves exact package versions with Composer scripts disabled, because the mbolli/php-ron package declares submodule-initialization install hooks.

Candidates under evaluation:

- accredifysg/php-json-canonicalize 1.1.1
- mbolli/php-ron 0.5.0

Both candidates passed the six project-held RFC 8785 sample vectors and their respective strict-input negative cases in the isolated PHP 8.4 CI run (run 46054359619). Both harnesses now reject nine invalid-input classes: duplicate literal names, duplicate decoded names, lone high and low surrogates, an I-JSON noncharacter, malformed UTF-8, an unescaped control character, numeric overflow, and malformed JSON.

A project-owned Appendix B fixture contains all 24 finite IEEE-754 samples from RFC 8785 Table 1. Both candidates passed all 24 values in PHP 8.4 CI run 46054462347 by reconstructing the exact binary64 input from the RFC hexadecimal representation. Both candidates therefore pass the project's six sample vectors and 24 finite Appendix B values on PHP 8.4. The expanded nine-case strict-input suite and the new shared PHP/Swift/Kotlin registry-anchor fixture assertions are awaiting CI on the current branch head.

This is limited candidate evidence, not production qualification. The upstream packages' own conformance claims remain maintainer-reported until independently reproduced against their complete pinned corpora. The project still needs:
- Complete upstream RFC 8785 corpus execution in SentryIQ CI (the project-owned six-vector and 24-value Appendix B subsets are passing).
- Complete PHP, Swift, and Kotlin CI confirmation of the shared registry-anchor canonical-bytes and SHA-256 fixture assertions (added; latest runs pending).
- Full dependency provenance, release-integrity, vulnerability, license, and maintainer-continuity review.
- A separate Composer/deployment design decision, lockfile and immutable artifact hash before any application dependency is introduced.
- Independent security review before production use.

**Interim disposition:** both packages remain evaluation candidates. Neither is selected or approved for production. The fixed-schema serializer remains restricted and non-production-qualified for general JCS.
