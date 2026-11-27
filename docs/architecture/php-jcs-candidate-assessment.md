# PHP JCS candidate assessment — 2026-11-27

## Decision

Select `onematrix/tracing-sdk` 1.2.0 as the RFC 8785 canonicalization engine for the restricted trust-bundle profile. It passes all six RFC 8785 examples and all 24 Appendix B number vectors on PHP 8.1 and 8.4. SentryIQ retains its own raw-input I-JSON gate before invoking the library: duplicate object names, invalid UTF-8, Unicode noncharacters, floats, unsafe integers, non-ASCII member names, and unknown schema members are rejected. The validator also differentially compares the library output with the restricted-profile reference serializer and fails closed on any mismatch.

## Candidates already exercised

- `accredifysg/php-json-canonicalize` 1.1.1: rejected by the strict-input gate because it accepts U+FDD0 (a Unicode noncharacter). Its declared PHP requirement is 8.2+.
- `mbolli/php-ron` 0.5.0: passes the recorded RFC 8785 and strict-input vectors, but its PHP 8.3+ requirement is incompatible with the current PHP 8.1 baseline.
- `mmccook/php-json-canonicalization-scheme` 1.0.0: declares PHP `^8.1` and MIT licensing, so it was added to the isolated qualification workflow. Source review of the pinned 1.0.0 tag found two blockers:
  1. Its API canonicalizes already-decoded PHP values rather than parsing raw JSON. Duplicate-member detection and strict raw UTF-8/I-JSON rejection therefore need a separate parser boundary; the package alone cannot satisfy the existing raw-input qualification contract.
  2. Its number formatter uses `number_format($number, 7, '.', '')` for values in the decimal range and default-precision `sprintf('%e', ...)` for exponent notation. Those are not ECMAScript shortest-roundtrip formatting and are insufficient for RFC 8785 Appendix B values that require more than seven fractional digits or full binary64 precision.

The pinned candidate's source is available at [JsonCanonicalizator.php](https://github.com/mmccook/php-json-canonicalization-scheme/blob/cd6d3e7645a2c1e62574a9a2437d68e9e74e799f/src/JsonCanonicalizator.php) and [Utils.php](https://github.com/mmccook/php-json-canonicalization-scheme/blob/cd6d3e7645a2c1e62574a9a2437d68e9e74e799f/src/Utils.php). The qualification harness is retained as a reproducible diagnostic, not as evidence of acceptance.

- `root23/php-json-canonicalization` 1.0.1: declares PHP `>=8.0`, but is not a viable PHP 8.1 candidate. Its pinned source uses the same lossy `number_format($number, 7, '.', '')` decimal path and default-precision `sprintf('%e', ...)` exponent path, so it cannot satisfy the Appendix B binary64 vectors. The repository has no declared licence and its last source push was in 2023; exclude it rather than treating its broad PHP requirement as evidence of conformance. Source reviewed: [JsonCanonicalizer.php](https://github.com/root23/php-json-canonicalization/blob/main/src/JsonCanonicalizer.php), [Converter.php](https://github.com/root23/php-json-canonicalization/blob/main/src/Converter.php), and [composer.json](https://github.com/root23/php-json-canonicalization/blob/main/composer.json).

- `truschery/kanon` 1.0.1: pinned and tested on PHP 8.4. It fails RFC 8785 Appendix B at IEEE-754 bit pattern `4430000000000000`; its `formatFloat` path delegates to PHP `json_encode`, which does not produce the required ECMAScript/JCS representation for this value. It also declares PHP `^8.2`, above the PHP 8.1 deployment baseline. Reject. Qualification evidence: current `php-jcs-candidate.yml` run 46068188509.

- `onematrix/tracing-sdk` 1.2.0: accepted candidate. The pinned `Tracing\\Sdk\\Canonicalize\\JsonCanonicalizer` passes all six RFC 8785 examples and 24 Appendix B binary64 numbers in the isolated harness on PHP 8.4 and in the PHP 8.1 compatibility job (run 46068732059). It declares PHP `^7.1 || ^8.0` and MIT licensing. The library's raw parser follows PHP `json_decode` duplicate-member semantics, so it is not used as the trust-bundle input gate by itself. SentryIQ's `TrustBundleValidator` first rejects duplicate raw members and I-JSON Unicode noncharacters, validates the fixed schema and restricted value profile, then invokes the pinned canonicalizer and requires byte-for-byte agreement with the restricted-profile reference implementation. The root `composer.json` pins exactly version 1.2.0. Source: [JsonCanonicalizer.php](https://github.com/OneMatrixL1/tracing-sdk-php/blob/1.2.0/src/Canonicalize/JsonCanonicalizer.php), [composer.json](https://github.com/OneMatrixL1/tracing-sdk-php/blob/1.2.0/composer.json).

## Next gate

The integrated PHP 8.1–8.5 regression matrix must pass with Composer installed, including duplicate-member and noncharacter rejection before canonicalization. Verify that the production HelioHost runtime provides the package's declared extensions (`curl`, `dom`, `libxml`, `mbstring`) before deployment. Keep the dependency pinned to 1.2.0 and retain the independent security review gate; do not update it without rerunning all RFC 8785 vectors and Appendix B.
