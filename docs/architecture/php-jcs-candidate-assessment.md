# PHP JCS candidate assessment — 2026-11-27

## Decision

No production JCS dependency is selected. The repository's trust-bundle regression matrix still includes PHP 8.1; do not raise the runtime floor implicitly and do not replace a maintained canonicalizer with a hand-written serializer.

## Candidates already exercised

- `accredifysg/php-json-canonicalize` 1.1.1: rejected by the strict-input gate because it accepts U+FDD0 (a Unicode noncharacter). Its declared PHP requirement is 8.2+.
- `mbolli/php-ron` 0.5.0: passes the recorded RFC 8785 and strict-input vectors, but its PHP 8.3+ requirement is incompatible with the current PHP 8.1 baseline.
- `mmccook/php-json-canonicalization-scheme` 1.0.0: declares PHP `^8.1` and MIT licensing, so it was added to the isolated qualification workflow. Source review of the pinned 1.0.0 tag found two blockers:
  1. Its API canonicalizes already-decoded PHP values rather than parsing raw JSON. Duplicate-member detection and strict raw UTF-8/I-JSON rejection therefore need a separate parser boundary; the package alone cannot satisfy the existing raw-input qualification contract.
  2. Its number formatter uses `number_format($number, 7, '.', '')` for values in the decimal range and default-precision `sprintf('%e', ...)` for exponent notation. Those are not ECMAScript shortest-roundtrip formatting and are insufficient for RFC 8785 Appendix B values that require more than seven fractional digits or full binary64 precision.

The pinned candidate's source is available at [JsonCanonicalizator.php](https://github.com/mmccook/php-json-canonicalization-scheme/blob/cd6d3e7645a2c1e62574a9a2437d68e9e74e799f/src/JsonCanonicalizator.php) and [Utils.php](https://github.com/mmccook/php-json-canonicalization-scheme/blob/cd6d3e7645a2c1e62574a9a2437d68e9e74e799f/src/Utils.php). The qualification harness is retained as a reproducible diagnostic, not as evidence of acceptance.

## Next gate

The PHP JCS candidate workflow must complete and record the third candidate's result. If it fails as source review predicts, keep the production gate blocked and evaluate either a separately approved PHP baseline change or a maintained PHP 8.1-compatible implementation with complete RFC 8785 and strict-input evidence. Do not select a candidate from Composer metadata or package claims alone.
