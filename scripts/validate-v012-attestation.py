#!/usr/bin/env python3
"""Validate genuine gh attestation verify JSON against SentryIQ's v0.1.2 adapter contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

EXPECTED = {
    "digest": "41cc5fc46055836ebb21ed4501bd6bd3ace249c4f352da0373b85e5a57d9c49e",
    "commit": "9c639a4792cadd5421f01ed198ba2a9261c5145f",
    "repository_id": "1345956206",
    "repository_uri": "https://github.com/Double-IQ/SentryIQ",
    "repository": "Double-IQ/SentryIQ",
    "ref": "refs/tags/v0.1.2",
    "workflow_uri": "https://github.com/Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v0.1.2",
    "issuer": "https://token.actions.githubusercontent.com",
    "predicate_type": "https://slsa.dev/provenance/v1",
    "workflow_path": ".github/workflows/release.yml",
    "event": "push",
    "runner": "github-hosted",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate-v012-attestation.py VERIFICATION_JSON")

    try:
        results = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read genuine verifier JSON: {exc}")

    if not isinstance(results, list) or not results:
        fail("gh returned no verified attestation result entries")

    failures: list[str] = []
    reports: list[dict[str, object]] = []

    for index, item in enumerate(results):
        prefix = f"result[{index}]"
        verification = item.get("verificationResult") if isinstance(item, dict) else None
        if not isinstance(verification, dict):
            failures.append(f"{prefix}: missing verificationResult")
            continue

        certificate = (verification.get("signature") or {}).get("certificate")
        statement = verification.get("statement")
        timestamps = verification.get("verifiedTimestamps")
        if not isinstance(certificate, dict):
            failures.append(f"{prefix}: missing verificationResult.signature.certificate")
            continue
        if not isinstance(statement, dict):
            failures.append(f"{prefix}: missing verificationResult.statement")
            continue
        if not isinstance(timestamps, list) or not timestamps:
            failures.append(f"{prefix}: missing verifiedTimestamps")
            continue

        checks = {
            "certificate.issuer": (certificate.get("issuer"), EXPECTED["issuer"]),
            "certificate.subjectAlternativeName": (
                certificate.get("subjectAlternativeName"),
                EXPECTED["workflow_uri"],
            ),
            "certificate.buildSignerURI": (certificate.get("buildSignerURI"), EXPECTED["workflow_uri"]),
            "certificate.buildConfigURI": (certificate.get("buildConfigURI"), EXPECTED["workflow_uri"]),
            "certificate.sourceRepositoryIdentifier": (
                str(certificate.get("sourceRepositoryIdentifier", "")),
                EXPECTED["repository_id"],
            ),
            "certificate.sourceRepositoryURI": (
                certificate.get("sourceRepositoryURI"),
                EXPECTED["repository_uri"],
            ),
            "certificate.sourceRepositoryRef": (certificate.get("sourceRepositoryRef"), EXPECTED["ref"]),
            "certificate.sourceRepositoryDigest": (
                str(certificate.get("sourceRepositoryDigest", "")).lower(),
                EXPECTED["commit"],
            ),
            "certificate.buildSignerDigest": (
                str(certificate.get("buildSignerDigest", "")).lower(),
                EXPECTED["commit"],
            ),
            "certificate.buildConfigDigest": (
                str(certificate.get("buildConfigDigest", "")).lower(),
                EXPECTED["commit"],
            ),
            "certificate.buildTrigger": (certificate.get("buildTrigger"), EXPECTED["event"]),
            "certificate.runnerEnvironment": (certificate.get("runnerEnvironment"), EXPECTED["runner"]),
            "statement.predicateType": (statement.get("predicateType"), EXPECTED["predicate_type"]),
        }

        subjects = statement.get("subject")
        subject_digests = []
        if isinstance(subjects, list):
            for subject in subjects:
                if isinstance(subject, dict):
                    digest = (subject.get("digest") or {}).get("sha256")
                    if isinstance(digest, str):
                        subject_digests.append(digest.lower())
        checks["statement.subject[].digest.sha256"] = (
            EXPECTED["digest"] if EXPECTED["digest"] in subject_digests else None,
            EXPECTED["digest"],
        )

        for field, (actual, expected) in checks.items():
            if actual != expected:
                failures.append(f"{prefix}: {field}: expected {expected!r}, got {actual!r}")

        reports.append({
            "certificate_issuer": certificate.get("issuer"),
            "certificate_san": (certificate.get("subjectAlternativeName") or {}).get("value"),
            "build_signer_uri": certificate.get("buildSignerURI"),
            "build_config_uri": certificate.get("buildConfigURI"),
            "repository_id": certificate.get("sourceRepositoryIdentifier"),
            "repository_uri": certificate.get("sourceRepositoryURI"),
            "source_ref": certificate.get("sourceRepositoryRef"),
            "source_commit": certificate.get("sourceRepositoryDigest"),
            "workflow_commit": certificate.get("buildSignerDigest"),
            "workflow_config_commit": certificate.get("buildConfigDigest"),
            "event": certificate.get("buildTrigger"),
            "runner": certificate.get("runnerEnvironment"),
            "predicate_type": statement.get("predicateType"),
            "verified_timestamp_count": len(timestamps),
            "subject_sha256_matches_release": EXPECTED["digest"] in subject_digests,
        })

    print("# Genuine v0.1.2 attestation verification")
    print()
    print(f"- Verifier result entries: {len(results)}")
    print(f"- Entries with certificate/statement evidence: {len(reports)}")
    for number, report in enumerate(reports, start=1):
        print()
        print(f"## Verified result {number}")
        for key, value in report.items():
            print(f"- {key}: `{value}`")

    if failures:
        print()
        print("## Contract mismatches")
        for failure in failures:
            print(f"- {failure}")
        fail(f"{len(failures)} adapter-contract mismatch(es)")

    print()
    print("**PASS:** Genuine GitHub CLI verification succeeded and every inspected certificate/provenance field matches the v0.1.2 adapter assumptions.")


if __name__ == "__main__":
    main()
