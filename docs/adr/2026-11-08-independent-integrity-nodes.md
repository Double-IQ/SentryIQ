# ADR: Independent SentryIQ Integrity Nodes and Release Assurance

- **Status:** Proposed
- **Date:** 2026-11-08
- **Scope:** Production release integrity, external origin monitoring, and incident notification
- **Tracking:** [Issue #13](https://github.com/Double-IQ/SentryIQ/issues/13)

## Context

SentryIQ is a password manager and digital vault. A compromised production origin can serve modified HTML or JavaScript to users even when vault data is encrypted at rest. A PWA cannot independently prove that its own same-origin verifier is trustworthy: the origin can replace the verifier or bypass its checks.

SentryIQ therefore needs an independent release-assurance and monitoring system. The owner has chosen two Integrity Nodes, hosted on different providers, that run independently of the production origin and report to an owner-controlled alert channel.

## Decision

Adopt a dual-node, independently operated integrity-monitoring architecture, combined with a signed release process.

### Trust boundaries

1. **Source and review:** GitHub repository, protected main branch, reviewed pull requests, and release approvals.
2. **Build and release:** CI produces immutable artifacts and a canonical manifest. Release signing is performed with a key that is not available to the production host and is not casually exposed to ordinary build jobs.
3. **Trust root:** A release-signing public key and anti-rollback policy are pinned independently by both Integrity Nodes.
4. **Integrity Node 1 and Node 2:** Separate providers, separate credentials, independent schedules, independent reports, and separate alert delivery paths where practical. Neither node's result is accepted as proof by the other.
5. **Production origin:** Treated as the monitored target, not as a source of trust. It must not be able to change node software, trust roots, expected manifests, schedules, or alert destinations.
6. **Owner alert channel:** Operates independently of the production origin.

### Release manifest

Each approved release should have a canonical, versioned manifest containing at least:

- SentryIQ release version and monotonic release sequence;
- source commit and build identity;
- canonical relative file paths;
- file sizes and SHA-256 hashes;
- manifest format/version and creation time;
- signing-key identifier and signature.

The signature authenticates the manifest. A checksum published beside an artifact by the same release account is not a substitute for an independently trusted signature.

The signing private key must never be stored on the production host. The final key-custody design (offline hardware-backed key, controlled signing workstation, or constrained keyless attestation policy) must be approved before production signing is enabled. Nodes receive only public verification material.

### Node responsibilities

Each node independently:

- retrieves the expected manifest from a trust channel the production origin cannot rewrite;
- verifies the manifest signature, validity, release sequence, and anti-rollback policy;
- checks public HTTP-visible resources, including HTML, JavaScript, CSS, images, web manifests, service-worker resources if introduced, redirects, externally loaded script origins, and relevant response headers;
- detects changed, missing, unexpected, and newly exposed public files;
- records check time, target response, expected and observed hashes, and verifier version;
- signs its report and sends alerts independently;
- detects stale checks, verifier failures, target unavailability, and disagreement with the other node.

Nodes should distinguish a confirmed integrity mismatch from availability failures, expected release transitions, and advisory security-header drift. Missing or invalid trusted manifests must never be treated as a successful verification.

### Private server-side files

An external HTTP monitor cannot hash private PHP source files, private configuration, or files that are not served over HTTP. Those require a separate authenticated, read-only deployment attestation or host-side collector. That mechanism must report file hashes and deployment identity only; it must not expose secrets, runtime data, vault content, or credentials to either node.

A collector running with production-host privileges is itself part of the trust boundary and must be designed, authenticated, constrained, and independently verified. Do not describe HTTP scanning as verification of private PHP source.

### CI/CD and origin hardening

- Run PHP and JavaScript syntax checks, tests, dependency review/scanning, secret scanning, and static security checks on relevant pull requests and main-branch changes.
- Protect main and release tags with review and required checks.
- Build immutable release artifacts and produce canonical manifests and provenance.
- Verify artifacts and deployed public files against the signed manifest.
- Audit deployment credentials and ensure web/PHP runtime identities cannot write application source or release artifacts where hosting permits.
- Audit third-party scripts and remove unnecessary dependencies.
- Tighten CSP incrementally. Remove `unsafe-inline` only after auditing and migrating inline scripts/styles; do not break authentication or Gallery flows in pursuit of a nominally strict policy.
- Keep monitoring and alert credentials out of the production application and repository.

### Incident handling

A confirmed mismatch should freeze further automated releases, preserve evidence, alert the owner through an independent channel, and trigger a documented investigation and recovery procedure. User notifications must not rely solely on the possibly compromised origin.

One node's isolated alert should not automatically disable vault access. Define confidence thresholds and corroboration rules so a compromised or faulty node cannot cause arbitrary lockouts. Node outage and node disagreement must still alert the owner.

## Consequences and limitations

- Two providers reduce single-provider and single-control-plane risk, but do not eliminate common-mode failures such as compromised source control, compromised signing authority, compromised DNS, or compromised owner accounts.
- Monitoring detects changes after they become observable. It does not guarantee prevention before a visitor receives malicious code.
- The dual-node system does not independently protect an iPhone PWA from malicious same-origin JavaScript before detection. Strong enforcement on iPhone requires a separately trusted client component or an explicitly accepted residual risk.
- Public-resource monitoring and private server-file attestation are separate verification mechanisms and must be reported separately.
- The architecture adds hosting, maintenance, key-custody, and incident-response responsibilities.

## Repository audit baseline (2026-11-08)

- `.github/workflows/release.yml` creates a ZIP and SHA-256 checksum but does not cryptographically sign a release manifest.
- `app/Updates/UpdateManager.php` verifies the package checksum but does not verify an independent signature.
- `.github/workflows/gallery-security.yml` has a feature-branch push filter and PR trigger; it is not a general security gate for all main-branch pushes.
- `app/Security/SecurityBootstrap.php` currently emits `script-src 'self' 'unsafe-inline'`.
- No tracked service-worker or web-app-manifest file was found in the repository tree during this audit.
- `app/Updates/UpdateManager.php` names `BTM-SA/SentryIQ` as its release repository, while the repository being audited is `Double-IQ/SentryIQ`. Confirm whether this is intentional before modifying updater behavior.

## Implementation order

1. Inventory the production deployment and define the release-signing trust model.
2. Harden CI checks, branch/tag protections, and immutable artifact generation.
3. Add canonical signed manifests and independent signature verification.
4. Implement one Integrity Node and adversarially test it.
5. Deploy the second node on a different provider and verify independence.
6. Add private-file deployment attestation if hosting supports a safe read-only mechanism.
7. Tighten CSP and origin permissions incrementally with compatibility tests.
8. Test alert delivery, node compromise/outage, rollback, and incident response.
