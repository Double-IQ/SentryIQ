<?php

declare(strict_types=1);

/**
 * Experimental native-PHP verification harness.
 *
 * This is deliberately a CI harness, not a production Node C adapter. It
 * verifies real GitHub Sigstore bundles with k2gl/sigstore-verify, then applies
 * SentryIQ's GitHub SLSA provenance policy to the authenticated DSSE payload.
 */

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\SubjectPolicy;
use K2gl\Sigstore\TrustedRoot;

$vendor = getenv('SENTRYIQ_SIGSTORE_VENDOR') ?: dirname(__DIR__) . '/.native-verifier/vendor';
$autoload = $vendor . '/autoload.php';
if (!is_file($autoload)) {
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, "Composer autoload file is missing: {$autoload}\n");
    } else {
        http_response_code(500);
        echo "FAIL: Composer autoload file is missing.\n";
    }
    exit(2);
}
require $autoload;

function fail(string $message): never
{
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, "FAIL: {$message}\n");
    } else {
        if (!headers_sent()) {
            http_response_code(500);
        }
        echo "FAIL: {$message}\n";
    }
    exit(1);
}

/** @return array<string, mixed> */
function readStatement(string $payload): array
{
    try {
        $statement = json_decode($payload, true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        throw new RuntimeException('Authenticated DSSE payload is not valid JSON.', 0, $exception);
    }
    if (!is_array($statement)) {
        throw new RuntimeException('Authenticated DSSE payload is not a JSON object.');
    }
    return $statement;
}

/**
 * Check GitHub's SLSA provenance fields only after Sigstore verification has
 * authenticated the envelope. External parameters are still policy-checked.
 *
 * @param array<string, mixed> $statement
 */
function assertSentryIqProvenance(array $statement, string $version, string $commit, string $digest, string $expectedRepo = 'Double-IQ/SentryIQ'): void
{
    $repoUri = 'https://github.com/' . $expectedRepo;
    $workflow = '.github/workflows/release.yml';
    $ref = 'refs/tags/v' . $version;

    if (($statement['predicateType'] ?? null) !== 'https://slsa.dev/provenance/v1') {
        throw new RuntimeException('Unexpected SLSA predicate type.');
    }

    $subjects = $statement['subject'] ?? null;
    $subjectMatches = false;
    if (is_array($subjects)) {
        foreach ($subjects as $subject) {
            if (is_array($subject)
                && is_array($subject['digest'] ?? null)
                && is_string($subject['digest']['sha256'] ?? null)
                && hash_equals($digest, strtolower($subject['digest']['sha256']))) {
                $subjectMatches = true;
            }
        }
    }
    if (!$subjectMatches) {
        throw new RuntimeException('Authenticated provenance subject does not match the local artifact.');
    }

    $predicate = $statement['predicate'] ?? null;
    $definition = is_array($predicate) ? ($predicate['buildDefinition'] ?? null) : null;
    $external = is_array($definition) ? ($definition['externalParameters'] ?? null) : null;
    $workflowInput = is_array($external) ? ($external['workflow'] ?? null) : null;
    if (!is_array($workflowInput)
        || ($workflowInput['repository'] ?? null) !== $repoUri
        || ($workflowInput['path'] ?? null) !== $workflow
        || ($workflowInput['ref'] ?? null) !== $ref) {
        throw new RuntimeException('Authenticated provenance workflow repository/path/ref does not match policy.');
    }

    $internal = is_array($definition) ? ($definition['internalParameters'] ?? null) : null;
    $github = is_array($internal) ? ($internal['github'] ?? null) : null;
    if (!is_array($github)
        || (string)($github['repository_id'] ?? '') !== '1345956206'
        || ($github['event_name'] ?? null) !== 'push') {
        throw new RuntimeException('Authenticated provenance repository ID or event does not match policy.');
    }

    // SLSA builder.id identifies the trusted build platform/workflow, not
    // the individual GitHub-hosted runner image. Match the exact workflow
    // identity here; do not infer runner type from this field.
    $runDetails = is_array($predicate) ? ($predicate['runDetails'] ?? null) : null;
    $builder = is_array($runDetails) ? ($runDetails['builder'] ?? null) : null;
    $expectedBuilder = $repoUri . '/' . $workflow . '@' . $ref;
    if (!is_array($builder)
        || ($builder['id'] ?? null) !== $expectedBuilder) {
        throw new RuntimeException('Provenance builder workflow identity does not match policy: ' . json_encode($builder['id'] ?? null, JSON_UNESCAPED_SLASHES));
    }

    $dependencies = is_array($definition) ? ($definition['resolvedDependencies'] ?? null) : null;
    $sourceFound = false;
    if (is_array($dependencies)) {
        foreach ($dependencies as $dependency) {
            if (!is_array($dependency) || !is_array($dependency['digest'] ?? null)) {
                continue;
            }
            $uri = $dependency['uri'] ?? null;
            $gitCommit = $dependency['digest']['gitCommit'] ?? null;
            if (is_string($uri)
                && $uri === 'git+' . $repoUri . '@' . $ref
                && is_string($gitCommit)
                && hash_equals($commit, strtolower($gitCommit))) {
                $sourceFound = true;
                break;
            }
        }
    }
    if (!$sourceFound) {
        throw new RuntimeException('Provenance resolved source dependency does not match the expected tag commit.');
    }
}

/**
 * Decode one DER-encoded UTF8String as returned by openssl_x509_parse() for
 * GitHub's Fulcio certificate extensions. Reject BER, truncation, and trailing
 * bytes rather than accepting ambiguous encodings.
 */
function decodeFulcioUtf8Extension(string $raw, string $field): string
{
    $size = strlen($raw);
    if ($size < 2 || ord($raw[0]) !== 0x0c) {
        throw new RuntimeException("Fulcio certificate extension {$field} is not a DER UTF8String.");
    }

    $firstLength = ord($raw[1]);
    $offset = 2;
    if (($firstLength & 0x80) === 0) {
        $length = $firstLength;
    } else {
        $lengthBytes = $firstLength & 0x7f;
        if ($lengthBytes < 1 || $lengthBytes > 4 || $size < 2 + $lengthBytes || ord($raw[2]) === 0) {
            throw new RuntimeException("Fulcio certificate extension {$field} has an invalid DER length.");
        }
        $length = 0;
        for ($i = 0; $i < $lengthBytes; $i++) {
            $length = ($length << 8) | ord($raw[2 + $i]);
        }
        if ($length < 0x80) {
            throw new RuntimeException("Fulcio certificate extension {$field} uses a non-minimal DER length.");
        }
        $offset += $lengthBytes;
    }

    if ($length < 1 || $offset + $length !== $size) {
        throw new RuntimeException("Fulcio certificate extension {$field} has a truncated value or trailing bytes.");
    }
    $value = substr($raw, $offset, $length);
    if (preg_match('//u', $value) !== 1) {
        throw new RuntimeException("Fulcio certificate extension {$field} is not valid UTF-8.");
    }
    return $value;
}

/**
 * Read and enforce the signed GitHub-specific claims from the verified leaf
 * certificate. This complements, rather than replaces, Sigstore's chain,
 * signature, transparency-log, and SAN/issuer verification.
 */
function assertSentryIqCertificateClaims(
    string $leafDer,
    string $version,
    string $commit,
    string $expectedRepo = 'Double-IQ/SentryIQ',
    string $expectedRunner = 'github-hosted'
): void {
    $pem = "-----BEGIN CERTIFICATE-----\n"
        . chunk_split(base64_encode($leafDer), 64, "\n")
        . "-----END CERTIFICATE-----\n";
    $certificate = openssl_x509_read($pem);
    $parsed = $certificate !== false ? openssl_x509_parse($certificate, false) : false;
    $extensions = is_array($parsed) ? ($parsed['extensions'] ?? null) : null;
    if (!is_array($extensions)) {
        throw new RuntimeException('Unable to parse authenticated Fulcio leaf certificate extensions.');
    }

    $oids = [
        'issuer_v1' => '1.3.6.1.4.1.57264.1.1',
        'issuer_v2' => '1.3.6.1.4.1.57264.1.8',
        'build_signer_uri' => '1.3.6.1.4.1.57264.1.9',
        'build_signer_digest' => '1.3.6.1.4.1.57264.1.10',
        'runner_environment' => '1.3.6.1.4.1.57264.1.11',
        'source_repository_uri' => '1.3.6.1.4.1.57264.1.12',
        'source_repository_digest' => '1.3.6.1.4.1.57264.1.13',
        'source_repository_ref' => '1.3.6.1.4.1.57264.1.14',
        'source_repository_identifier' => '1.3.6.1.4.1.57264.1.15',
        'build_config_uri' => '1.3.6.1.4.1.57264.1.18',
        'build_config_digest' => '1.3.6.1.4.1.57264.1.19',
        'build_trigger' => '1.3.6.1.4.1.57264.1.20',
    ];

    $claims = [];
    foreach ($oids as $name => $oid) {
        if (!is_string($extensions[$oid] ?? null) || $extensions[$oid] === '') {
            throw new RuntimeException("Fulcio certificate is missing required signed claim {$name}.");
        }
        $claims[$name] = $name === 'issuer_v1'
            ? $extensions[$oid]
            : decodeFulcioUtf8Extension($extensions[$oid], $name);
    }

    $repoUri = 'https://github.com/' . $expectedRepo;
    $tagRef = 'refs/tags/v' . $version;
    $workflowUri = $repoUri . '/.github/workflows/release.yml@' . $tagRef;
    $expected = [
        'issuer_v1' => 'https://token.actions.githubusercontent.com',
        'issuer_v2' => 'https://token.actions.githubusercontent.com',
        'build_signer_uri' => $workflowUri,
        'build_signer_digest' => $commit,
        'runner_environment' => $expectedRunner,
        'source_repository_uri' => $repoUri,
        'source_repository_digest' => $commit,
        'source_repository_ref' => $tagRef,
        'source_repository_identifier' => '1345956206',
        'build_config_uri' => $workflowUri,
        'build_config_digest' => $commit,
        'build_trigger' => 'push',
    ];
    $claims['issuer_v2'] = decodeFulcioUtf8Extension(
        $extensions[$oids['issuer_v2']] ?? '',
        'issuer_v2'
    );

    foreach ($expected as $name => $value) {
        if (!hash_equals($value, $claims[$name])) {
            throw new RuntimeException("Fulcio certificate claim {$name} does not match SentryIQ release policy.");
        }
    }

    $expectedSan = 'URI:' . $workflowUri;
    if (($extensions['subjectAltName'] ?? null) !== $expectedSan) {
        throw new RuntimeException('Fulcio certificate SAN does not match the exact release workflow identity.');
    }
}

/**
 * @return list<string>
 */
function readJsonLines(string $path): array
{
    $raw = @file_get_contents($path);
    if (!is_string($raw) || $raw === '' || strlen($raw) > 20_000_000) {
        throw new RuntimeException('Attestation bundle file is missing, empty, or exceeds 20 MB.');
    }
    $lines = preg_split('/\r?\n/', trim($raw));
    if (!is_array($lines) || $lines === []) {
        throw new RuntimeException('Attestation bundle file contains no JSON lines.');
    }
    return array_values(array_filter($lines, static fn(string $line): bool => trim($line) !== ''));
}

if ($argc !== 5) {
    fail('Usage: php validate-native-php-sigstore.php ARTIFACT BUNDLE.jsonl VERSION COMMIT');
}
[, $artifactPath, $bundlePath, $version, $commit] = $argv;
$commit = strtolower(trim($commit));
if (!preg_match('/^[a-f0-9]{40}$/', $commit) || !preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
    fail('Invalid release version or full Git commit SHA.');
}
if (!is_file($artifactPath) || is_link($artifactPath) || !is_readable($artifactPath)) {
    fail('Artifact must be a readable regular file.');
}
$digest = hash_file('sha256', $artifactPath);
if (!is_string($digest)) {
    fail('Unable to hash artifact.');
}

try {
    // Refresh the public-good trust root through Sigstore's TUF metadata.
    // This is intentionally separate from GitHub's attestation API trust.
    $trustedRoot = TrustedRoot::fromSigstorePublicGood();
    $verifier = new SigstoreVerifier();
    $identity = IdentityPolicy::githubActions(
        'Double-IQ/SentryIQ',
        'release.yml',
        'refs/tags/v' . $version
    );
    $subject = new SubjectPolicy('sha256', $digest);
    $verified = 0;
    $acceptedBundleJson = null;
    $lastFailure = null;

    foreach (readJsonLines($bundlePath) as $line) {
        try {
            $bundle = Bundle::fromJson($line);
            $envelope = $verifier->verify($bundle, $trustedRoot, $identity, $subject);
            $statement = readStatement($envelope->payload);
            assertSentryIqProvenance($statement, $version, $commit, $digest);
            $verified++;
            $acceptedBundleJson ??= $line;
        } catch (Throwable $exception) {
            $lastFailure = $exception;
        }
    }

    if ($verified < 1) {
        throw new RuntimeException(
            'No Sigstore bundle passed cryptographic verification and SentryIQ provenance policy: '
                . ($lastFailure instanceof Throwable ? get_class($lastFailure) . ': ' . $lastFailure->getMessage() : 'unknown failure'),
            0,
            $lastFailure
        );
    }

    $inspectionBundle = Bundle::fromJson($acceptedBundleJson);
    if (!is_string($inspectionBundle->leafCertificate)) {
        throw new RuntimeException('Verified bundle has no Fulcio leaf certificate.');
    }
    assertSentryIqCertificateClaims($inspectionBundle->leafCertificate, $version, $commit);

    // Negative controls: the same authentic bundle must fail for a wrong
    // artifact digest and for a different workflow identity.
    if (!is_string($acceptedBundleJson)) {
        throw new RuntimeException('Internal error: no accepted bundle was retained for negative controls.');
    }
    $firstBundle = Bundle::fromJson($acceptedBundleJson);
    $tamperRejected = false;
    try {
        $verifier->verify(
            $firstBundle,
            $trustedRoot,
            $identity,
            new SubjectPolicy('sha256', hash('sha256', 'tampered artifact'))
        );
    } catch (Throwable) {
        $tamperRejected = true;
    }
    if (!$tamperRejected) {
        throw new RuntimeException('Negative control failed: wrong artifact digest was accepted.');
    }

    $identityRejected = false;
    try {
        $verifier->verify(
            $firstBundle,
            $trustedRoot,
            IdentityPolicy::githubActions(
                'attacker/other-repository',
                'release.yml',
                'refs/tags/v' . $version
            ),
            $subject
        );
    } catch (Throwable) {
        $identityRejected = true;
    }
    if (!$identityRejected) {
        throw new RuntimeException('Negative control failed: wrong signer identity was accepted.');
    }

    // Tamper with the DSSE signature bytes while preserving a syntactically
    // valid bundle. The cryptographic verifier must reject it.
    $tamperedSignatureRejected = false;
    $tamperedData = json_decode($acceptedBundleJson, true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($tamperedData)
        || !is_array($tamperedData['dsseEnvelope']['signatures'][0] ?? null)
        || !is_string($tamperedData['dsseEnvelope']['signatures'][0]['sig'] ?? null)) {
        throw new RuntimeException('Unexpected DSSE bundle structure; cannot run signature-tamper negative control.');
    }
    $tamperedData['dsseEnvelope']['signatures'][0]['sig'] = base64_encode(str_repeat("\\0", 64));
    $tamperedJson = json_encode($tamperedData, JSON_THROW_ON_ERROR);
    try {
        $verifier->verify(Bundle::fromJson($tamperedJson), $trustedRoot, $identity, $subject);
    } catch (Throwable) {
        $tamperedSignatureRejected = true;
    }
    if (!$tamperedSignatureRejected) {
        throw new RuntimeException('Negative control failed: altered DSSE signature was accepted.');
    }

    // The authenticated statement must not validate against a different
    // repository, source commit, or release tag policy.
    $wrongRepositoryRejected = false;
    try {
        assertSentryIqProvenance($statement, $version, $commit, $digest, 'attacker/other-repository');
    } catch (Throwable) {
        $wrongRepositoryRejected = true;
    }
    if (!$wrongRepositoryRejected) {
        throw new RuntimeException('Negative control failed: wrong provenance repository was accepted.');
    }

    $wrongCommitRejected = false;
    try {
        assertSentryIqProvenance($statement, $version, str_repeat('0', 40), $digest);
    } catch (Throwable) {
        $wrongCommitRejected = true;
    }
    if (!$wrongCommitRejected) {
        throw new RuntimeException('Negative control failed: wrong source commit was accepted.');
    }

    $wrongTagRejected = false;
    try {
        assertSentryIqProvenance($statement, '9.9.9', $commit, $digest);
    } catch (Throwable) {
        $wrongTagRejected = true;
    }
    if (!$wrongTagRejected) {
        throw new RuntimeException('Negative control failed: wrong release tag was accepted.');
    }

    $wrongRunnerRejected = false;
    try {
        assertSentryIqCertificateClaims($inspectionBundle->leafCertificate, $version, $commit, 'Double-IQ/SentryIQ', 'self-hosted');
    } catch (Throwable) {
        $wrongRunnerRejected = true;
    }
    if (!$wrongRunnerRejected) {
        throw new RuntimeException('Negative control failed: wrong runner environment was accepted.');
    }

    $wrongCertificateCommitRejected = false;
    try {
        assertSentryIqCertificateClaims($inspectionBundle->leafCertificate, $version, str_repeat('0', 40));
    } catch (Throwable) {
        $wrongCertificateCommitRejected = true;
    }
    if (!$wrongCertificateCommitRejected) {
        throw new RuntimeException('Negative control failed: wrong certificate source/build commit was accepted.');
    }

    $wrongCertificateRepositoryRejected = false;
    try {
        assertSentryIqCertificateClaims($inspectionBundle->leafCertificate, $version, $commit, 'attacker/other-repository');
    } catch (Throwable) {
        $wrongCertificateRepositoryRejected = true;
    }
    if (!$wrongCertificateRepositoryRejected) {
        throw new RuntimeException('Negative control failed: wrong certificate repository was accepted.');
    }

    foreach ([
        "truncated" => "\x0c\x02A",
        "trailing bytes" => "\x0c\x01A\x00",
        "non-minimal length" => "\x0c\x81\x01A",
        "indefinite length" => "\x0c\x80\x00\x00",
        "invalid UTF-8" => "\x0c\x01\xff",
    ] as $case => $malformedDer) {
        $malformedRejected = false;
        try {
            decodeFulcioUtf8Extension($malformedDer, $case);
        } catch (Throwable) {
            $malformedRejected = true;
        }
        if (!$malformedRejected) {
            throw new RuntimeException("Negative control failed: malformed DER {$case} was accepted.");
        }
    }

    echo "PASS: {$verified} bundle(s) passed native PHP Sigstore verification and SentryIQ provenance policy.\n";
    echo "PASS: wrong digest, signer, DSSE signature, repository, source commit, release tag, runner, certificate commit/repository, and malformed DER were rejected.\n";
    echo "Artifact SHA-256: {$digest}\n";
} catch (Throwable $exception) {
    fail($exception->getMessage());
}
