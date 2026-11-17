<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/ReleaseArtifactVerifier.php';
require_once __DIR__ . '/../app/Updates/ReleaseTrustPolicy.php';
require_once __DIR__ . '/../app/Updates/NativeSigstoreIntegrityAttestationVerifier.php';

use SentryIQ\Updates\NativeSigstoreIntegrityAttestationVerifier;
use SentryIQ\Updates\ReleaseArtifactVerifier;
use SentryIQ\Updates\ReleaseTrustPolicy;

final class FakeReleaseArtifactVerifier implements ReleaseArtifactVerifier
{
    /** @var list<string> */
    public array $subjects = [];

    public function verifyArtifact(string $artifactPath, string $version, string $expectedSubjectName): array
    {
        $this->subjects[] = $expectedSubjectName;
        return [
            'cryptographically_verified' => true,
            'repository' => 'Double-IQ/SentryIQ',
            'repository_id' => '1345956206',
            'source_ref' => 'refs/tags/v' . $version,
            'source_commit' => str_repeat('a', 40),
            'workflow_path' => '.github/workflows/release.yml',
            'workflow_ref' => 'Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v' . $version,
            'source_event' => 'push',
            'subject_sha256' => hash_file('sha256', $artifactPath),
        ];
    }
}

function adapterAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function adapterReject(callable $call, string $message): void
{
    try {
        $call();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$directory = sys_get_temp_dir() . '/sentryiq-native-node-adapter-' . bin2hex(random_bytes(6));
if (!mkdir($directory, 0700)) throw new RuntimeException('Unable to create adapter test directory.');

try {
    $manifest = $directory . '/release-manifest.json';
    $zip = $directory . '/sentryiq-1.2.3.zip';
    $unexpected = $directory . '/unexpected.json';
    file_put_contents($manifest, '{"format":2}');
    file_put_contents($zip, 'test-zip-bytes');
    file_put_contents($unexpected, '{}');

    $fake = new FakeReleaseArtifactVerifier();
    $adapter = new NativeSigstoreIntegrityAttestationVerifier($fake, new ReleaseTrustPolicy());
    $commit = str_repeat('a', 40);

    call_user_func($adapter, $manifest, '1.2.3', $commit, '1.2.2');
    call_user_func($adapter, $zip, '1.2.3', $commit, '1.2.2');
    adapterAssert($fake->subjects === ['release-manifest.json', 'sentryiq-1.2.3.zip'], 'Adapter must verify the canonical manifest and ZIP as separate subjects.');

    adapterReject(
        static fn() => call_user_func($adapter, $unexpected, '1.2.3', $commit, '1.2.2'),
        'Adapter must reject artifacts outside the approved subject set.'
    );
    adapterReject(
        static fn() => call_user_func($adapter, $zip, '1.2.3', $commit, '1.2.3'),
        'Adapter must reject rollback or same-version replay.'
    );
} finally {
    @unlink($manifest ?? '');
    @unlink($zip ?? '');
    @unlink($unexpected ?? '');
    @rmdir($directory);
}

echo "Native Sigstore integrity adapter tests passed.\\n";
