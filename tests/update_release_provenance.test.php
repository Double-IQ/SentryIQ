<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/UpdateManager.php';

use SentryIQ\Updates\GitHubCliAttestationVerifier;
use SentryIQ\Updates\ReleaseTrustPolicy;
use SentryIQ\Updates\UpdateManager;

function releaseCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function releaseReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function releaseWrite(string $path, string $contents): void
{
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create release test directory.');
    }
    if (file_put_contents($path, $contents) === false) {
        throw new RuntimeException('Unable to write release test fixture.');
    }
}

function releaseRemoveTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) rmdir($item->getPathname());
        else unlink($item->getPathname());
    }
    rmdir($path);
}

$root = sys_get_temp_dir() . '/sentryiq-release-trust-' . bin2hex(random_bytes(8));
$app = $root . '/app';
$data = $root . '/data';
$staging = $root . '/staging';
if (!mkdir($app, 0700, true) || !mkdir($data, 0700, true) || !mkdir($staging, 0700, true)) {
    throw new RuntimeException('Unable to prepare release trust test workspace.');
}

try {
    $commit = str_repeat('a', 40);
    $version = '1.2.3';
    $files = [
        'index.php' => '<?php echo "safe";',
        'assets/app.js' => 'window.SentryIQ = true;',
        'runtime/email_template.php' => '<?php return "email";',
        'runtime/vault_engine.php' => '<?php return "vault";',
        'runtime/vault_icon_cache.php' => '<?php return "icons";',
        'runtime/VaultKdfPolicy.php' => '<?php return "kdf";',
    ];
    $entries = [];
    $public = [];
    $runtime = [];
    foreach ($files as $relative => $contents) {
        releaseWrite($staging . '/' . $relative, $contents);
        $entries[] = [
            'path' => $relative,
            'size' => strlen($contents),
            'sha256' => hash('sha256', $contents),
        ];
        if (str_starts_with($relative, 'runtime/')) $runtime[] = substr($relative, 8);
        else $public[] = $relative;
    }
    $manifest = [
        'format' => 2,
        'repository' => 'Double-IQ/SentryIQ',
        'repository_id' => '1345956206',
        'version' => $version,
        'commit' => $commit,
        'workflow_path' => '.github/workflows/release.yml',
        'public_files' => $public,
        'runtime_files' => $runtime,
        'files' => $entries,
    ];

    $apiRunner = static function (string $url) use ($commit): array {
        if (str_ends_with($url, '/git/ref/tags/v1.2.3')) {
            return [
                'ref' => 'refs/tags/v1.2.3',
                'object' => ['type' => 'commit', 'sha' => $commit],
            ];
        }
        throw new RuntimeException('Unexpected GitHub API URL in test: ' . $url);
    };
    $manager = new UpdateManager($app, $data, null, $apiRunner);
    $manifestMethod = new ReflectionMethod(UpdateManager::class, 'assertManifestMatchesPackage');
    $manifestMethod->setAccessible(true);
    $manifestMethod->invoke($manager, $manifest, $staging, $version, $commit);

    $badCommit = $manifest;
    $badCommit['commit'] = str_repeat('b', 40);
    releaseReject(
        fn() => $manifestMethod->invoke($manager, $badCommit, $staging, $version, $commit),
        'Manifest with a different source commit must be rejected.'
    );

    $badDigest = $manifest;
    $badDigest['files'][0]['sha256'] = hash('sha256', 'tampered');
    releaseReject(
        fn() => $manifestMethod->invoke($manager, $badDigest, $staging, $version, $commit),
        'Manifest with a mismatched file digest must be rejected.'
    );

    $badPath = $manifest;
    $badPath['files'][0]['path'] = '../outside.php';
    releaseReject(
        fn() => $manifestMethod->invoke($manager, $badPath, $staging, $version, $commit),
        'Manifest path traversal must be rejected.'
    );

    $badRuntime = $manifest;
    $badRuntime['runtime_files'][] = 'sentryiq_config.php';
    releaseReject(
        fn() => $manifestMethod->invoke($manager, $badRuntime, $staging, $version, $commit),
        'Unapproved runtime PHP files must be rejected.'
    );

    releaseWrite($staging . '/unlisted.php', '<?php echo "unlisted";');
    releaseReject(
        fn() => $manifestMethod->invoke($manager, $manifest, $staging, $version, $commit),
        'Files not listed in the attested manifest must be rejected.'
    );
    unlink($staging . '/unlisted.php');

    // Annotated tags must be dereferenced to a commit; tag object SHAs are not
    // accepted as source commit identities.
    $tagObject = str_repeat('b', 40);
    $annotatedApi = static function (string $url) use ($commit, $tagObject): array {
        if (str_ends_with($url, '/git/ref/tags/v1.2.3')) {
            return ['ref' => 'refs/tags/v1.2.3', 'object' => ['type' => 'tag', 'sha' => $tagObject]];
        }
        if (str_ends_with($url, '/git/tags/' . $tagObject)) {
            return ['tag' => 'v1.2.3', 'object' => ['type' => 'commit', 'sha' => $commit]];
        }
        throw new RuntimeException('Unexpected GitHub API URL in annotated-tag test.');
    };
    $annotatedManager = new UpdateManager($app, $data, null, $annotatedApi);
    $resolveMethod = new ReflectionMethod(UpdateManager::class, 'resolveReleaseCommit');
    $resolveMethod->setAccessible(true);
    releaseCheck(
        $resolveMethod->invoke($annotatedManager, $version) === $commit,
        'Annotated release tag did not resolve to its commit.'
    );

    // Verify that the updater passes the independently resolved commit and the
    // actual local artifact into the maintained GitHub CLI attestation adapter.
    $artifact = $root . '/release.zip';
    releaseWrite($artifact, 'synthetic test archive');
    $artifactDigest = hash_file('sha256', $artifact);
    $workflowUri = 'https://github.com/Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v1.2.3';
    $verifiedOutput = [[
        'verificationResult' => [
            'signature' => ['certificate' => [
                'issuer' => 'https://token.actions.githubusercontent.com',
                'subjectAlternativeName' => $workflowUri,
                'sourceRepositoryIdentifier' => '1345956206',
                'sourceRepositoryURI' => 'https://github.com/Double-IQ/SentryIQ',
                'sourceRepositoryDigest' => $commit,
                'sourceRepositoryRef' => 'refs/tags/v1.2.3',
                'buildSignerURI' => $workflowUri,
                'buildSignerDigest' => $commit,
                'buildConfigURI' => $workflowUri,
                'buildConfigDigest' => $commit,
                'buildTrigger' => 'push',
                'runnerEnvironment' => 'github-hosted',
            ]],
            'verifiedTimestamps' => [['type' => 'Tlog', 'timestamp' => '2026-11-18T00:00:00Z']],
            'statement' => [
                'predicateType' => 'https://slsa.dev/provenance/v1',
                'subject' => [['digest' => ['sha256' => $artifactDigest]]],
            ],
        ],
    ]];
    $verifierRunner = static fn(array $command): array => [0, json_encode($verifiedOutput, JSON_THROW_ON_ERROR), ''];
    $verifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $verifierRunner);
    $trustedManager = new UpdateManager($app, $data, $verifier, $apiRunner);
    $verifyMethod = new ReflectionMethod(UpdateManager::class, 'verifyReleaseArtifact');
    $verifyMethod->setAccessible(true);
    releaseCheck(
        $verifyMethod->invoke($trustedManager, $artifact, $version, '1.2.2') === $commit,
        'Updater did not enforce the GitHub attestation against the resolved release commit.'
    );

    echo "Updater release provenance and manifest tests passed.\\n";
} finally {
    releaseRemoveTree($root);
}
