<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/UpdateManager.php';

use SentryIQ\Updates\GitHubCliAttestationVerifier;
use SentryIQ\Updates\ReleaseTrustPolicy;
use SentryIQ\Updates\UpdateManager;

function applyCheck(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function applyWrite(string $path, string $contents): void
{
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create integration fixture directory.');
    }
    if (file_put_contents($path, $contents) === false) {
        throw new RuntimeException('Unable to write integration fixture.');
    }
}

function applyRemoveTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
        else @unlink($item->getPathname());
    }
    @rmdir($path);
}

if (!class_exists(ZipArchive::class)) {
    throw new RuntimeException('The isolated updater integration test requires PHP ZipArchive.');
}

$root = sys_get_temp_dir() . '/sentryiq-update-apply-' . bin2hex(random_bytes(8));
$app = $root . '/app';
$data = $root . '/private-data';
$package = $root . '/package';
if (!mkdir($app, 0700, true) || !mkdir($data, 0700, true) || !mkdir($package, 0700, true)) {
    throw new RuntimeException('Unable to prepare isolated updater integration workspace.');
}

try {
    applyWrite($app . '/VERSION', '1.2.2');
    applyWrite($app . '/index.php', '<?php echo "old-release";');
    applyWrite($data . '/email_template.php', '<?php return "old-email-template";');

    $version = '1.2.3';
    $commit = str_repeat('c', 40);
    $packageFiles = [
        'VERSION' => $version,
        'index.php' => '<?php echo "new-release";',
        'runtime/email_template.php' => '<?php return "new-email-template";',
    ];

    $entries = [];
    $publicFiles = [];
    $runtimeFiles = [];
    foreach ($packageFiles as $relative => $contents) {
        applyWrite($package . '/' . $relative, $contents);
        $entries[] = [
            'path' => $relative,
            'size' => strlen($contents),
            'sha256' => hash('sha256', $contents),
        ];
        if (str_starts_with($relative, 'runtime/')) {
            $runtimeFiles[] = substr($relative, strlen('runtime/'));
        } else {
            $publicFiles[] = $relative;
        }
    }

    $manifest = [
        'format' => 2,
        'repository' => 'Double-IQ/SentryIQ',
        'repository_id' => '1345956206',
        'version' => $version,
        'commit' => $commit,
        'workflow_path' => '.github/workflows/release.yml',
        'public_files' => $publicFiles,
        'runtime_files' => $runtimeFiles,
        'files' => $entries,
    ];
    applyWrite(
        $package . '/update-manifest.json',
        json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)
    );

    $zipPath = $root . '/sentryiq-' . $version . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create isolated release archive.');
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($package, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($iterator as $file) {
        $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($package) + 1));
        if (!$zip->addFile($file->getPathname(), $relative)) {
            throw new RuntimeException('Unable to add a package file to the release archive.');
        }
    }
    if (!$zip->close()) {
        throw new RuntimeException('Unable to finalize isolated release archive.');
    }

    $zipDigest = hash_file('sha256', $zipPath);
    if (!is_string($zipDigest)) throw new RuntimeException('Unable to hash isolated release archive.');
    $checksumPath = $root . '/sentryiq-' . $version . '.zip.sha256';
    applyWrite($checksumPath, $zipDigest . '  sentryiq-' . $version . '.zip' . PHP_EOL);

    $zipUrl = 'https://github.com/Double-IQ/SentryIQ/releases/download/v' . $version . '/sentryiq-' . $version . '.zip';
    $checksumUrl = $zipUrl . '.sha256';
    $release = [
        'tag_name' => 'v' . $version,
        'name' => 'SentryIQ ' . $version,
        'draft' => false,
        'prerelease' => false,
        'published_at' => '2026-11-19T00:00:00Z',
        'html_url' => 'https://github.com/Double-IQ/SentryIQ/releases/tag/v' . $version,
        'assets' => [
            ['name' => 'sentryiq-' . $version . '.zip', 'browser_download_url' => $zipUrl],
            ['name' => 'sentryiq-' . $version . '.zip.sha256', 'browser_download_url' => $checksumUrl],
        ],
    ];

    $apiRunner = static function (string $url) use ($release, $commit): array {
        if (str_ends_with($url, '/releases/latest')) return $release;
        if (str_ends_with($url, '/git/ref/tags/v' . '1.2.3')) {
            return ['ref' => 'refs/tags/v1.2.3', 'object' => ['type' => 'commit', 'sha' => $commit]];
        }
        throw new RuntimeException('Unexpected API request in isolated updater integration: ' . $url);
    };

    $downloadRunner = static function (string $url, string $target) use ($zipUrl, $zipPath, $checksumPath): bool {
        if ($url === $zipUrl) return copy($zipPath, $target);
        if ($url === $zipUrl . '.sha256') return copy($checksumPath, $target);
        return false;
    };

    $workflowUri = 'https://github.com/Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v' . $version;
    $verifiedOutput = [[
        'verificationResult' => [
            'signature' => ['certificate' => [
                'issuer' => 'https://token.actions.githubusercontent.com',
                'subjectAlternativeName' => $workflowUri,
                'sourceRepositoryIdentifier' => '1345956206',
                'sourceRepositoryURI' => 'https://github.com/Double-IQ/SentryIQ',
                'sourceRepositoryDigest' => $commit,
                'sourceRepositoryRef' => 'refs/tags/v' . $version,
                'buildSignerURI' => $workflowUri,
                'buildSignerDigest' => $commit,
                'buildConfigURI' => $workflowUri,
                'buildConfigDigest' => $commit,
                'buildTrigger' => 'push',
                'runnerEnvironment' => 'github-hosted',
            ]],
            'verifiedTimestamps' => [['type' => 'Tlog', 'timestamp' => '2026-11-19T00:00:00Z']],
            'statement' => [
                'predicateType' => 'https://slsa.dev/provenance/v1',
                'subject' => [['digest' => ['sha256' => $zipDigest]]],
            ],
        ],
    ]];
    $verifierRunner = static function (array $command) use ($verifiedOutput): array {
        if (($command[1] ?? '') !== 'attestation' || ($command[2] ?? '') !== 'verify') {
            throw new RuntimeException('Updater did not invoke GitHub CLI attestation verification.');
        }
        return [0, json_encode($verifiedOutput, JSON_THROW_ON_ERROR), ''];
    };

    $verifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $verifierRunner);
    $manager = new UpdateManager($app, $data, $verifier, $apiRunner, $downloadRunner);
    $result = $manager->applyLatest();

    applyCheck(($result['status'] ?? '') === 'updated', 'Isolated update did not report success.');
    applyCheck(($result['from'] ?? '') === '1.2.2' && ($result['to'] ?? '') === $version, 'Update version transition was incorrect.');
    applyCheck(file_get_contents($app . '/VERSION') === $version, 'Application VERSION was not replaced.');
    applyCheck(file_get_contents($app . '/index.php') === '<?php echo "new-release";', 'Public application file was not replaced.');
    applyCheck(file_get_contents($data . '/email_template.php') === '<?php return "new-email-template";', 'Runtime template was not replaced.');
    applyCheck((fileperms($data . '/email_template.php') & 0777) === 0600, 'Runtime template permissions were not restricted.');

    $backupRoot = $data . '/updates/backups/' . (string)$result['backup'];
    applyCheck(
        file_get_contents($backupRoot . '/public/index.php') === '<?php echo "old-release";',
        'Successful update did not retain the original public file backup.'
    );
    applyCheck(
        file_get_contents($backupRoot . '/runtime/email_template.php') === '<?php return "old-email-template";',
        'Successful update did not retain the original runtime file backup.'
    );
    applyCheck(
        count(array_diff(scandir($data . '/updates/downloads') ?: [], ['.', '..'])) === 0,
        'Successful update left a downloaded release artifact behind.'
    );
    applyCheck(
        count(array_diff(scandir($data . '/updates/staging') ?: [], ['.', '..'])) === 0,
        'Successful update left an extracted staging directory behind.'
    );

    echo "Isolated non-production updater apply integration passed.\n";
} finally {
    applyRemoveTree($root);
}
