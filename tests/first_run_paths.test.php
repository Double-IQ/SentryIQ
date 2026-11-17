<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/FirstRunPaths.php';

function assert_same_value($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, "FAIL: {$message}\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

$root = sys_get_temp_dir() . '/sentryiq-first-run-paths-' . bin2hex(random_bytes(6));
$security = $root . '/httpdocs/app/Security';
$vendor = $root . '/sentryiq-tuf-patched-private/vendor';
if (!mkdir($security, 0700, true) || !mkdir($vendor, 0700, true)) {
    throw new RuntimeException('Unable to prepare temporary path fixture.');
}

try {
    assert_same_value($root, FirstRunPaths::accountRoot($security), 'account root resolves above httpdocs');
    assert_same_value($root . '/private_data', FirstRunPaths::dataDirectory($security), 'secure data directory is outside httpdocs');
    assert_same_value($root . '/httpdocs/runtime', FirstRunPaths::bundledPrivateDirectory($security), 'bundled first-run source remains under the application root');
    assert_same_value('', FirstRunPaths::sigstoreAutoload($security), 'missing private Composer autoloader disables updater configuration');

    file_put_contents($vendor . '/autoload.php', "<?php // test autoloader\n");
    assert_same_value(realpath($vendor . '/autoload.php'), FirstRunPaths::sigstoreAutoload($security), 'existing sibling private Composer autoloader is discovered');

    unlink($vendor . '/autoload.php');
    symlink($root . '/httpdocs', $vendor . '/autoload.php');
    assert_same_value('', FirstRunPaths::sigstoreAutoload($security), 'symlinked autoloader is rejected');
    unlink($vendor . '/autoload.php');

    $external = $root . '/external-dependencies';
    mkdir($external . '/vendor', 0700, true);
    file_put_contents($external . '/vendor/autoload.php', "<?php // external test autoloader\\n");
    rmdir($vendor);
    symlink($external, $root . '/sentryiq-tuf-patched-private');
    assert_same_value('', FirstRunPaths::sigstoreAutoload($security), 'symlinked dependency root is rejected');
    unlink($root . '/sentryiq-tuf-patched-private');

    echo "First-run private path tests passed.\n";
} finally {
    if (is_file($vendor . '/autoload.php') || is_link($vendor . '/autoload.php')) unlink($vendor . '/autoload.php');
    @rmdir($vendor);
    @rmdir($root . '/sentryiq-tuf-patched-private');
    @unlink($root . '/sentryiq-tuf-patched-private');
    @unlink($external . '/vendor/autoload.php');
    @rmdir($external . '/vendor');
    @rmdir($external);
    @rmdir($security);
    @rmdir(dirname($security));
    @rmdir(dirname(dirname($security)));
    @rmdir($root . '/httpdocs');
    @rmdir($root);
}
