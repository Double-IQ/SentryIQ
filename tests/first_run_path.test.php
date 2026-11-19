<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/FirstRunPath.php';

function firstRunPathAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

firstRunPathAssert(
    sentryiq_first_run_configured_data_dir([], '/home/bicheveb/sentryiq-private') === '/home/bicheveb/sentryiq-private',
    'An explicitly configured absolute cPanel storage path should be accepted.'
);
firstRunPathAssert(
    sentryiq_first_run_configured_data_dir(['SENTRYIQ_DATA_DIR' => '/home/bicheveb/sentryiq-private'], '') === '/home/bicheveb/sentryiq-private',
    'The Apache/server environment variable should be accepted when getenv is unavailable.'
);
firstRunPathAssert(
    sentryiq_first_run_configured_data_dir([], '') === '',
    'Missing storage configuration must fail closed.'
);
firstRunPathAssert(
    sentryiq_first_run_configured_data_dir([], 'relative/private') === '',
    'Relative storage paths must be rejected.'
);
firstRunPathAssert(
    sentryiq_first_run_configured_data_dir([], '/home/bicheveb/../private') === '',
    'Parent traversal must be rejected.'
);
firstRunPathAssert(
    sentryiq_first_run_configured_data_dir([], '/home/bicheveb/public_html/private') === '',
    'Web-root-like storage paths must be rejected.'
);
firstRunPathAssert(
    sentryiq_first_run_configured_data_dir([], '/') === '',
    'Filesystem root must be rejected.'
);

$fixture = sys_get_temp_dir() . '/sentryiq-first-run-' . bin2hex(random_bytes(6));
$accountRoot = $fixture . '/account';
$docRoot = $accountRoot . '/sentryiq.bichet.co.za';
$outside = $fixture . '/outside';
if (!mkdir($docRoot, 0700, true) || !mkdir($outside, 0700, true)) {
    throw new RuntimeException('Unable to create first-run path fixtures.');
}
try {
    firstRunPathAssert(
        sentryiq_first_run_path_is_safe_candidate($accountRoot . '/sentryiq-private', $docRoot),
        'A sibling protected directory under the cPanel account root should be accepted.'
    );
    firstRunPathAssert(
        !sentryiq_first_run_path_is_safe_candidate($docRoot . '/private_data', $docRoot),
        'A path inside the document root must be rejected before directory creation.'
    );
    firstRunPathAssert(
        !sentryiq_first_run_path_is_safe_candidate($outside . '/private_data', $docRoot),
        'A path outside the cPanel account root must be rejected.'
    );
    firstRunPathAssert(
        !sentryiq_first_run_path_is_safe_candidate($accountRoot . '/sentryiq-private', ''),
        'A missing document root must fail closed for web first-run storage.'
    );
    $linkedParent = $fixture . '/linked-account';
    if (!symlink($accountRoot, $linkedParent)) {
        throw new RuntimeException('Unable to create symlinked account-root fixture.');
    }
    firstRunPathAssert(
        !sentryiq_first_run_path_is_safe_candidate($linkedParent . '/sentryiq-private', $docRoot),
        'A symlinked account-root parent must be rejected.'
    );
    unlink($linkedParent);
} finally {
    rmdir($docRoot);
    rmdir($accountRoot);
    rmdir($outside);
    rmdir($fixture);
}


echo "First-run explicit storage path tests passed.\n";
