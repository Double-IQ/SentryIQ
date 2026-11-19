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

echo "First-run explicit storage path tests passed.\n";
