<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$dataDir = (string)(getenv('SENTRYIQ_TEST_DATA_DIR') ?: '');
$sessionDir = (string)(getenv('SENTRYIQ_TEST_SESSION_DIR') ?: '');
$sessionId = (string)(getenv('SENTRYIQ_TEST_SESSION_ID') ?: '');

if ($dataDir === '' || $sessionDir === '' || !preg_match('/^[a-f0-9]{32}$/', $sessionId)) {
    throw new RuntimeException('Browser self-test fixture environment is incomplete.');
}
if (is_file($root . '/sentryiq_config.php') || is_link($root . '/sentryiq_config.php')) {
    throw new RuntimeException('Refusing to overwrite an existing SentryIQ config.');
}
if (!is_dir($dataDir) && !mkdir($dataDir, 0700, true)) {
    throw new RuntimeException('Unable to create isolated private data directory.');
}
if (!is_dir($sessionDir) && !mkdir($sessionDir, 0700, true)) {
    throw new RuntimeException('Unable to create isolated PHP session directory.');
}
chmod($dataDir, 0700);
chmod($sessionDir, 0700);

$config = [
    'installed' => true,
    'username' => 'ci-browser-test',
    'two_fa_email' => '',
    'base_url' => 'https://localhost',
    'data_dir' => $dataDir,
    'two_fa_token_expiry' => 300,
];
$configSource = "<?php\nreturn " . var_export($config, true) . ";\n";
if (file_put_contents($root . '/sentryiq_config.php', $configSource, LOCK_EX) === false
    || file_put_contents($dataDir . '/sentryiq_config.php', $configSource, LOCK_EX) === false) {
    throw new RuntimeException('Unable to write isolated test configuration.');
}
chmod($root . '/sentryiq_config.php', 0600);
chmod($dataDir . '/sentryiq_config.php', 0600);

foreach (['vault_engine.php', 'email_template.php', 'VaultKdfPolicy.php', 'vault_icon_cache.php'] as $template) {
    $source = $root . '/private_data/' . $template;
    if (!is_file($source) || !copy($source, $dataDir . '/' . $template)) {
        throw new RuntimeException('Unable to stage real runtime template: ' . $template);
    }
    chmod($dataDir . '/' . $template, 0600);
}

foreach (['documents', 'documents/files'] as $directory) {
    if (!is_dir($dataDir . '/' . $directory) && !mkdir($dataDir . '/' . $directory, 0700, true)) {
        throw new RuntimeException('Unable to create isolated document fixture directory.');
    }
}
file_put_contents($dataDir . '/documents/metadata.json', "{}\n", LOCK_EX);
chmod($dataDir . '/documents/metadata.json', 0600);

$passkeyStore = [
    'credentials' => [[
        'credential_id' => 'ci-fixture-credential',
        'public_key' => '',
        'created_at' => time(),
        'sign_count' => 0,
    ]],
];
file_put_contents($dataDir . '/passkeys.json', json_encode($passkeyStore, JSON_THROW_ON_ERROR), LOCK_EX);
chmod($dataDir . '/passkeys.json', 0600);

require_once $dataDir . '/vault_engine.php';
$password = 'SentryIQ-CI-only-browser-fixture-password-2026';
$records = [[
    'id' => 'sys_config_node',
    'type' => 'system_config',
    'app_username' => 'ci-browser-test',
    '2fa_email' => '',
    'imap_password' => '',
]];
if (!vault_initialize($password, $records)) {
    throw new RuntimeException('Unable to initialize isolated test vault.');
}
$unlocked = vault_unlock($password);
if (!is_array($unlocked) || !isset($unlocked['key']) || strlen((string)$unlocked['key']) !== 32) {
    throw new RuntimeException('Unable to unlock isolated test vault.');
}

$now = time();
$session = 'master_key|s:32:"' . $unlocked['key'] . '";'
    . 'authenticated_at|i:' . $now . ';'
    . 'last_activity|i:' . $now . ';'
    . 'app_username|s:15:"ci-browser-test";'
    . 'csrf_token|s:64:"' . bin2hex(random_bytes(32)) . '";';
if (file_put_contents($sessionDir . '/sess_' . $sessionId, $session, LOCK_EX) === false) {
    throw new RuntimeException('Unable to seed isolated authenticated browser session.');
}
chmod($sessionDir . '/sess_' . $sessionId, 0600);

echo "Initialized isolated SentryIQ browser fixture.\n";
