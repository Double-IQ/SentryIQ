<?php

declare(strict_types=1);

require_once __DIR__ . '/../private_data/vault_icon_cache.php';

function iconSecurityCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function iconSecurityReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$publicAddresses = [
    '8.8.8.8',
    '1.1.1.1',
    '2606:4700:4700::1111',
];
foreach ($publicAddresses as $address) {
    iconSecurityCheck(vault_icon_is_public_ip($address), 'Public address was incorrectly rejected: ' . $address);
}

$blockedAddresses = [
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '192.0.0.10',
    '192.0.2.1',
    '192.168.1.1',
    '198.18.0.1',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    'ff02::1',
    '2002::1',
];
foreach ($blockedAddresses as $address) {
    iconSecurityCheck(!vault_icon_is_public_ip($address), 'Private/reserved address was accepted: ' . $address);
}

iconSecurityCheck(
    vault_icon_filter_public_addresses(['8.8.8.8', '1.1.1.1']) === ['8.8.8.8', '1.1.1.1'],
    'A set of public DNS answers should be accepted.'
);
iconSecurityCheck(
    vault_icon_filter_public_addresses(['8.8.8.8', '127.0.0.1']) === [],
    'A mixed public/private DNS answer set must be rejected in full.'
);
iconSecurityCheck(
    vault_icon_filter_public_addresses(['169.254.169.254']) === [],
    'A metadata-service DNS answer must be rejected.'
);

iconSecurityCheck(
    vault_icon_remote_url_parts('https://example.com/icon.png') === ['host' => 'example.com', 'port' => 443],
    'A normal HTTPS URL should be accepted.'
);
foreach ([
    'http://example.com/icon.png',
    'https://127.0.0.1/icon.png',
    'https://example.com:8443/icon.png',
    'https://user:pass@example.com/icon.png',
    'file:///etc/passwd',
] as $url) {
    iconSecurityCheck(vault_icon_remote_url_parts($url) === null, 'Unsafe remote URL was accepted: ' . $url);
}

$body = '1234';
iconSecurityCheck(
    vault_icon_append_bounded_body($body, '5678', 8) === 4 && $body === '12345678',
    'Bounded response writer should accept data up to the configured limit.'
);
iconSecurityCheck(
    vault_icon_append_bounded_body($body, '9', 8) === 0 && $body === '12345678',
    'Bounded response writer must reject data beyond the configured limit.'
);

echo "Vault icon SSRF and response-size tests passed.\\n";
