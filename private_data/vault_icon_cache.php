<?php

declare(strict_types=1);

/**
 * Fetch and persist a site's icon, preferring its Open Graph image and
 * falling back to a declared favicon/icon and then /favicon.ico.
 * Stored assets remain inside SENTRYIQ_DATA_DIR and are never served directly.
 */
function cache_vault_icon(string $url, string $entryId): array
{
    $empty = [
        'icon_type' => null,
        'icon_path' => null,
        'icon_source' => null,
        'icon_fetched_at' => null,
    ];

    if ($url === '' || !function_exists('curl_init')) {
        return $empty;
    }

    $parts = parse_url($url);
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])) {
        return $empty;
    }

    $host = strtolower((string)$parts['host']);
    $originHost = str_contains($host, ':') ? '[' . $host . ']' : $host;
    $origin = 'https://' . $originHost;

    $page = curl_vault_asset($url, false);
    if ($page === null) {
        return $empty;
    }

    $pageUrl = $page['final_url'] !== '' ? $page['final_url'] : $url;
    $baseParts = parse_url($pageUrl);
    if (!is_array($baseParts) || strtolower((string)($baseParts['scheme'] ?? '')) !== 'https' || empty($baseParts['host'])) {
        return $empty;
    }
    $baseHost = strtolower((string)$baseParts['host']);
    $baseOrigin = 'https://' . (str_contains($baseHost, ':') ? '[' . $baseHost . ']' : $baseHost);

    $faviconUrl = null;
    $ogImageUrl = null;

    if (stripos($page['content_type'], 'text/html') !== false || stripos($page['body'], '<html') !== false) {
        if (class_exists('DOMDocument')) {
            libxml_use_internal_errors(true);
            $dom = new DOMDocument();

            if (@$dom->loadHTML($page['body'])) {
                foreach ($dom->getElementsByTagName('link') as $link) {
                    $rel = strtolower(trim((string)$link->getAttribute('rel')));
                    $href = trim((string)$link->getAttribute('href'));
                    if ($href !== '' && (str_contains($rel, 'icon') || str_contains($rel, 'shortcut'))) {
                        $candidate = resolve_vault_asset_url($href, $pageUrl, $baseOrigin);
                        if ($candidate !== null) {
                            $faviconUrl = $candidate;
                            break;
                        }
                    }
                }

                foreach ($dom->getElementsByTagName('meta') as $meta) {
                    $property = strtolower(trim((string)$meta->getAttribute('property')));
                    $name = strtolower(trim((string)$meta->getAttribute('name')));
                    $content = trim((string)$meta->getAttribute('content'));
                    if ($content !== '' && ($property === 'og:image' || $name === 'og:image')) {
                        $candidate = resolve_vault_asset_url($content, $pageUrl, $baseOrigin);
                        if ($candidate !== null) {
                            $ogImageUrl = $candidate;
                            break;
                        }
                    }
                }
            }

            libxml_clear_errors();
        }
    }

    $candidates = [];
    if ($ogImageUrl !== null) $candidates[] = ['type' => 'og_image', 'url' => $ogImageUrl];
    if ($faviconUrl !== null) $candidates[] = ['type' => 'favicon', 'url' => $faviconUrl];
    $candidates[] = ['type' => 'favicon', 'url' => $origin . '/favicon.ico'];

    foreach ($candidates as $candidate) {
        $image = curl_vault_asset($candidate['url'], true);
        if ($image === null) continue;

        $directory = rtrim(SENTRYIQ_DATA_DIR, '/') . '/vault_icons';
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            return $empty;
        }
        @chmod($directory, 0700);

        $extension = detect_vault_image_extension($image['body'], $image['content_type']);
        if ($extension === null) continue;

        $filePath = $directory . '/' . hash('sha256', $entryId) . '.' . $extension;
        if (@file_put_contents($filePath, $image['body'], LOCK_EX) === false) continue;
        @chmod($filePath, 0600);

        return [
            'icon_type' => $candidate['type'],
            'icon_path' => $filePath,
            'icon_source' => $candidate['url'],
            'icon_fetched_at' => date('c'),
        ];
    }

    return $empty;
}

function vault_icon_ipv4_in_cidr(string $ip, string $cidr): bool
{
    [$network, $prefix] = explode('/', $cidr, 2);
    $ipBytes = inet_pton($ip);
    $networkBytes = inet_pton($network);
    if ($ipBytes === false || $networkBytes === false || strlen($ipBytes) !== 4 || strlen($networkBytes) !== 4) {
        return false;
    }
    $prefixBits = (int)$prefix;
    $mask = $prefixBits === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefixBits)) & 0xFFFFFFFF);
    $ipValue = unpack('N', $ipBytes)[1];
    $networkValue = unpack('N', $networkBytes)[1];
    return ($ipValue & $mask) === ($networkValue & $mask);
}

function vault_icon_is_public_ip(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) return false;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return false;

    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        foreach ([
            '0.0.0.0/8',
            '10.0.0.0/8',
            '100.64.0.0/10',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.0.0.0/24',
            '192.0.2.0/24',
            '192.88.99.0/24',
            '192.168.0.0/16',
            '198.18.0.0/15',
            '198.51.100.0/24',
            '203.0.113.0/24',
            '224.0.0.0/4',
            '240.0.0.0/4',
        ] as $range) {
            if (vault_icon_ipv4_in_cidr($ip, $range)) return false;
        }
        return true;
    }

    // Reject address-translation/tunnelling ranges because they can encode
    // an otherwise-private IPv4 destination behind a globally-routable IPv6.
    $blockedIpv6Prefixes = [
        '::ffff:0:0/96',
        '64:ff9b::/96',
        '64:ff9b:1::/48',
        '2001::/23',
        '2001:db8::/32',
        '2002::/16',
    ];
    $packed = inet_pton($ip);
    if ($packed === false || strlen($packed) !== 16) return false;
    // Only globally routable unicast space (2000::/3) is eligible.
    if ((ord($packed[0]) & 0xE0) !== 0x20) return false;
    foreach ($blockedIpv6Prefixes as $range) {
        [$network, $prefix] = explode('/', $range, 2);
        $networkBytes = inet_pton($network);
        if ($networkBytes === false) continue;
        $bits = (int)$prefix;
        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;
        if (substr($packed, 0, $wholeBytes) !== substr($networkBytes, 0, $wholeBytes)) continue;
        if ($remainingBits === 0) return false;
        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
        if ((ord($packed[$wholeBytes]) & $mask) === (ord($networkBytes[$wholeBytes]) & $mask)) return false;
    }
    return true;
}

/**
 * Resolve and pin every DNS answer. If even one answer is private/reserved,
 * reject the hostname rather than allowing round-robin selection to reach it.
 *
 * @return list<string>
 */
function vault_icon_filter_public_addresses(array $addresses): array
{
    $addresses = array_values(array_unique(array_filter($addresses, 'is_string')));
    if ($addresses === []) return [];
    foreach ($addresses as $address) {
        if (!vault_icon_is_public_ip($address)) return [];
    }
    return $addresses;
}

function vault_icon_remote_url_parts(string $url): ?array
{
    $parts = parse_url($url);
    if (!is_array($parts)
        || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
        || empty($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])
        || (isset($parts['port']) && (int)$parts['port'] !== 443)) {
        return null;
    }
    $host = strtolower((string)$parts['host']);
    if (!filter_var($host, FILTER_VALIDATE_IP)
        && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        return null;
    }
    return ['host' => $host, 'port' => 443];
}

function vault_icon_append_bounded_body(string &$body, string $chunk, int $maxBytes): int
{
    if ($maxBytes < 0 || strlen($body) + strlen($chunk) > $maxBytes) return 0;
    $body .= $chunk;
    return strlen($chunk);
}

function vault_icon_resolve_public_addresses(string $host): array
{
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return vault_icon_is_public_ip($host) ? [$host] : [];
    }

    $records = @dns_get_record($host, DNS_A | DNS_AAAA);
    if (!is_array($records) || $records === []) return [];
    $addresses = [];
    foreach ($records as $record) {
        if (isset($record['ip']) && is_string($record['ip'])) $addresses[] = $record['ip'];
        if (isset($record['ipv6']) && is_string($record['ipv6'])) $addresses[] = $record['ipv6'];
    }
    return vault_icon_filter_public_addresses($addresses);
}

function curl_vault_asset(string $url, bool $imageOnly): ?array
{
    $urlParts = vault_icon_remote_url_parts($url);
    if ($urlParts === null) return null;
    $host = $urlParts['host'];
    $addresses = vault_icon_resolve_public_addresses($host);
    if ($addresses === []) return null;

    $resolveEntries = [];
    if (filter_var($host, FILTER_VALIDATE_IP) === false) {
        $pinnedAddresses = array_map(
            static fn(string $address): string => str_contains($address, ':') ? '[' . $address . ']' : $address,
            $addresses
        );
        $resolveEntries[] = $host . ':443:' . implode(',', $pinnedAddresses);
    }

    $ch = curl_init($url);
    if ($ch === false) return null;

    $body = '';
    $tooLarge = false;
    $maxBytes = 5 * 1024 * 1024;
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_USERAGENT => 'SentryIQ/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_RESOLVE => $resolveEntries,
        CURLOPT_FAILONERROR => true,
        CURLOPT_HTTPHEADER => $imageOnly
            ? ['Accept: image/avif,image/webp,image/png,image/jpeg,image/gif,image/x-icon,*/*;q=0.8']
            : ['Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'],
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$tooLarge, $maxBytes): int {
            $written = vault_icon_append_bounded_body($body, $chunk, $maxBytes);
            if ($written === 0 && $chunk !== '') $tooLarge = true;
            return $written;
        },
    ]);

    $ok = curl_exec($ch);
    $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = strtolower((string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE));
    $finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    $finalParts = parse_url($finalUrl !== '' ? $finalUrl : $url);
    if ($tooLarge
        || $ok !== true
        || $httpCode < 200
        || $httpCode >= 300
        || !is_array($finalParts)
        || strtolower((string)($finalParts['scheme'] ?? '')) !== 'https'
        || strtolower((string)($finalParts['host'] ?? '')) !== $host
        || (isset($finalParts['port']) && (int)$finalParts['port'] !== 443)
        || $body === '') {
        return null;
    }

    return [
        'body' => $body,
        'content_type' => $contentType,
        'final_url' => $finalUrl,
    ];
}

function resolve_vault_asset_url(string $assetUrl, string $pageUrl, string $origin): ?string
{
    $assetUrl = trim(html_entity_decode($assetUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    if ($assetUrl === '' || str_starts_with(strtolower($assetUrl), 'data:') || str_starts_with(strtolower($assetUrl), 'javascript:')) return null;

    if (str_starts_with($assetUrl, '//')) {
        return 'https:' . $assetUrl;
    }

    if (preg_match('#^https://#i', $assetUrl)) return $assetUrl;
    if (str_starts_with($assetUrl, 'http://')) return null;
    if (str_starts_with($assetUrl, '/')) return rtrim($origin, '/') . $assetUrl;

    $path = parse_url($pageUrl, PHP_URL_PATH) ?: '/';
    $directory = rtrim(str_replace('\\', '/', dirname($path)), '/');
    return rtrim($origin, '/') . ($directory !== '' ? $directory : '') . '/' . ltrim($assetUrl, '/');
}

function detect_vault_image_extension(string $body, string $contentType): ?string
{
    $mime = '';
    $imageInfo = @getimagesizefromstring($body);
    if ($imageInfo !== false && !empty($imageInfo['mime'])) {
        $mime = strtolower((string)$imageInfo['mime']);
    } elseif ($contentType !== '') {
        $mime = strtolower(trim(explode(';', $contentType)[0]));
    }

    return match ($mime) {
        'image/png' => 'png',
        'image/jpeg', 'image/jpg' => 'jpg',
        'image/gif' => 'gif',
        'image/webp' => 'webp',
        'image/avif' => 'avif',
        'image/x-icon', 'image/vnd.microsoft.icon' => 'ico',
        default => null,
    };
}