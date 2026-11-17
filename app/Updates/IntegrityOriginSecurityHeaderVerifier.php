<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/** Verifies the browser-security header posture visible at the public origin. */
final class IntegrityOriginSecurityHeaderVerifier
{
    /** @var callable(string):array{status:int,headers:array<string,string>} */
    private $request;

    public function __construct(?callable $request = null)
    {
        $this->request = $request ?? fn(string $url): array => $this->curlGet($url);
    }

    /**
     * @return array{approved:bool,mismatches:list<string>,headers:array<string,string>}
     */
    public function verify(string $origin): array
    {
        $parts = parse_url($origin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || (isset($parts['port']) && $parts['port'] !== 443)
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || ($parts['path'] ?? '') !== '') {
            throw new RuntimeException('Origin header verifier requires the canonical SentryIQ HTTPS origin.');
        }

        $response = ($this->request)(rtrim($origin, '/') . '/VERSION');
        if (!is_array($response) || ($response['status'] ?? null) !== 200
            || !is_array($response['headers'] ?? null)) {
            throw new RuntimeException('Origin security header probe did not return HTTP 200 without redirects.');
        }
        $headers = [];
        foreach ($response['headers'] as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        $mismatches = [];
        $hsts = $headers['strict-transport-security'] ?? '';
        if (!preg_match('/(?:^|;)\s*max-age\s*=\s*(\d+)/i', $hsts, $match)
            || (int)$match[1] < 31536000) {
            $mismatches[] = 'strict-transport-security';
        }
        if (strtolower($headers['x-content-type-options'] ?? '') !== 'nosniff') {
            $mismatches[] = 'x-content-type-options';
        }
        if (strtolower($headers['x-frame-options'] ?? '') !== 'deny') {
            $mismatches[] = 'x-frame-options';
        }
        if (strtolower($headers['referrer-policy'] ?? '') !== 'strict-origin-when-cross-origin') {
            $mismatches[] = 'referrer-policy';
        }

        $permissions = strtolower($headers['permissions-policy'] ?? '');
        foreach (['camera', 'microphone', 'geolocation'] as $feature) {
            if (!preg_match('/(?:^|,)\s*' . preg_quote($feature, '/') . '\s*=\s*\(\)/', $permissions)) {
                $mismatches[] = 'permissions-policy:' . $feature;
            }
        }

        $csp = strtolower($headers['content-security-policy'] ?? '');
        foreach (["frame-ancestors 'none'", "base-uri 'self'", "object-src 'none'"] as $directive) {
            if (!str_contains($csp, $directive)) {
                $mismatches[] = 'content-security-policy:' . $directive;
            }
        }

        return [
            'approved' => $mismatches === [],
            'mismatches' => $mismatches,
            'headers' => $headers,
        ];
    }

    /** @return array{status:int,headers:array<string,string>} */
    private function curlGet(string $url): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL is required for origin security header verification.');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize origin security header probe.');
        }
        $headers = [];
        $body = '';
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HTTPHEADER => [
                'Cache-Control: no-cache, no-store, no-transform',
                'Pragma: no-cache',
            ],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > 128) return 0;
                $body .= $chunk;
                return strlen($chunk);
            },
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headers): int {
                $length = strlen($line);
                if (preg_match('/^([^:]+):\s*(.*)$/', trim($line), $match)) {
                    $name = strtolower(trim($match[1]));
                    $value = trim($match[2]);
                    $headers[$name] = isset($headers[$name]) ? $headers[$name] . ', ' . $value : $value;
                }
                return $length;
            },
        ]);
        $ok = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        if ($ok === false) {
            throw new RuntimeException('Origin security header HTTPS probe failed.');
        }
        return ['status' => $status, 'headers' => $headers];
    }
}
