<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Bounded decoder for machine-to-machine JSON object requests.
 * Rejects duplicate object keys at every depth before PHP's decoder can collapse them.
 */
final class IntegrityEventRequestDecoder
{
    /** @return array<string,mixed> */
    public static function decode(string $json, int $maxBytes = 32768): array
    {
        if ($json === '' || strlen($json) > $maxBytes || !self::isSingleObject($json)) {
            throw new RuntimeException('Integrity event request JSON is empty, oversized, ambiguous or not an object.');
        }
        self::assertNoDuplicateObjectKeys($json);
        try {
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Integrity event request JSON is invalid.', 0, $exception);
        }
        if (!is_array($decoded) || array_is_list($decoded) || !is_string($decoded['action'] ?? null)) {
            throw new RuntimeException('Integrity event request object schema is invalid.');
        }
        return $decoded;
    }

    /** @param array<string,mixed> $request @param list<string> $expected */
    public static function assertExactFields(array $request, array $expected): void
    {
        $actual = array_keys($request);
        sort($actual);
        sort($expected);
        if ($actual !== $expected) {
            throw new RuntimeException('Integrity event request fields do not match the selected action.');
        }
    }

    private static function isSingleObject(string $json): bool
    {
        $trimmed = trim($json);
        return str_starts_with($trimmed, '{') && str_ends_with($trimmed, '}');
    }

    /** Reject duplicate keys in every JSON object, not just the outer request. */
    public static function assertNoDuplicateObjectKeys(string $json): void
    {
        if (self::hasDuplicateObjectKeys($json)) {
            throw new RuntimeException('JSON contains duplicate object keys.');
        }
    }

    private static function hasDuplicateObjectKeys(string $json): bool
    {
        $length = strlen($json);
        $stack = [];
        $inString = false;
        $escaped = false;
        $stringStart = 0;

        for ($i = 0; $i < $length; $i++) {
            $char = $json[$i];
            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inString = false;
                    $containerIndex = count($stack) - 1;
                    if ($containerIndex >= 0 && ($stack[$containerIndex]['type'] ?? null) === 'object') {
                        $end = $i + 1;
                        while ($end < $length && ctype_space($json[$end])) $end++;
                        if ($end < $length && $json[$end] === ':') {
                            try {
                                $key = json_decode(
                                    substr($json, $stringStart, $i - $stringStart + 1),
                                    true,
                                    2,
                                    JSON_THROW_ON_ERROR
                                );
                            } catch (\JsonException) {
                                return true;
                            }
                            if (!is_string($key) || isset($stack[$containerIndex]['keys'][$key])) return true;
                            $stack[$containerIndex]['keys'][$key] = true;
                        }
                    }
                }
                continue;
            }

            if ($char === '"') {
                $inString = true;
                $stringStart = $i;
            } elseif ($char === '{') {
                $stack[] = ['type' => 'object', 'keys' => []];
            } elseif ($char === '[') {
                $stack[] = ['type' => 'array'];
            } elseif ($char === '}' || $char === ']') {
                if ($stack === []) return true;
                array_pop($stack);
            }
        }
        return $inString || $stack !== [];
    }
}
