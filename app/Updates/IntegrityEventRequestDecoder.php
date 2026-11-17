<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Bounded decoder for machine-to-machine JSON object requests.
 * Rejects duplicate top-level keys before PHP's decoder can collapse them.
 */
final class IntegrityEventRequestDecoder
{
    /** @return array<string,mixed> */
    public static function decode(string $json, int $maxBytes = 32768): array
    {
        if ($json === '' || strlen($json) > $maxBytes || !self::isSingleObject($json)
            || self::hasDuplicateTopLevelKeys($json)) {
            throw new RuntimeException('Integrity event request JSON is empty, oversized, ambiguous or not an object.');
        }
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

    private static function isSingleObject(string $json): bool
    {
        $trimmed = trim($json);
        return str_starts_with($trimmed, '{') && str_ends_with($trimmed, '}');
    }

    private static function hasDuplicateTopLevelKeys(string $json): bool
    {
        $length = strlen($json);
        $depth = 0;
        $inString = false;
        $escaped = false;
        $keys = [];
        $stringStart = 0;

        for ($i = 0; $i < $length; $i++) {
            $char = $json[$i];
            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inString = false;
                    if ($depth === 1) {
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
                            if (!is_string($key) || isset($keys[$key])) return true;
                            $keys[$key] = true;
                        }
                    }
                }
                continue;
            }

            if ($char === '"') {
                $inString = true;
                $stringStart = $i;
            } elseif ($char === '{' || $char === '[') {
                $depth++;
            } elseif ($char === '}' || $char === ']') {
                $depth--;
            }
        }
        return false;
    }
}
