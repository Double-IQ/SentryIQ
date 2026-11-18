<?php

declare(strict_types=1);

namespace SentryIQ\Auth;

use RuntimeException;

/**
 * Minimal bounded CBOR reader for the ES256 COSE_Key carried in
 * WebAuthn attested credential data. This is parsing, not signature crypto.
 */
final class WebAuthnCose
{
    public static function decodeFirst(string $data, int &$offset = 0, int $depth = 0): mixed
    {
        if ($depth > 8 || $offset < 0 || $offset >= strlen($data)) {
            throw new RuntimeException('Invalid or excessively nested WebAuthn CBOR data.');
        }

        $initial = ord($data[$offset++]);
        $major = $initial >> 5;
        $additional = $initial & 0x1f;

        if ($major === 7) {
            return match ($additional) {
                20 => false,
                21 => true,
                22 => null,
                default => throw new RuntimeException('Unsupported WebAuthn CBOR simple value.'),
            };
        }

        $length = self::readLength($data, $offset, $additional);
        if ($length > 4096) {
            throw new RuntimeException('WebAuthn CBOR value exceeds the size limit.');
        }

        return match ($major) {
            0 => $length,
            1 => -1 - $length,
            2 => self::readBytes($data, $offset, $length),
            3 => self::readText($data, $offset, $length),
            4 => self::readArray($data, $offset, $length, $depth),
            5 => self::readMap($data, $offset, $length, $depth),
            default => throw new RuntimeException('Unsupported WebAuthn CBOR major type.'),
        };
    }

    public static function ec2P256SpkiDer(array $cose): string
    {
        if (($cose[1] ?? null) !== 2
            || ($cose[3] ?? null) !== -7
            || ($cose[-1] ?? null) !== 1) {
            throw new RuntimeException('Passkey COSE key must be an ES256 P-256 EC2 key.');
        }

        $x = $cose[-2] ?? null;
        $y = $cose[-3] ?? null;
        if (!is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
            throw new RuntimeException('Passkey COSE key coordinates are invalid.');
        }

        $prefix = hex2bin('3059301306072A8648CE3D020106082A8648CE3D03010703420004');
        if (!is_string($prefix)) {
            throw new RuntimeException('Unable to encode the passkey public key.');
        }
        return $prefix . $x . $y;
    }

    public static function pemToDer(string $pem): string
    {
        $body = preg_replace(
            '/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/',
            '',
            trim($pem)
        );
        if (!is_string($body) || $body === '') {
            throw new RuntimeException('Submitted passkey public key is not valid PEM.');
        }
        $der = base64_decode($body, true);
        if (!is_string($der) || $der === '') {
            throw new RuntimeException('Submitted passkey public key is not valid PEM.');
        }
        return $der;
    }

    private static function readLength(string $data, int &$offset, int $additional): int
    {
        if ($additional < 24) return $additional;
        $byteCount = match ($additional) {
            24 => 1,
            25 => 2,
            26 => 4,
            default => throw new RuntimeException('Unsupported or oversized WebAuthn CBOR length.'),
        };
        if ($offset + $byteCount > strlen($data)) {
            throw new RuntimeException('Truncated WebAuthn CBOR length.');
        }
        $bytes = substr($data, $offset, $byteCount);
        $offset += $byteCount;
        $value = match ($byteCount) {
            1 => ord($bytes[0]),
            2 => unpack('n', $bytes)[1],
            4 => unpack('N', $bytes)[1],
        };
        if (!is_int($value) || $value > 4096) {
            throw new RuntimeException('WebAuthn CBOR length exceeds the configured limit.');
        }
        return $value;
    }

    private static function readBytes(string $data, int &$offset, int $length): string
    {
        if ($offset + $length > strlen($data)) {
            throw new RuntimeException('Truncated WebAuthn CBOR byte string.');
        }
        $value = substr($data, $offset, $length);
        $offset += $length;
        return $value;
    }

    private static function readText(string $data, int &$offset, int $length): string
    {
        $value = self::readBytes($data, $offset, $length);
        if (preg_match('//u', $value) !== 1) {
            throw new RuntimeException('WebAuthn CBOR text is not valid UTF-8.');
        }
        return $value;
    }

    private static function readArray(string $data, int &$offset, int $length, int $depth): array
    {
        $values = [];
        for ($index = 0; $index < $length; $index++) {
            $values[] = self::decodeFirst($data, $offset, $depth + 1);
        }
        return $values;
    }

    private static function readMap(string $data, int &$offset, int $length, int $depth): array
    {
        $values = [];
        for ($index = 0; $index < $length; $index++) {
            $key = self::decodeFirst($data, $offset, $depth + 1);
            if (!is_int($key) && !is_string($key)) {
                throw new RuntimeException('Unsupported WebAuthn CBOR map key.');
            }
            if (array_key_exists($key, $values)) {
                throw new RuntimeException('Duplicate WebAuthn CBOR map key.');
            }
            $values[$key] = self::decodeFirst($data, $offset, $depth + 1);
        }
        return $values;
    }
}
