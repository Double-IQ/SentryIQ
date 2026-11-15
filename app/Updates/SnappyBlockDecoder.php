<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Decodes a raw Snappy block (the format used by GitHub's .json.sn
 * artifact-attestation bundle URLs) without requiring a native PHP extension.
 */
final class SnappyBlockDecoder
{
    public static function decode(string $input, int $maximumOutputBytes): string
    {
        $inputLength = strlen($input);
        if ($inputLength < 2 || $maximumOutputBytes < 1) {
            throw new RuntimeException('Snappy block is empty or has an invalid output limit.');
        }

        $offset = 0;
        $expectedLength = self::readVarint($input, $offset);
        if ($expectedLength < 1 || $expectedLength > $maximumOutputBytes) {
            throw new RuntimeException('Snappy block declares an invalid or excessive uncompressed length.');
        }

        $output = '';
        while ($offset < $inputLength) {
            $tag = ord($input[$offset++]);
            $type = $tag & 0x03;

            if ($type === 0) {
                $encodedLength = $tag >> 2;
                if ($encodedLength < 60) {
                    $length = $encodedLength + 1;
                } else {
                    $lengthBytes = $encodedLength - 59;
                    if ($lengthBytes < 1 || $lengthBytes > 4 || $offset + $lengthBytes > $inputLength) {
                        throw new RuntimeException('Snappy literal length is malformed or truncated.');
                    }
                    $lengthMinusOne = 0;
                    for ($i = 0; $i < $lengthBytes; $i++) {
                        $lengthMinusOne |= ord($input[$offset++]) << (8 * $i);
                    }
                    $length = $lengthMinusOne + 1;
                    if ($lengthBytes > 1 && $lengthMinusOne < (1 << (8 * ($lengthBytes - 1)))) {
                        throw new RuntimeException('Snappy literal length is not minimally encoded.');
                    }
                }

                if ($offset + $length > $inputLength || strlen($output) + $length > $expectedLength) {
                    throw new RuntimeException('Snappy literal exceeds its input or declared output length.');
                }
                $output .= substr($input, $offset, $length);
                $offset += $length;
                continue;
            }

            if ($type === 1) {
                if ($offset >= $inputLength) {
                    throw new RuntimeException('Snappy one-byte copy offset is truncated.');
                }
                $length = 4 + (($tag >> 2) & 0x07);
                $copyOffset = (($tag & 0xe0) << 3) | ord($input[$offset++]);
            } elseif ($type === 2) {
                if ($offset + 2 > $inputLength) {
                    throw new RuntimeException('Snappy two-byte copy offset is truncated.');
                }
                $length = 1 + ($tag >> 2);
                $copyOffset = ord($input[$offset]) | (ord($input[$offset + 1]) << 8);
                $offset += 2;
            } else {
                if ($offset + 4 > $inputLength) {
                    throw new RuntimeException('Snappy four-byte copy offset is truncated.');
                }
                $length = 1 + ($tag >> 2);
                $copyOffset = ord($input[$offset])
                    | (ord($input[$offset + 1]) << 8)
                    | (ord($input[$offset + 2]) << 16)
                    | (ord($input[$offset + 3]) << 24);
                $offset += 4;
            }

            $currentLength = strlen($output);
            if ($copyOffset < 1 || $copyOffset > $currentLength
                || $currentLength + $length > $expectedLength) {
                throw new RuntimeException('Snappy copy operation references invalid or excessive output.');
            }

            // Byte-wise copying deliberately supports Snappy's overlapping
            // back-references (for example, repeating a short literal).
            for ($i = 0; $i < $length; $i++) {
                $output .= $output[strlen($output) - $copyOffset];
            }
        }

        if (strlen($output) !== $expectedLength) {
            throw new RuntimeException('Snappy block output length does not match its declaration.');
        }
        return $output;
    }

    private static function readVarint(string $input, int &$offset): int
    {
        $length = strlen($input);
        $value = 0;
        for ($i = 0; $i < 5; $i++) {
            if ($offset >= $length) {
                throw new RuntimeException('Snappy uncompressed length varint is truncated.');
            }
            $byte = ord($input[$offset++]);
            $payload = $byte & 0x7f;
            if ($i === 4 && $payload > 0x0f) {
                throw new RuntimeException('Snappy uncompressed length varint overflows 32 bits.');
            }
            $value |= $payload << (7 * $i);
            if (($byte & 0x80) === 0) {
                if ($i > 0 && $payload === 0) {
                    throw new RuntimeException('Snappy uncompressed length varint is not minimally encoded.');
                }
                return $value;
            }
        }
        throw new RuntimeException('Snappy uncompressed length varint is too long.');
    }
}
