<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Loads the public pointer and then the actual private runtime configuration.
 * The webroot pointer is never treated as the source of secrets.
 */
final class IntegrityNode4RuntimeConfig
{
    /** @return array<string,mixed> */
    public static function load(string $pointerFile): array
    {
        if (is_link($pointerFile) || !is_file($pointerFile) || !is_readable($pointerFile)) {
            throw new RuntimeException('SentryIQ public configuration pointer is unavailable.');
        }
        $pointerPath = realpath($pointerFile);
        $publicRoot = realpath(dirname($pointerFile));
        if (!is_string($pointerPath) || !is_string($publicRoot)) {
            throw new RuntimeException('SentryIQ configuration paths cannot be resolved.');
        }

        $pointer = require $pointerPath;
        if (!is_array($pointer)) {
            throw new RuntimeException('SentryIQ public configuration pointer is invalid.');
        }
        foreach (['integrity_event', 'node_tokens', 'node_public_keys', 'signing_key', 'private_key', 'alert_sender'] as $secretKey) {
            if (array_key_exists($secretKey, $pointer)) {
                throw new RuntimeException('SentryIQ secrets must not be stored in the public configuration pointer.');
            }
        }
        if (!is_string($pointer['data_dir'] ?? null)
            || $pointer['data_dir'] === '' || !str_starts_with($pointer['data_dir'], DIRECTORY_SEPARATOR)
            || is_link($pointer['data_dir'])) {
            throw new RuntimeException('SentryIQ public pointer does not identify a safe private data directory.');
        }
        $dataDir = realpath($pointer['data_dir']);
        if (!is_string($dataDir) || !is_dir($dataDir) || !is_readable($dataDir)
            || $dataDir === $publicRoot
            || str_starts_with($dataDir, rtrim($publicRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('SentryIQ private data directory is missing or inside the public webroot.');
        }

        $privateFile = $dataDir . DIRECTORY_SEPARATOR . 'sentryiq_config.php';
        if (is_link($privateFile) || !is_file($privateFile) || !is_readable($privateFile)) {
            throw new RuntimeException('SentryIQ private runtime configuration is unavailable.');
        }
        $privatePath = realpath($privateFile);
        if (!is_string($privatePath) || !str_starts_with(
            $privatePath,
            rtrim($dataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
        )) {
            throw new RuntimeException('SentryIQ private runtime configuration escaped its data directory.');
        }

        $private = require $privatePath;
        if (!is_array($private)) {
            throw new RuntimeException('SentryIQ private runtime configuration is invalid.');
        }
        $event = $private['integrity_event'] ?? null;
        if (is_array($event) && ($event['enabled'] ?? false) === true) {
            if (($event['target_origin'] ?? null) !== 'https://sentryiq.bichet.co.za') {
                throw new RuntimeException('Node 4 target origin must be the canonical SentryIQ production origin.');
            }
            $expectedNodes = ['integrity-a', 'integrity-b'];
            $tokens = $event['node_tokens'] ?? null;
            $keys = $event['node_public_keys'] ?? null;
            if (!is_array($tokens) || !is_array($keys)) {
                throw new RuntimeException('Node 4 requires independent credentials and public keys for both Integrity Nodes.');
            }
            $tokenIds = array_keys($tokens);
            $keyIds = array_keys($keys);
            sort($tokenIds);
            sort($keyIds);
            if ($tokenIds !== $expectedNodes || $keyIds !== $expectedNodes) {
                throw new RuntimeException('Node 4 trust configuration must contain exactly Nodes A and B.');
            }
            $decodedKeys = [];
            foreach ($expectedNodes as $nodeId) {
                if (!is_string($tokens[$nodeId]) || !preg_match('/^[A-Za-z0-9_-]{40,128}$/', $tokens[$nodeId])) {
                    throw new RuntimeException('Node 4 bearer tokens must be high-entropy URL-safe values.');
                }
                $decoded = base64_decode((string)$keys[$nodeId], true);
                if (!is_string($decoded) || strlen($decoded) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    throw new RuntimeException('Node 4 requires valid Ed25519 public keys for both nodes.');
                }
                $decodedKeys[] = $decoded;
            }
            if (hash_equals($tokens['integrity-a'], $tokens['integrity-b'])
                || hash_equals($decodedKeys[0], $decodedKeys[1])) {
                throw new RuntimeException('Node A and B credentials and signing keys must be distinct.');
            }
        }
        if (isset($private['data_dir']) && $private['data_dir'] !== $pointer['data_dir']
            && realpath((string)$private['data_dir']) !== $dataDir) {
            throw new RuntimeException('SentryIQ public and private data directory settings disagree.');
        }

        return array_replace($pointer, $private, ['data_dir' => $dataDir]);
    }
}
