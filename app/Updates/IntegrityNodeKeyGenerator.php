<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/** Creates one node-local Ed25519 report-signing identity without overwriting keys. */
final class IntegrityNodeKeyGenerator
{
    /**
     * @return array{node_id:string,private_key_path:string,public_key_path:string,public_key_base64:string}
     */
    public function generate(string $nodeId, string $privateDataDirectory, string $publicWebRoot): array
    {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b', 'integrity-c'], true)) {
            throw new RuntimeException('Integrity node key identity must be integrity-a, integrity-b or integrity-c.');
        }
        if (!function_exists('sodium_crypto_sign_keypair')) {
            throw new RuntimeException('PHP sodium is required to generate Integrity Node signing keys.');
        }

        $private = realpath($privateDataDirectory);
        $web = realpath($publicWebRoot);
        if (!is_string($private) || !is_dir($private) || is_link($privateDataDirectory)
            || !is_string($web) || !is_dir($web) || is_link($publicWebRoot)) {
            throw new RuntimeException('Node key generation requires real private-data and public-web directories.');
        }
        if ($private === $web
            || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Node signing keys must be stored outside the public webroot.');
        }
        if (!@chmod($private, 0700) || ((fileperms($private) ?: 0) & 0077) !== 0) {
            throw new RuntimeException('Node private-data directory must have 0700 permissions.');
        }

        $privatePath = $private . '/' . $nodeId . '.ed25519.key';
        $publicPath = $private . '/' . $nodeId . '.ed25519.pub';
        if (file_exists($privatePath) || is_link($privatePath)
            || file_exists($publicPath) || is_link($publicPath)) {
            throw new RuntimeException('Node signing key already exists; refusing to overwrite or rotate it.');
        }

        $pair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($pair);
        $public = sodium_crypto_sign_publickey($pair);
        sodium_memzero($pair);
        if (strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
            || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new RuntimeException('Sodium returned an invalid Ed25519 keypair.');
        }

        $privateTemp = $privatePath . '.tmp-' . bin2hex(random_bytes(8));
        $publicTemp = $publicPath . '.tmp-' . bin2hex(random_bytes(8));
        $privateCreated = false;
        $publicCreated = false;
        try {
            if (@file_put_contents($privateTemp, $secret, LOCK_EX) !== strlen($secret)
                || !@chmod($privateTemp, 0600)
                || @file_put_contents($publicTemp, $public, LOCK_EX) !== strlen($public)
                || !@chmod($publicTemp, 0600)) {
                throw new RuntimeException('Unable to write private temporary node key files.');
            }
            // Hard-link publication is atomic and refuses to replace an existing key.
            if (!@link($privateTemp, $privatePath)) {
                throw new RuntimeException('Private node signing key already exists or could not be published.');
            }
            $privateCreated = true;
            if (!@link($publicTemp, $publicPath)) {
                throw new RuntimeException('Public node signing key already exists or could not be published.');
            }
            $publicCreated = true;
        } catch (\Throwable $exception) {
            @unlink($privateTemp);
            @unlink($publicTemp);
            if ($privateCreated) @unlink($privatePath);
            if ($publicCreated) @unlink($publicPath);
            throw $exception;
        } finally {
            sodium_memzero($secret);
        }
        @unlink($privateTemp);
        @unlink($publicTemp);

        return [
            'node_id' => $nodeId,
            'private_key_path' => $privatePath,
            'public_key_path' => $publicPath,
            'public_key_base64' => base64_encode($public),
        ];
    }
}
