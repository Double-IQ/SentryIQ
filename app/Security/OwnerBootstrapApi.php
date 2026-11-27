<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;

/**
 * Authenticated bootstrap API service. The app host relays signed public state;
 * trust is established only by independently pinned registry/bundle signers and
 * the native phone's verification of the same bytes.
 */
final class OwnerBootstrapApi
{
    private readonly OwnerApprovalProofVerifier $proofVerifier;
    private readonly string $canonicalBundle;

    /**
     * @param list<array{kid:string,role:string,alg:string,public_key_pem:string}> $registrySignerKeys
     * @param list<array{kid:string,role:string,alg:string,public_key_pem:string}> $bundleSignerKeys
     * @param callable(array<string,mixed>):bool $verifyTuf
     */
    public function __construct(
        private readonly BootstrapChallengeStore $challenges,
        private readonly string $privateDirectory,
        private readonly TrustBundleValidator $bundleValidator,
        private readonly RegistryAnchorVerifier $registryAnchorVerifier,
        private readonly string $ownerId,
        private readonly string $bundleJson,
        private readonly string $registryAnchorPayload,
        private readonly string $registryAnchorSignatureBase64Url,
        private readonly array $registrySignerKeys,
        private readonly array $bundleSignerKeys,
        private readonly ?string $currentSequence,
        private readonly ?string $currentBundleDigest,
        private readonly mixed $verifyTuf
    ) {
        if (!is_callable($verifyTuf) || !preg_match('/^[A-Za-z0-9._:-]{1,256}$/D', $ownerId)) {
            throw new RuntimeException('Bootstrap owner binding or TUF verifier is unavailable.');
        }
        $initial = $this->bundleValidator->validate(
            $this->bundleJson,
            $this->bundleSignerKeys,
            $this->ownerId,
            $this->currentBundleDigest,
            $this->currentSequence
        );
        $this->canonicalBundle = $initial['canonical_bundle'];
        $this->proofVerifier = $this->makeProofVerifier();
    }

    /** Return only state that has passed signed-anchor, bundle, and TUF validation. */
    public function snapshot(int $now): array
    {
        $signature = self::decodeBase64Url($this->registryAnchorSignatureBase64Url);
        $anchor = $this->registryAnchorVerifier->verify(
            $this->registryAnchorPayload,
            $signature,
            $this->registrySignerKeys,
            $this->ownerId,
            $this->currentSequence,
            $this->currentBundleDigest,
            $now
        );

        $validated = $this->bundleValidator->validate(
            $this->bundleJson,
            $this->bundleSignerKeys,
            $this->ownerId,
            $this->currentBundleDigest,
            $this->currentSequence,
            $now
        );
        if ($validated['sequence'] !== $anchor['sequence']
            || !hash_equals($validated['digest'], $anchor['bundle_sha256'])
            || !hash_equals($validated['digest'], hash('sha256', $validated['canonical_bundle']))
            || !hash_equals($this->ownerId, $anchor['owner_id'])
            || !(($this->verifyTuf)($validated['bundle']))) {
            throw new RuntimeException('Signed registry anchor, trust bundle, and TUF state do not agree.');
        }

        return [
            'owner_id' => $this->ownerId,
            'sequence' => $validated['sequence'],
            'bundle_sha256' => $validated['digest'],
            'canonical_bundle' => $validated['canonical_bundle'],
            'registry_anchor_payload' => $this->registryAnchorPayload,
            'registry_anchor_signature' => $signature,
            'validated_bundle' => $validated['bundle'],
            'master_keyset_digest' => $validated['master_keyset_digest'],
            'key_fingerprints' => $validated['key_fingerprints'],
        ];
    }

    public function issueChallenge(int $now, int $ttlSeconds = 300): array
    {
        $snapshot = $this->snapshot($now);
        $challenge = $this->challenges->issue(
            $this->ownerId,
            $snapshot['bundle_sha256'],
            $now,
            $ttlSeconds
        );
        return [
            'challenge' => $challenge,
            'purpose' => 'owner-bootstrap-approval',
            'bundle_sha256' => $snapshot['bundle_sha256'],
            'expires_at' => $now + $ttlSeconds,
        ];
    }

    /**
     * @param array{challenge:string,bundle_sha256:string,root_role:string,root_key_id:string,root_fingerprint:string,device_keyset_digest:string,purpose:string,signature:string} $proof
     * @return array{receipt_id:string}
     */
    public function approve(array $proof, int $now): array
    {
        // The proof verifier consumes the challenge before any context/TUF/anchor revalidation.
        $receipt = $this->proofVerifier->verifyAndRecord(
            $proof['challenge'] ?? '',
            $this->ownerId,
            $this->canonicalBundle,
            $proof['bundle_sha256'] ?? '',
            $proof['root_role'] ?? '',
            $proof['root_key_id'] ?? '',
            $proof['root_fingerprint'] ?? '',
            $proof['device_keyset_digest'] ?? '',
            $proof['purpose'] ?? '',
            $proof['signature'] ?? '',
            $now
        );
        return ['receipt_id' => $receipt['receipt_id']];
    }

    private function makeProofVerifier(): OwnerApprovalProofVerifier
    {
        $resolveOwnerKey = function (string $ownerId): array {
            if (!hash_equals($this->ownerId, $ownerId)) return [];
            $snapshot = $this->snapshot(time());
            $signing = $snapshot['validated_bundle']['master_keyset']['signing'] ?? null;
            if (!is_array($signing)) return [];
            return [
                'owner_id' => $this->ownerId,
                'key_id' => $signing['kid'] ?? '',
                'role' => 'master-signing',
                'algorithm' => $signing['alg'] ?? '',
                'status' => 'active',
                'device_keyset_digest' => $snapshot['master_keyset_digest'],
                'public_key_pem' => $signing['public_key_pem'] ?? '',
            ];
        };

        $validateContext = function (
            string $canonicalBundle,
            string $rootRole,
            string $rootKeyId,
            string $rootFingerprint,
            string $deviceKeysetDigest,
            string $purpose
        ): bool {
            $snapshot = $this->snapshot(time());
            if (!hash_equals($snapshot['canonical_bundle'], $canonicalBundle)
                || !hash_equals($snapshot['master_keyset_digest'], $deviceKeysetDigest)
                || $rootRole !== 'release-authorisation'
                || $purpose !== 'bootstrap-release-root'
                || !isset($snapshot['key_fingerprints'][$rootKeyId])
                || !hash_equals($snapshot['key_fingerprints'][$rootKeyId], strtolower($rootFingerprint))) {
                return false;
            }
            $releaseKeys = $snapshot['validated_bundle']['release_authorisation']['keys'] ?? [];
            foreach ($releaseKeys as $key) {
                if (($key['kid'] ?? null) === $rootKeyId
                    && ($key['purpose'] ?? null) === 'release-authorisation') {
                    return (bool)(($this->verifyTuf)($snapshot['validated_bundle']));
                }
            }
            return false;
        };

        return new OwnerApprovalProofVerifier(
            $this->challenges,
            $this->privateDirectory,
            $resolveOwnerKey,
            $validateContext
        );
    }

    private static function decodeBase64Url(string $value): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]+$/D', $value)) {
            throw new RuntimeException('Registry anchor signature encoding is malformed.');
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (!is_string($decoded) || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $value) {
            throw new RuntimeException('Registry anchor signature encoding is invalid.');
        }
        return $decoded;
    }
}
