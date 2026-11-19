<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

/** Verifies one named release artifact and returns authenticated claims. */
interface ReleaseArtifactVerifier
{
    /** @return array<string,mixed> */
    public function verifyArtifact(string $artifactPath, string $version, string $expectedSubjectName): array;
}
