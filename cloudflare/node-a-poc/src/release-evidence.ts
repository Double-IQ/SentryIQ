import { createHash } from "node:crypto";
import { fetchGithubReleaseAttestationBundles } from "./github-attestations";
import { parseAndValidateReleaseManifest, type VerifiedReleaseManifest } from "./release-manifest";
import { verifyReleaseAttestationBundle, type VerifiedReleaseClaims } from "./release-attestation-policy";

const MAX_RELEASE_ZIP_BYTES = 100_000_000;

export interface VerifiedReleaseEvidence {
  readonly manifest: VerifiedReleaseManifest;
  readonly manifestClaims: VerifiedReleaseClaims;
  readonly zipClaims: VerifiedReleaseClaims;
  readonly zipSha256: string;
}

/**
 * Verify the exact manifest and ZIP bytes, then independently verify each
 * digest's GitHub/Sigstore provenance against the supplied pinned trusted root.
 * The caller must supply bytes obtained through a separately constrained
 * release-asset transport; this function never trusts adjacent checksum files.
 */
export async function verifyReleaseEvidence(input: {
  readonly manifestBytes: Uint8Array;
  readonly zipBytes: Uint8Array;
  readonly expectedVersion: string;
  readonly expectedCommit: string;
  readonly trustedRootJson: string;
  readonly request?: typeof fetch;
  readonly apiToken?: string;
}): Promise<VerifiedReleaseEvidence> {
  if (!(input.zipBytes instanceof Uint8Array) || input.zipBytes.byteLength < 1 ||
      input.zipBytes.byteLength > MAX_RELEASE_ZIP_BYTES) {
    throw new Error("release ZIP is empty or exceeds the 100 MB verification limit");
  }
  if (typeof input.trustedRootJson !== "string" ||
      input.trustedRootJson.length < 2 || input.trustedRootJson.length > 8_000_000) {
    throw new Error("pinned Sigstore trusted root is missing or exceeds its size limit");
  }

  const manifest = parseAndValidateReleaseManifest(
    input.manifestBytes, input.expectedVersion, input.expectedCommit
  );
  const zipSha256 = createHash("sha256").update(input.zipBytes).digest("hex");
  const request = input.request ?? fetch;

  const [manifestBundles, zipBundles] = await Promise.all([
    fetchGithubReleaseAttestationBundles(manifest.sha256, request, input.apiToken),
    fetchGithubReleaseAttestationBundles(zipSha256, request, input.apiToken)
  ]);

  const manifestClaims = verifyAnyBundle(
    manifestBundles, input.trustedRootJson, input.expectedVersion,
    input.expectedCommit, "release-manifest.json", manifest.sha256
  );
  const zipClaims = verifyAnyBundle(
    zipBundles, input.trustedRootJson, input.expectedVersion,
    input.expectedCommit, "sentryiq-" + input.expectedVersion + ".zip", zipSha256
  );

  return { manifest, manifestClaims, zipClaims, zipSha256 };
}

function verifyAnyBundle(
  bundles: readonly string[],
  trustedRootJson: string,
  version: string,
  commit: string,
  subjectName: string,
  subjectSha256: string
): VerifiedReleaseClaims {
  let lastError: unknown;
  for (const bundle of bundles) {
    try {
      return verifyReleaseAttestationBundle(
        bundle, trustedRootJson, version, commit, subjectName, subjectSha256
      );
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(
    "no GitHub attestation bundle passed the exact " + subjectName + " release policy",
    lastError instanceof Error ? { cause: lastError } : undefined
  );
}
