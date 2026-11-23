import { createHash } from "node:crypto";
import { fetchGithubReleaseAttestationBundles } from "./github-attestations";
import { resolveGithubReleaseTagCommit } from "./github-release-tag";
import { parseAndValidateReleaseManifest, type VerifiedReleaseManifest } from "./release-manifest";
import { verifyReleaseAttestationBundle, type VerifiedReleaseClaims } from "./release-attestation-policy";

const MAX_RELEASE_ZIP_BYTES = 250_000_000;

export interface VerifiedReleaseEvidence {
  readonly manifest: VerifiedReleaseManifest;
  readonly manifestClaims: VerifiedReleaseClaims;
  readonly zipClaims: VerifiedReleaseClaims;
  readonly zipSha256: string;
  readonly zipSize: number;
  readonly tagCommit: string;
}

/**
 * Verify the exact manifest and ZIP bytes, then independently verify each
 * digest's GitHub/Sigstore provenance against the supplied pinned trusted root.
 * The caller must supply bytes obtained through a separately constrained
 * release-asset transport; this function never trusts adjacent checksum files.
 */
export async function verifyReleaseEvidence(input: {
  readonly manifestBytes: Uint8Array;
  readonly zipBytes?: Uint8Array;
  readonly zipSha256?: string;
  readonly zipSize?: number;
  readonly expectedVersion: string;
  readonly expectedCommit: string;
  readonly trustedRootJson: string;
  readonly request?: typeof fetch;
  readonly apiToken?: string;
}): Promise<VerifiedReleaseEvidence> {
  let zipSha256: string;
  let zipSize: number;
  if (input.zipBytes instanceof Uint8Array) {
    zipSize = input.zipBytes.byteLength;
    if (zipSize < 1 || zipSize > MAX_RELEASE_ZIP_BYTES) {
      throw new Error("release ZIP is empty or exceeds the 250 MB verification limit");
    }
    zipSha256 = createHash("sha256").update(input.zipBytes).digest("hex");
    if (input.zipSha256 !== undefined && input.zipSha256 !== zipSha256) {
      throw new Error("streamed and in-memory release ZIP digests do not match");
    }
    if (input.zipSize !== undefined && input.zipSize !== zipSize) {
      throw new Error("streamed and in-memory release ZIP lengths do not match");
    }
  } else {
    if (typeof input.zipSha256 !== "string" || !/^[a-f0-9]{64}$/.test(input.zipSha256) ||
        !Number.isSafeInteger(input.zipSize) || (input.zipSize as number) < 1 ||
        (input.zipSize as number) > MAX_RELEASE_ZIP_BYTES) {
      throw new Error("streamed release ZIP digest or size is missing or outside its 250 MB bound");
    }
    zipSha256 = input.zipSha256;
    zipSize = input.zipSize as number;
  }
  if (typeof input.trustedRootJson !== "string" ||
      input.trustedRootJson.length < 2 || input.trustedRootJson.length > 8_000_000) {
    throw new Error("pinned Sigstore trusted root is missing or exceeds its size limit");
  }

  const manifest = parseAndValidateReleaseManifest(
    input.manifestBytes, input.expectedVersion, input.expectedCommit
  );
  const request = input.request ?? fetch;
  const tagCommit = await resolveGithubReleaseTagCommit(input.expectedVersion, request, input.apiToken);
  if (tagCommit !== input.expectedCommit) {
    throw new Error("GitHub release tag commit does not match the manifest and expected release commit");
  }

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

  return { manifest, manifestClaims, zipClaims, zipSha256, zipSize, tagCommit };
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
