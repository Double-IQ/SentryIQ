import type { OriginIntegrityResult } from "./origin-integrity";
import { verifyCanonicalOrigin } from "./origin-integrity";
import type { VerifiedReleaseEvidence } from "./release-evidence";
import { verifyReleaseEvidence } from "./release-evidence";
import type { StagedReleaseAssets } from "./release-assets";
import type { NodeAEventRunResult, NodeAEventRunner } from "./node-a-event-runner";
import { NodeAEventAlreadyAlertedError } from "./node-a-event-runner";
import type { NodeAReleaseAssetFetcher } from "./release-assets";

const CANONICAL_ORIGIN = "https://sentryiq.bichet.co.za";

export interface NodeAReleasePinCandidate {
  readonly version: string;
  readonly commit: string;
  readonly manifestSha256: string;
  readonly zipSha256: string;
}

export interface NodeAReleaseMonitorDependencies {
  readonly fetcher: Pick<NodeAReleaseAssetFetcher, "fetchDeployedVersion" | "fetchReleaseAssets">;
  readonly refreshTuf: () => Promise<void>;
  readonly loadTrustedRoot: () => Promise<string>;
  readonly eventRunner: Pick<NodeAEventRunner, "run">;
  readonly advancePin: (candidate: NodeAReleasePinCandidate) => Promise<unknown>;
  readonly notifyOwnerDirectly: (reason: string, context: Record<string, unknown>) => void | Promise<void>;
  readonly withRunLease: <T>(operation: () => Promise<T>) => Promise<T>;
  readonly request?: typeof fetch;
  readonly apiToken?: string;
  readonly verifyRelease?: typeof verifyReleaseEvidence;
  readonly verifyOrigin?: (
    origin: string,
    manifest: VerifiedReleaseEvidence["manifest"],
    request?: typeof fetch
  ) => Promise<OriginIntegrityResult>;
}

export interface NodeAReleaseMonitorResult {
  readonly release_version: string;
  readonly release_commit: string;
  readonly release_manifest_sha256: string;
  readonly release_artifact_sha256: string;
  readonly event: NodeAEventRunResult;
  readonly pin_advanced: boolean;
}

/**
 * Scheduled Node A control-plane composition. The caller supplies the
 * Durable Object run lease, TUF refresh/trusted-root access, and atomic pin
 * writer; this class never advances a pin before all evidence and Node 4
 * acknowledgement gates have succeeded.
 */
export class NodeAReleaseMonitor {
  constructor(private readonly dependencies: NodeAReleaseMonitorDependencies) {
    if (typeof dependencies.notifyOwnerDirectly !== "function" ||
        typeof dependencies.withRunLease !== "function" ||
        typeof dependencies.refreshTuf !== "function" ||
        typeof dependencies.loadTrustedRoot !== "function" ||
        typeof dependencies.advancePin !== "function") {
      throw new Error("Node A release monitor requires run fencing, TUF state and an independent owner-alert path");
    }
  }

  async run(): Promise<NodeAReleaseMonitorResult> {
    const execution = { phase: "acquire_run_lease", version: "unknown" };
    try {
      return await this.dependencies.withRunLease(async () => {
        execution.phase = "refresh_sigstore_tuf";
        await this.dependencies.refreshTuf();

        execution.phase = "load_persisted_sigstore_trusted_root";
        const trustedRootJson = await this.dependencies.loadTrustedRoot();
        if (typeof trustedRootJson !== "string" || trustedRootJson.length < 2 ||
            trustedRootJson.length > 8_000_000) {
          throw new Error("persisted Sigstore trusted root is missing or outside its size limit");
        }

        execution.phase = "read_deployed_version";
        execution.version = await this.dependencies.fetcher.fetchDeployedVersion();

        execution.phase = "fetch_release_assets";
        const assets: StagedReleaseAssets = await this.dependencies.fetcher.fetchReleaseAssets(execution.version);
        if (assets.version !== execution.version) {
          throw new Error("release asset fetcher returned a version different from the live deployed VERSION");
        }

        execution.phase = "verify_release_manifest_zip_and_github_attestations";
        const request = this.dependencies.request ?? fetch;
        const verifyRelease = this.dependencies.verifyRelease ?? verifyReleaseEvidence;
        const release = await verifyRelease({
          manifestBytes: assets.manifestBytes,
          zipSha256: assets.zipSha256,
          zipSize: assets.zipSize,
          expectedVersion: execution.version,
          trustedRootJson,
          request,
          apiToken: this.dependencies.apiToken
        });
        if (release.manifest.version !== execution.version ||
            release.zipSha256 !== assets.zipSha256 || release.zipSize !== assets.zipSize ||
            release.manifest.commit !== release.tagCommit) {
          throw new Error("verified release evidence is not bound to the deployed version, ZIP digest and Git tag");
        }

        execution.phase = "verify_canonical_public_origin";
        const verifyOrigin = this.dependencies.verifyOrigin ?? verifyCanonicalOrigin;
        const origin = await verifyOrigin(CANONICAL_ORIGIN, release.manifest, request);

        execution.phase = "private_host_and_node4_challenge_report_exchange";
        const event = await this.dependencies.eventRunner.run({ release, origin });

        let pinAdvanced = false;
        if (event.approved) {
          execution.phase = "atomically_advance_release_pin";
          await this.dependencies.advancePin({
            version: release.manifest.version,
            commit: release.manifest.commit,
            manifestSha256: release.manifest.sha256,
            zipSha256: release.zipSha256
          });
          pinAdvanced = true;
        }
        return {
          release_version: release.manifest.version,
          release_commit: release.manifest.commit,
          release_manifest_sha256: release.manifest.sha256,
          release_artifact_sha256: release.zipSha256,
          event,
          pin_advanced: pinAdvanced
        };
      });
    } catch (error) {
      if (error instanceof NodeAEventAlreadyAlertedError) throw error;
      try {
        await this.dependencies.notifyOwnerDirectly("scheduled_integrity_run_failed", {
          node_id: "integrity-a",
          phase: execution.phase,
          ...(execution.version !== "unknown" ? { release_version: execution.version } : {}),
          exception: error instanceof Error ? error.name : "UnknownError"
        });
      } catch (alertError) {
        throw new Error("Node A scheduled run and independent owner alert both failed", { cause: alertError });
      }
      throw new Error("Node A scheduled release monitor failed after independent owner alert delivery", { cause: error });
    }
  }
}
