import type { OriginIntegrityResult } from "./origin-integrity";
import type { VerifiedReleaseEvidence } from "./release-evidence";
import type { PrivateHostResult } from "./private-host-attestation";
import { Node4EventClient } from "./node4-event-client";
import { NodeAReportSigner } from "./node-a-report-signer";
import type { NodeAPrivateHostGate } from "./private-host-attestation";

export interface NodeAEventRunResult {
  readonly approved: boolean;
  readonly report: string;
  readonly checked_paths: readonly string[];
  readonly mismatches: readonly { path: string; reason: string }[];
  readonly manifest_sha256: string;
  readonly artifact_sha256: string;
  readonly event_acknowledgement: Record<string, unknown>;
}

/**
 * Binds release evidence, public-origin checks, private-host evidence and the
 * Node 4 challenge/report exchange. The direct alert callback is mandatory
 * and is invoked independently of Node 4 on every rejection/transport failure.
 */
export class NodeAEventRunner {
  constructor(
    private readonly node4: Node4EventClient,
    private readonly signer: NodeAReportSigner,
    private readonly privateHost: Pick<NodeAPrivateHostGate, "verify">,
    private readonly notifyOwnerDirectly: (
      reason: string,
      context: Record<string, unknown>
    ) => void | Promise<void>
  ) {
    if (typeof notifyOwnerDirectly !== "function") {
      throw new Error("Node A requires an independent direct owner-alert transport");
    }
  }

  async run(input: {
    readonly release: VerifiedReleaseEvidence;
    readonly origin: OriginIntegrityResult;
  }): Promise<NodeAEventRunResult> {
    const release = input.release;
    const manifest = release.manifest;
    if (!release || !manifest || release.tagCommit !== manifest.commit ||
        release.manifestClaims.subjectSha256 !== manifest.sha256 ||
        release.zipClaims.subjectSha256 !== release.zipSha256 ||
        release.manifestClaims.sourceCommit !== manifest.commit ||
        release.zipClaims.sourceCommit !== manifest.commit) {
      throw new Error("Node A event runner requires fully bound dual-subject release evidence");
    }
    if (!input.origin || !Array.isArray(input.origin.checkedPaths) ||
        !Array.isArray(input.origin.mismatches) ||
        !input.origin.checkedPaths.includes("@origin-headers") ||
        input.origin.approved !== (input.origin.mismatches.length === 0)) {
      throw new Error("Node A event runner received an invalid canonical-origin result");
    }

    let challenge;
    try {
      challenge = await this.node4.requestChallenge({
        targetOrigin: "https://sentryiq.bichet.co.za",
        releaseVersion: manifest.version,
        commit: manifest.commit,
        artifactSha256: release.zipSha256,
        manifestSha256: manifest.sha256
      });
    } catch (error) {
      await this.alert("node4_challenge_unavailable", manifest.version, manifest.commit, 0);
      throw new Error("Node 4 challenge failed after independent owner alert delivery", { cause: error });
    }

    let privateResult: PrivateHostResult | undefined;
    let privateHostFailed = false;
    try {
      privateResult = await this.privateHost.verify({
        nonce: challenge.nonce,
        releaseVersion: manifest.version,
        commit: manifest.commit,
        manifestSha256: manifest.sha256,
        artifactSha256: release.zipSha256,
        manifest
      });
      if (!privateResult || typeof privateResult.approved !== "boolean" ||
          !Array.isArray(privateResult.mismatches)) {
        throw new Error("private-host verifier returned an invalid result");
      }
    } catch {
      privateHostFailed = true;
    }

    const checkedPaths = [...new Set([...input.origin.checkedPaths, "@private-host-attestation"])];
    const mismatches: Array<{ path: string; reason: string }> = [];
    const mismatchPaths = new Set<string>();
    for (const item of input.origin.mismatches) {
      const reason = item.path === "@origin-headers"
        ? "security_header_mismatch"
        : item.reason;
      if (!mismatchPaths.has(item.path)) {
        mismatchPaths.add(item.path);
        mismatches.push({ path: item.path, reason });
      }
    }
    if (privateHostFailed || privateResult?.approved === false) {
      mismatches.push({
        path: "@private-host-attestation",
        reason: "private_host_attestation_failed"
      });
    }

    const decision = mismatches.length === 0 ? "approve" : "reject";
    let report: string;
    try {
      report = this.signer.createReport({
        releaseVersion: manifest.version,
        commit: manifest.commit,
        artifactSha256: release.zipSha256,
        nonce: challenge.nonce,
        decision,
        evidence: {
          target_origin: "https://sentryiq.bichet.co.za",
          manifest_sha256: manifest.sha256,
          checked_paths: checkedPaths,
          mismatches
        }
      });
    } catch (error) {
      await this.alert("report_signing_failed", manifest.version, manifest.commit, mismatches.length);
      throw new Error("Node A report signing failed after independent owner alert delivery", { cause: error });
    }

    let acknowledgement: Record<string, unknown>;
    try {
      acknowledgement = await this.node4.submitReport(report);
    } catch (error) {
      await this.alert("node4_report_delivery_failed", manifest.version, manifest.commit, mismatches.length);
      throw new Error("Node 4 report submission failed after independent owner alert delivery", { cause: error });
    }

    if (decision === "reject") {
      await this.alert("integrity_mismatch", manifest.version, manifest.commit, mismatches.length);
    }
    return {
      approved: decision === "approve",
      report,
      checked_paths: checkedPaths,
      mismatches,
      manifest_sha256: manifest.sha256,
      artifact_sha256: release.zipSha256,
      event_acknowledgement: acknowledgement
    };
  }

  private async alert(reason: string, version: string, commit: string, mismatchCount: number): Promise<void> {
    try {
      await this.notifyOwnerDirectly(reason, {
        node_id: "integrity-a",
        release_version: version,
        commit,
        mismatch_count: mismatchCount
      });
    } catch (error) {
      throw new Error("Node A independent direct owner alert delivery failed", { cause: error });
    }
  }
}
