import { describe, expect, it } from "vitest";
import { NodeAEventAlreadyAlertedError } from "../src/node-a-event-runner";
import { NodeAReleaseMonitor } from "../src/node-a-release-monitor";
import type { VerifiedReleaseEvidence } from "../src/release-evidence";

const commit = "a".repeat(40);
const manifestSha = "b".repeat(64);
const zipSha = "c".repeat(64);
const manifest = {
  format: 2 as const, repository: "Double-IQ/SentryIQ" as const, repository_id: "1345956206" as const,
  version: "1.2.3", commit, workflow_path: ".github/workflows/release.yml" as const,
  public_files: ["VERSION"], runtime_files: ["config.php"],
  files: [], publicHttpFiles: [], sha256: manifestSha
};
const claims = {
  repository: "Double-IQ/SentryIQ" as const, repositoryId: "1345956206" as const,
  version: "1.2.3", sourceCommit: commit, workflowCommit: commit,
  subjectName: "release-manifest.json", subjectSha256: manifestSha
};
const release = {
  manifest,
  manifestClaims: claims,
  zipClaims: { ...claims, subjectName: "sentryiq-1.2.3.zip", subjectSha256: zipSha },
  zipSha256: zipSha,
  zipSize: 3,
  tagCommit: commit
} as VerifiedReleaseEvidence;
const assets = { version: "1.2.3", manifestBytes: new Uint8Array([1]), zipSha256: zipSha, zipSize: 3 };

function dependencies(overrides: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const alerts: Array<[string, Record<string, unknown>]> = [];
  const pins: unknown[] = [];
  const deps = {
    fetcher: {
      fetchDeployedVersion: async () => { calls.push("version"); return "1.2.3"; },
      fetchReleaseAssets: async () => { calls.push("assets"); return assets; }
    },
    refreshTuf: async () => { calls.push("tuf"); },
    loadTrustedRoot: async () => { calls.push("root"); return "{}"; },
    eventRunner: {
      run: async () => {
        calls.push("event");
        return {
          approved: true, report: "signed", checked_paths: ["VERSION"],
          mismatches: [], manifest_sha256: manifestSha, artifact_sha256: zipSha,
          event_acknowledgement: { status: "accepted" }
        };
      }
    },
    advancePin: async (candidate: unknown) => { calls.push("pin"); pins.push(candidate); },
    notifyOwnerDirectly: async (reason: string, context: Record<string, unknown>) => { alerts.push([reason, context]); },
    withRunLease: async <T>(operation: () => Promise<T>) => { calls.push("lease"); return operation(); },
    verifyRelease: async () => { calls.push("attest"); return release; },
    verifyOrigin: async () => { calls.push("origin"); return { approved: true, checkedPaths: ["VERSION", "@origin-headers"], mismatches: [], headerMismatches: [] }; },
    request: fetch
  };
  return { deps: { ...deps, ...overrides } as ConstructorParameters<typeof NodeAReleaseMonitor>[0], calls, alerts, pins };
}

describe("Node A scheduled release monitor composition", () => {
  it("refreshes TUF, verifies both release subjects and origin, exchanges Node 4 report, then advances pin", async () => {
    const f = dependencies();
    const monitor = new NodeAReleaseMonitor(f.deps);
    const result = await monitor.run();
    expect(result).toMatchObject({
      release_version: "1.2.3", release_commit: commit,
      release_manifest_sha256: manifestSha, release_artifact_sha256: zipSha,
      pin_advanced: true, event: { approved: true }
    });
    expect(f.calls).toEqual(["lease", "tuf", "root", "version", "assets", "attest", "origin", "event", "pin"]);
    expect(f.pins).toEqual([{
      version: "1.2.3", commit, manifestSha256: manifestSha, zipSha256: zipSha
    }]);
    expect(f.alerts).toHaveLength(0);
  });

  it("does not advance the pin after a signed Node 4 rejection", async () => {
    const f = dependencies({
      eventRunner: {
        run: async () => ({
          approved: false, report: "signed-rejection", checked_paths: ["VERSION"],
          mismatches: [{ path: "VERSION", reason: "content_mismatch" }],
          manifest_sha256: manifestSha, artifact_sha256: zipSha,
          event_acknowledgement: { status: "accepted" }
        })
      }
    });
    const monitor = new NodeAReleaseMonitor(f.deps);
    const result = await monitor.run();
    expect(result.pin_advanced).toBe(false);
    expect(f.pins).toHaveLength(0);
  });

  it("directly alerts on pre-event failures and does not duplicate an event-runner alert", async () => {
    const failed = dependencies({ refreshTuf: async () => { throw new Error("TUF unavailable"); } });
    await expect(new NodeAReleaseMonitor(failed.deps).run()).rejects.toThrow("after independent owner alert");
    expect(failed.alerts).toEqual([["scheduled_integrity_run_failed", {
      node_id: "integrity-a", phase: "refresh_sigstore_tuf",
      release_version: "unknown", exception: "Error"
    }]]);

    const alreadyAlerted = dependencies({
      eventRunner: { run: async () => { throw new NodeAEventAlreadyAlertedError("direct alert attempted"); } }
    });
    await expect(new NodeAReleaseMonitor(alreadyAlerted.deps).run()).rejects.toThrow("direct alert attempted");
    expect(alreadyAlerted.alerts).toHaveLength(0);
  });

  it("alerts and preserves the old pin if the atomic pin write fails", async () => {
    const f = dependencies({ advancePin: async () => { throw new Error("pin CAS rejected"); } });
    await expect(new NodeAReleaseMonitor(f.deps).run()).rejects.toThrow("after independent owner alert");
    expect(f.alerts[0]?.[1]).toMatchObject({ phase: "atomically_advance_release_pin", release_version: "1.2.3" });
  });
});
