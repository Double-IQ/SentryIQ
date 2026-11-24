import { describe, expect, it } from "vitest";
import { verifyReleaseEvidence } from "../src/release-evidence";

describe("complete release evidence gate", () => {
  it("rejects an empty or oversized ZIP before contacting GitHub", async () => {
    let called = false;
    const request: typeof fetch = async () => {
      called = true;
      return new Response(null, { status: 500 });
    };
    await expect(verifyReleaseEvidence({
      manifestBytes: new TextEncoder().encode("{}"),
      zipBytes: new Uint8Array(),
      expectedVersion: "0.1.3",
      expectedCommit: "a".repeat(40),
      trustedRootJson: "{}",
      request
    })).rejects.toThrow("ZIP is empty");
    expect(called).toBe(false);
  });

  it("rejects a missing pinned trusted root before network access", async () => {
    let called = false;
    const request: typeof fetch = async () => {
      called = true;
      return new Response(null, { status: 500 });
    };
    await expect(verifyReleaseEvidence({
      manifestBytes: new TextEncoder().encode("{}"),
      zipBytes: new Uint8Array([1]),
      expectedVersion: "0.1.3",
      expectedCommit: "a".repeat(40),
      trustedRootJson: "",
      request
    })).rejects.toThrow("trusted root");
    expect(called).toBe(false);
  });

  it("rejects a release tag that resolves to a different commit before attestation lookup", async () => {
    const commit = "a".repeat(40);
    const manifestBytes = new TextEncoder().encode(JSON.stringify({
      format: 2,
      repository: "Double-IQ/SentryIQ",
      repository_id: "1345956206",
      version: "0.1.3",
      commit,
      workflow_path: ".github/workflows/release.yml",
      public_files: ["VERSION"],
      runtime_files: ["config.php"],
      files: [
        { path: "VERSION", size: 6, sha256: "2d2454ef0edeb462a6ce8b25d387aaa74df08093d5cea0428a10ce55510c6326" },
        { path: "runtime/config.php", size: 1, sha256: "b".repeat(64) }
      ]
    }));
    const request: typeof fetch = async () => new Response(JSON.stringify({
      ref: "refs/tags/v0.1.3",
      object: { type: "commit", sha: "c".repeat(40) }
    }), { status: 200 });
    await expect(verifyReleaseEvidence({
      manifestBytes,
      zipSha256: "b".repeat(64),
      zipSize: 3,
      expectedVersion: "0.1.3",
      expectedCommit: commit,
      trustedRootJson: "{}",
      request
    })).rejects.toThrow("tag commit does not match");
  });

  it("rejects a manifest identity mismatch before contacting GitHub", async () => {
    let called = false;
    const request: typeof fetch = async () => {
      called = true;
      return new Response(null, { status: 500 });
    };
    await expect(verifyReleaseEvidence({
      manifestBytes: new TextEncoder().encode(JSON.stringify({ format: 2 })),
      zipBytes: new Uint8Array([1]),
      expectedVersion: "0.1.3",
      expectedCommit: "a".repeat(40),
      trustedRootJson: "{}",
      request
    })).rejects.toThrow("identity or schema");
    expect(called).toBe(false);
  });
});
