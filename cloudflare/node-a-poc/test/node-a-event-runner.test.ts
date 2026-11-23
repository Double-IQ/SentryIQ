import { Buffer } from "node:buffer";
import { generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Node4EventClient } from "../src/node4-event-client";
import { NodeAReportSigner } from "../src/node-a-report-signer";
import { NodeAEventRunner } from "../src/node-a-event-runner";
import { parseAndValidateReleaseManifest } from "../src/release-manifest";
import type { VerifiedReleaseEvidence } from "../src/release-evidence";

const token = "A".repeat(48);
const commit = "a".repeat(40);
const zipSha = "b".repeat(64);

function fixtures() {
  const manifest = parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify({
    format: 2, repository: "Double-IQ/SentryIQ", repository_id: "1345956206",
    version: "1.2.3", commit, workflow_path: ".github/workflows/release.yml",
    public_files: ["VERSION"], runtime_files: ["config.php"],
    files: [
      { path: "VERSION", size: 6, sha256: "d82f34ae9aa41bc4a0cb529a1ac0898fed09d6b479fb1cc44cb66c34f15ee84d" },
      { path: "runtime/config.php", size: 1, sha256: "e".repeat(64) }
    ]
  })), "1.2.3", commit);
  const claims = {
    repository: "Double-IQ/SentryIQ" as const,
    repositoryId: "1345956206" as const,
    version: "1.2.3",
    sourceCommit: commit,
    workflowCommit: commit,
    subjectName: "release-manifest.json",
    subjectSha256: manifest.sha256
  };
  const release = {
    manifest,
    manifestClaims: claims,
    zipClaims: { ...claims, subjectName: "sentryiq-1.2.3.zip", subjectSha256: zipSha },
    zipSha256: zipSha,
    tagCommit: commit
  } as VerifiedReleaseEvidence;
  const pair = generateKeyPairSync("ed25519");
  const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const publicDer = pair.publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const secret = Buffer.concat([privateDer.subarray(-32), publicDer.subarray(-32)]);
  const signer = new NodeAReportSigner("integrity-a", secret.toString("base64"), () => 1_800_000_000);
  const calls: Array<Record<string, unknown>> = [];
  const request: typeof fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push(body);
    if (body.action === "challenge") {
      return Response.json({ status: "ok", node_id: "integrity-a", nonce: "c".repeat(64), expires_at: 1_800_000_300 }, { status: 201 });
    }
    return Response.json({ status: "accepted", report_id: "node4-report-1" }, { status: 202 });
  };
  const node4 = new Node4EventClient(token, request, () => 1_800_000_000);
  return { release, signer, node4, calls, publicKey: pair.publicKey };
}

describe("Node A end-to-end event runner", () => {
  it("binds release, origin, private host and Node 4 acknowledgement in one signed report", async () => {
    const f = fixtures();
    const alerts: Array<[string, Record<string, unknown>]> = [];
    const privateHost = { verify: async () => ({
      approved: true, collectorId: "sentryiq-host-attestor" as const,
      issuedAt: 1_800_000_000, expiresAt: 1_800_000_100,
      filesChecked: 1, privateConfigChecked: 1, mismatches: []
    }) };
    const runner = new NodeAEventRunner(f.node4, f.signer, privateHost,
      async (reason, context) => { alerts.push([reason, context]); });
    const result = await runner.run({
      release: f.release,
      origin: { approved: true, checkedPaths: ["VERSION", "@origin-headers"], mismatches: [], headerMismatches: [] }
    });
    expect(result.approved).toBe(true);
    expect(result.event_acknowledgement).toMatchObject({ status: "accepted", report_id: "node4-report-1" });
    expect(alerts).toHaveLength(0);
    expect(f.calls).toHaveLength(2);
    const report = JSON.parse(String(f.calls[1]!.envelope)) as { payload: string; signature: string };
    const payloadBytes = Buffer.from(report.payload, "base64");
    expect(verify(null, payloadBytes, f.publicKey, Buffer.from(report.signature, "base64"))).toBe(true);
    expect(JSON.parse(payloadBytes.toString("utf8"))).toMatchObject({
      node_id: "integrity-a", decision: "approve", nonce: "c".repeat(64),
      manifest_sha256: f.release.manifest.sha256, artifact_sha256: zipSha,
      checked_paths: ["VERSION", "@origin-headers", "@private-host-attestation"]
    });
  });

  it("sends a signed rejection and independently alerts on origin/private-host mismatch", async () => {
    const f = fixtures();
    const alerts: string[] = [];
    const runner = new NodeAEventRunner(f.node4, f.signer, {
      verify: async () => ({
        approved: false, collectorId: "sentryiq-host-attestor" as const,
        issuedAt: 1_800_000_000, expiresAt: 1_800_000_100,
        filesChecked: 1, privateConfigChecked: 1,
        mismatches: [{ path: "runtime/config.php", reason: "digest_mismatch" }]
      })
    }, async (reason) => { alerts.push(reason); });
    const result = await runner.run({
      release: f.release,
      origin: {
        approved: false, checkedPaths: ["VERSION", "@origin-headers"],
        mismatches: [
          { path: "VERSION", reason: "content_mismatch" },
          { path: "@origin-headers", reason: "security_header_mismatch:hsts" },
          { path: "@origin-headers", reason: "security_header_mismatch:csp" }
        ],
        headerMismatches: ["hsts", "csp"]
      }
    });
    expect(result.approved).toBe(false);
    expect(result.mismatches).toEqual([
      { path: "VERSION", reason: "content_mismatch" },
      { path: "@origin-headers", reason: "security_header_mismatch" },
      { path: "@private-host-attestation", reason: "private_host_attestation_failed" }
    ]);
    expect(alerts).toEqual(["integrity_mismatch"]);
  });

  it("alerts directly when Node 4 challenge is unavailable", async () => {
    const f = fixtures();
    const alerts: string[] = [];
    const node4 = new Node4EventClient(token, async () => new Response(null, { status: 503 }));
    const runner = new NodeAEventRunner(node4, f.signer,
      { verify: async () => { throw new Error("should not run"); } },
      async (reason) => { alerts.push(reason); });
    await expect(runner.run({
      release: f.release,
      origin: { approved: true, checkedPaths: ["VERSION", "@origin-headers"], mismatches: [], headerMismatches: [] }
    })).rejects.toThrow("challenge failed");
    expect(alerts).toEqual(["node4_challenge_unavailable"]);
  });
});
