import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { NodeAReportSigner } from "../src/node-a-report-signer";

const commit = "a".repeat(40);
const artifact = "b".repeat(64);
const manifest = "c".repeat(64);
const nonce = "d".repeat(64);
const evidence = {
  target_origin: "https://sentryiq.bichet.co.za",
  manifest_sha256: manifest,
  checked_paths: ["VERSION", "assets/app.js", "@origin-headers", "@private-host-attestation"],
  mismatches: []
};

function signer() {
  const pair = generateKeyPairSync("ed25519");
  const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const publicDer = pair.publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const secret = Buffer.concat([privateDer.subarray(-32), publicDer.subarray(-32)]);
  return { instance: new NodeAReportSigner("integrity-a", secret.toString("base64"), () => 1_800_000_000), publicKey: pair.publicKey };
}

describe("Node A schema-v2 detached report signer", () => {
  it("signs the exact Node 4 payload and binds origin, manifest, evidence and nonce", () => {
    const { instance, publicKey } = signer();
    const envelope = JSON.parse(instance.createReport({
      releaseVersion: "v1.2.3", commit, artifactSha256: artifact, nonce,
      decision: "approve", evidence
    })) as { payload: string; signature: string };
    const payloadBytes = Buffer.from(envelope.payload, "base64");
    expect(verify(null, payloadBytes, publicKey, Buffer.from(envelope.signature, "base64"))).toBe(true);
    expect(JSON.parse(payloadBytes.toString("utf8"))).toMatchObject({
      schema_version: 2, node_id: "integrity-a", release_version: "1.2.3",
      tag: "v1.2.3", target_origin: evidence.target_origin,
      manifest_sha256: manifest, checked_paths: evidence.checked_paths, mismatches: []
    });
  });

  it("rejects a mismatched secret/public pair, unsafe paths, missing markers and inconsistent decisions", () => {
    const { instance } = signer();
    const pair = generateKeyPairSync("ed25519");
    const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
    const wrongPublic = Buffer.alloc(32, 1);
    expect(() => new NodeAReportSigner("integrity-a",
      Buffer.concat([privateDer.subarray(-32), wrongPublic]).toString("base64"))).toThrow("do not match");
    expect(() => instance.createReport({
      releaseVersion: "1.2.3", commit, artifactSha256: artifact, nonce,
      decision: "approve", evidence: { ...evidence, checked_paths: ["../VERSION", "@origin-headers", "@private-host-attestation"] }
    })).toThrow("unsafe");
    expect(() => instance.createReport({
      releaseVersion: "1.2.3", commit, artifactSha256: artifact, nonce,
      decision: "approve", evidence: { ...evidence, checked_paths: ["VERSION", "@origin-headers"] }
    })).toThrow("must include");
    expect(() => instance.createReport({
      releaseVersion: "1.2.3", commit, artifactSha256: artifact, nonce,
      decision: "approve", evidence: { ...evidence, mismatches: [{ path: "VERSION", reason: "content_mismatch" }] }
    })).toThrow("conflicts");
  });
});
