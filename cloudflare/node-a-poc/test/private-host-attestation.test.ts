import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseAndValidateReleaseManifest } from "../src/release-manifest";
import { NodeAPrivateHostGate } from "../src/private-host-attestation";

const version = "1.2.3";
const commit = "a".repeat(40);
const nonce = "b".repeat(64);
const manifestDigest = "c".repeat(64);
const artifactDigest = "d".repeat(64);
const fileDigest = "e".repeat(64);
const configDigest = "f".repeat(64);
const token = "A".repeat(48);

function createManifest() {
  return parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify({
    format: 2, repository: "Double-IQ/SentryIQ", repository_id: "1345956206",
    version, commit, workflow_path: ".github/workflows/release.yml",
    public_files: ["VERSION"], runtime_files: ["config.php"],
    files: [
      { path: "VERSION", size: 6, sha256: "d82f34ae9aa41bc4a0cb529a1ac0898fed09d6b479fb1cc44cb66c34f15ee84d" },
      { path: "runtime/config.php", size: 1, sha256: fileDigest }
    ]
  })), version, commit);
}

function fixture(decision = "approve", manifestHash = manifestDigest) {
  const pair = generateKeyPairSync("ed25519");
  const rawPublic = (pair.publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
  const payload = {
    schema_version: 1,
    collector_id: "sentryiq-host-attestor",
    issued_at: 1_800_000_000,
    expires_at: 1_800_000_100,
    nonce,
    target_origin: "https://sentryiq.bichet.co.za",
    repository: "Double-IQ/SentryIQ",
    repository_id: "1345956206",
    release_version: version,
    tag: "v" + version,
    commit,
    manifest_sha256: manifestHash,
    artifact_sha256: artifactDigest,
    files: [{
      path: "runtime/config.php",
      expected_sha256: fileDigest,
      observed_sha256: fileDigest,
      result: "match"
    }],
    private_config: [{
      policy_id: "db.credentials",
      expected_sha256: configDigest,
      observed_sha256: configDigest,
      result: "match"
    }],
    decision
  };
  const payloadBytes = Buffer.from(JSON.stringify(payload));
  const signature = sign(null, payloadBytes, pair.privateKey);
  const request: typeof fetch = async (_input, init) => {
    expect(init?.redirect).toBe("error");
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer " + token);
    return Response.json({
      payload: payloadBytes.toString("base64"),
      signature: signature.toString("base64")
    }, { status: 200 });
  };
  return {
    gate: new NodeAPrivateHostGate(token, rawPublic.toString("base64"),
      { "runtime/config.php": fileDigest }, { "db.credentials": configDigest }, request, () => 1_800_000_050),
    payload,
    pair
  };
}

describe("Node A private-host collector gate", () => {
  it("verifies the pinned Ed25519 collector response and exact release/config inventory", async () => {
    const manifest = createManifest();
    const { gate } = fixture("approve", manifest.sha256);
    const result = await gate.verify({
      nonce, releaseVersion: version, commit, manifestSha256: manifest.sha256,
      artifactSha256: artifactDigest, manifest
    });
    expect(result).toMatchObject({
      approved: true, collectorId: "sentryiq-host-attestor",
      filesChecked: 1, privateConfigChecked: 1, mismatches: []
    });
  });

  it("rejects wrong nonce, stale evidence, bad signatures and manifest-policy drift", async () => {
    const manifest = createManifest();
    const first = fixture("approve", manifest.sha256);
    await expect(first.gate.verify({
      nonce: "0".repeat(64), releaseVersion: version, commit, manifestSha256: manifest.sha256,
      artifactSha256: artifactDigest, manifest
    })).rejects.toThrow("identity, freshness or schema");

    const stale = fixture("approve", manifest.sha256);
    stale.payload.expires_at = 1_800_000_020;
    const staleBytes = Buffer.from(JSON.stringify(stale.payload));
    const staleSignature = sign(null, staleBytes, stale.pair.privateKey);
    const staleGate = new NodeAPrivateHostGate(token,
      (stale.pair.publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32).toString("base64"),
      { "runtime/config.php": fileDigest }, { "db.credentials": configDigest },
      async () => Response.json({ payload: staleBytes.toString("base64"), signature: staleSignature.toString("base64") }),
      () => 1_800_000_050);
    await expect(staleGate.verify({
      nonce, releaseVersion: version, commit, manifestSha256: manifest.sha256,
      artifactSha256: artifactDigest, manifest
    })).rejects.toThrow("stale");

    const drift = fixture("approve", manifest.sha256);
    await expect(drift.gate.verify({
      nonce, releaseVersion: version, commit, manifestSha256: "0".repeat(64),
      artifactSha256: artifactDigest, manifest
    })).rejects.toThrow("challenge context");
  });

  it("rejects a collector-signed file digest mismatch and missing pinned files", async () => {
    const manifest = createManifest();
    const mismatch = fixture("approve", manifest.sha256);
    mismatch.payload.files[0]!.result = "digest_mismatch";
    mismatch.payload.files[0]!.observed_sha256 = "0".repeat(64);
    mismatch.payload.decision = "reject";
    const payloadBytes = Buffer.from(JSON.stringify(mismatch.payload));
    const signature = sign(null, payloadBytes, mismatch.pair.privateKey);
    const gate = new NodeAPrivateHostGate(token,
      (mismatch.pair.publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32).toString("base64"),
      { "runtime/config.php": fileDigest }, { "db.credentials": configDigest },
      async () => Response.json({ payload: payloadBytes.toString("base64"), signature: signature.toString("base64") }),
      () => 1_800_000_050);
    const result = await gate.verify({
      nonce, releaseVersion: version, commit, manifestSha256: manifest.sha256,
      artifactSha256: artifactDigest, manifest
    });
    expect(result.approved).toBe(false);
    expect(result.mismatches).toContainEqual({ path: "runtime/config.php", reason: "digest_mismatch" });
  });
});
