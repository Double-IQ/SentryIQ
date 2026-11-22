import { env } from "cloudflare:test";
import { exports as workerExports } from "cloudflare:workers";
import { bundleFromJSON } from "@sigstore/bundle";
import { crypto as sigstoreCrypto, json as sigstoreJson } from "@sigstore/core";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import * as bundles from "./fixtures/bundles";
import { trustedRoot } from "./fixtures/trust";
import { genuineV012BundleJson } from "./fixtures/genuine-v012-bundle";
import { genuineV012TrustedRootJson } from "./fixtures/genuine-v012-trusted-root";
import { tufRootBase64 } from "./fixtures/tuf-root";
import { describe, expect, it } from "vitest";

async function expectRemoteRejection(promise: Promise<unknown>, message: string): Promise<void> {
  let caught = false;
  try {
    await promise;
  } catch (error) {
    caught = true;
    expect(String(error)).toContain(message);
  }
  expect(caught).toBe(true);
}

const candidate = (version: string, suffix = "a") => ({
  version,
  commit: suffix.repeat(40),
  manifestSha256: "b".repeat(64),
  zipSha256: "c".repeat(64)
});

describe("Node A Workers runtime proof", () => {
  it("loads the Sigstore verifier and TUF client in workerd and executes Ed25519 crypto", async () => {
    const response = await workerExports.default.fetch(new Request("https://node-a-poc.test/runtime-check"), env, {} as ExecutionContext);
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body.cryptoOk).toBe(true);
    expect(body.sigstoreVerifierLoaded).toBe(true);
    expect(body.tufClientLoaded).toBe(true);
    expect(body.tufNetworkOrCacheInitialized).toBe(false);
    expect(body.productionReady).toBe(false);
  });

  it("cryptographically verifies the genuine SentryIQ v0.1.2 release attestation in workerd", () => {
    if (genuineV012BundleJson === null || genuineV012TrustedRootJson === null) {
      throw new Error("CI must inject the genuine GitHub attestation bundle and current Sigstore trusted root before running this suite");
    }
    const bundle = bundleFromJSON(JSON.parse(genuineV012BundleJson));
    const currentTrustedRoot = TrustedRoot.fromJSON(JSON.parse(genuineV012TrustedRootJson));
    const trustMaterial = toTrustMaterial(currentTrustedRoot);
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const tlogAuthority = trustMaterial.tlogs.find((item) => item.logID.equals(tlogEntry.logId.keyId));
    expect(tlogAuthority, "trusted Rekor log key must be present in the current trusted root").toBeDefined();
    const setPayload = {
      body: tlogEntry.canonicalizedBody.toString("base64"),
      integratedTime: Number(tlogEntry.integratedTime),
      logIndex: Number(tlogEntry.logIndex),
      logID: tlogEntry.logId.keyId.toString("hex")
    };
    const setBytes = Buffer.from(sigstoreJson.canonicalize(setPayload), "utf8");
    const setSignature = Buffer.from(tlogEntry.inclusionPromise!.signedEntryTimestamp);
    // Protobuf bytes are Uint8Array in the Workers runtime; Buffer is only one Node subclass.
    expect(tlogEntry.inclusionPromise!.signedEntryTimestamp, "protobuf SET signature bytes must be Uint8Array in workerd").toBeInstanceOf(Uint8Array);
    expect(tlogEntry.inclusionPromise!.signedEntryTimestamp.byteLength, "protobuf SET signature must not be empty").toBeGreaterThan(0);
    expect(sigstoreCrypto.digest("sha256", setBytes).toString("hex")).toBe("afdc764f3952ff786981b31cb5112741eecf747663d48bbcd9e90ebb2a8d346e");
    const selfTestKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const selfTestSignature = sign("sha256", setBytes, selfTestKey.privateKey);
    expect(verify("sha256", setBytes, selfTestKey.publicKey, selfTestSignature), "workerd Node crypto self-test signature must verify").toBe(true);
    const trustedKeyBytes = Buffer.from(currentTrustedRoot.tlogs[0].publicKey.rawBytes);
    const exportedKeyBytes = Buffer.from(tlogAuthority!.publicKey.export({ type: "spki", format: "der" }));
    expect(exportedKeyBytes.equals(trustedKeyBytes), "selected Rekor authority key must match trusted-root key bytes").toBe(true);
    expect(verify("sha256", setBytes, tlogAuthority!.publicKey, setSignature), "Node crypto must verify the genuine Rekor SET signature").toBe(true);
    const sigstoreKey = tlogAuthority!.publicKey;
    console.info("SIGSTORE_CRYPTO_DIAGNOSTIC", JSON.stringify({
      asymmetricKeyType: (sigstoreKey as { asymmetricKeyType?: string }).asymmetricKeyType ?? null,
      keyConstructor: Object.getPrototypeOf(sigstoreKey)?.constructor?.name ?? null,
      nodeKeyObjectInstance: sigstoreKey instanceof (createPublicKey(Buffer.from(currentTrustedRoot.tlogs[0].publicKey.rawBytes)).constructor as typeof sigstoreKey.constructor),
      explicitSha256Verify: sigstoreCrypto.verify(setBytes, sigstoreKey, setSignature, "sha256"),
      defaultVerify: sigstoreCrypto.verify(setBytes, sigstoreKey, setSignature)
    }));
    expect(sigstoreCrypto.verify(setBytes, sigstoreKey, setSignature), "Sigstore crypto must verify the genuine Rekor SET signature").toBe(true);

    const verifier = new Verifier(trustMaterial, {
      ctlogThreshold: 1,
      tlogThreshold: 1,
      timestampThreshold: 1
    });
    const signer = verifier.verify(toSignedEntity(bundle));
    const statement = JSON.parse(Buffer.from(bundle.content.dsseEnvelope.payload).toString("utf8")) as {
      predicateType?: string;
      subject?: Array<{ name?: string; digest?: { sha256?: string } }>;
      predicate?: {
        buildDefinition?: {
          externalParameters?: { workflow?: { repository?: string; ref?: string; path?: string } };
          resolvedDependencies?: Array<{ digest?: { gitCommit?: string } }>;
        };
      };
    };

    expect(signer.identity?.subjectAlternativeName).toBe(
      "https://github.com/Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v0.1.2"
    );
    expect(statement.predicateType).toBe("https://slsa.dev/provenance/v1");
    expect(statement.subject).toContainEqual({
      name: "sentryiq-0.1.2.zip",
      digest: { sha256: "41cc5fc46055836ebb21ed4501bd6bd3ace249c4f352da0373b85e5a57d9c49e" }
    });
    expect(statement.predicate?.buildDefinition?.externalParameters?.workflow).toEqual({
      repository: "https://github.com/Double-IQ/SentryIQ",
      ref: "refs/tags/v0.1.2",
      path: ".github/workflows/release.yml"
    });
    expect(statement.predicate?.buildDefinition?.resolvedDependencies?.[0]?.digest?.gitCommit)
      .toBe("9c639a4792cadd5421f01ed198ba2a9261c5145f");
  });

  it("verifies an upstream Sigstore Rekor v2 certificate bundle in workerd", () => {
    const bundle = bundleFromJSON(bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002);
    const verifier = new Verifier(toTrustMaterial(trustedRoot), {
      ctlogThreshold: 1,
      tlogThreshold: 1,
      timestampThreshold: 1
    });
    expect(() => verifier.verify(toSignedEntity(bundle, bundles.ARTIFACT))).not.toThrow();
  });

  it("bootstraps the upstream Sigstore TUF cache through Durable Object SQLite", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-upstream-tuf-bootstrap-test");
    const stub = env.NODE_A_STATE.get(id);
    const result = await stub.testUpstreamTufEphemeralCache(tufRootBase64);
    expect(result.rootVersion).toBeGreaterThan(0);
    expect(result.ephemeralCacheBootstrapped).toBe(true);
    expect(result.persistentCacheRejected).toBe(true);
    expect(result.expectedNetworkFailure).toBe(true);
  });

  it("uses Durable Object SQLite for persistent TUF files and request-local temporary files", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-tuf-fs-adapter-test");
    const first = env.NODE_A_STATE.get(id);
    const result = await first.testTufFilesystemAdapter();
    expect(result).toEqual({
      persistentRead: "persistent-root-fixture",
      copiedRead: "persistent-root-fixture",
      temporaryRead: "request-scoped-target",
      temporaryExistsAfterCleanup: false,
      stagedWriteVisibleBeforeCommit: true,
      discardedWriteAbsentAfterRollback: true
    });

    const second = env.NODE_A_STATE.get(id);
    const contextCheck = await second.testTufFilesystemAdapter();
    expect(contextCheck.persistentRead).toBe("persistent-root-fixture");
  });

  it("requires an explicit immutable baseline before any release pin can advance", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-baseline-test");
    const stub = env.NODE_A_STATE.get(id);
    const lock = await stub.acquireRunLock(60_000);
    await expectRemoteRejection(stub.advancePin(candidate("1.0.0"), lock.token), "independent release baseline has not been initialized");
    await stub.initializeBaseline(candidate("1.0.0"));
    await expectRemoteRejection(stub.initializeBaseline(candidate("1.0.1", "d")), "independently initialized baseline is immutable");
    expect((await stub.getPin())?.version).toBe("1.0.0");
  });

  it("persists the release pin across separate Durable Object stubs", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-persistence-test");
    const first = env.NODE_A_STATE.get(id);
    const saved = await first.initializeBaseline(candidate("1.2.3"));
    expect(saved.version).toBe("1.2.3");

    const second = env.NODE_A_STATE.get(id);
    expect(await second.getPin()).toEqual(saved);
  });

  it("rejects downgrade and same-version replacement without mutating the pin", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-rollback-test");
    const stub = env.NODE_A_STATE.get(id);
    await stub.initializeBaseline(candidate("1.0.0"));
    const lock = await stub.acquireRunLock(60_000);
    const original = await stub.advancePin(candidate("2.0.0"), lock.token);

    await expectRemoteRejection(stub.advancePin(candidate("1.9.9", "d"), lock.token), "release rollback rejected");
    await expectRemoteRejection(stub.advancePin({ ...candidate("2.0.0"), zipSha256: "e".repeat(64) }, lock.token), "same-version release identity or digest replacement rejected");
    expect(await stub.getPin()).toEqual(original);
  });

  it("will not advance a pin without a valid active run lock", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-lock-required-test");
    const stub = env.NODE_A_STATE.get(id);
    await stub.initializeBaseline(candidate("1.0.0"));
    await expectRemoteRejection(stub.advancePin(candidate("1.1.0"), "a".repeat(64)), "valid active Node A run lock required");
    expect((await stub.getPin())?.version).toBe("1.0.0");
  });

  it("treats an exact same-version pin as idempotent", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-idempotent-test");
    const stub = env.NODE_A_STATE.get(id);
    const first = await stub.initializeBaseline(candidate("3.0.0"));
    const lock = await stub.acquireRunLock(60_000);
    const second = await stub.advancePin(candidate("3.0.0"), lock.token);
    expect(second).toEqual(first);
  });

  it("serializes runs with a durable lease and token-bound release", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-lock-test");
    const stub = env.NODE_A_STATE.get(id);
    const lock = await stub.acquireRunLock(60_000);
    await expectRemoteRejection(stub.acquireRunLock(60_000), "Node A run already holds the durable lock");
    await expectRemoteRejection(stub.releaseRunLock("b".repeat(64)), "run lock token mismatch");
    await stub.releaseRunLock(lock.token);
    const next = await stub.acquireRunLock(60_000);
    expect(next.token).toMatch(/^[a-f0-9]{64}$/);
    expect(next.token).not.toBe(lock.token);
  });
});
