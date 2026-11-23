import { env } from "cloudflare:test";
import { exports as workerExports } from "cloudflare:workers";
import { bundleFromJSON } from "@sigstore/bundle";
import { crypto as sigstoreCrypto, json as sigstoreJson } from "@sigstore/core";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import * as bundles from "./fixtures/bundles";
import { trustedRoot } from "./fixtures/trust";
import { genuineV012BundleJson } from "./fixtures/genuine-v012-bundle";
import { genuineV012TrustedRootJson } from "./fixtures/genuine-v012-trusted-root";
import { GuardedTufUpdater, TufPersistenceCommitError, TufStateMutationError, TufUpdaterPoisonedError } from "../src/guarded-tuf-updater";
import { DurableObjectTufMetadataStore } from "../src/durable-tuf-metadata-store";
import { TufMetadataReadError, type TufMetadataIdentity, type TufMetadataStore, type StoredTufMetadata } from "../src/tuf-storage-contract";
import { FencedTufMetadataSession } from "../src/fenced-tuf-metadata-session";
import type { TufTargetDescriptor, TufTargetStage } from "../src/tuf-storage-contract";
import { R2TufTargetStore } from "../src/r2-tuf-target-store";
import { stageVerifiedTufTarget } from "../src/verified-target-stream";
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
    expect(body.asyncTufUpdaterLoaded).toBe(true);
    expect(body.durableMetadataBindingLoaded).toBe(true);
    expect(body.r2TargetBindingLoaded).toBe(true);
    expect(body.tufNetworkOrCacheInitialized).toBe(false);
    expect(body.productionReady).toBe(false);
  });

  it("preserves Ed25519 verification when applying EC/RSA digest inference", () => {
    const data = Buffer.from("SentryIQ Ed25519 inference regression");
    const pair = generateKeyPairSync("ed25519");
    const signature = sign(null, data, pair.privateKey);
    expect(sigstoreCrypto.verify(data, pair.publicKey, signature)).toBe(true);
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

  it("rejects a tampered genuine DSSE signature after trusted-key validation", () => {
    if (genuineV012BundleJson === null || genuineV012TrustedRootJson === null) {
      throw new Error("CI must inject the genuine GitHub attestation bundle and current Sigstore trusted root before running this suite");
    }
    const bundle = bundleFromJSON(JSON.parse(genuineV012BundleJson));
    const trust = toTrustMaterial(TrustedRoot.fromJSON(JSON.parse(genuineV012TrustedRootJson)));
    const entity = toSignedEntity(bundle);
    const verifier = new Verifier(trust, {
      ctlogThreshold: 1,
      tlogThreshold: 1,
      timestampThreshold: 1
    });
    const internal = verifier as unknown as {
      verifyTimestamps: (entity: typeof entity) => Date[];
      verifySigningKey: (entity: typeof entity, timestamps: Date[]) => { key: unknown };
      verifySignature: (entity: typeof entity, signer: { key: unknown }) => void;
    };
    const timestamps = internal.verifyTimestamps(entity);
    const signer = internal.verifySigningKey(entity, timestamps);
    const signatureContent = entity.signature as unknown as { env: { signatures: Array<{ sig: Buffer }> } };
    const tampered = Buffer.from(signatureContent.env.signatures[0].sig);
    tampered[0] ^= 1;
    signatureContent.env.signatures[0].sig = tampered;
    expect(() => internal.verifySignature(entity, signer)).toThrow("signature verification failed");
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

  it("commits TUF metadata with a fenced compare-and-set and monotonic role versions", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-tuf-metadata-cas-test");
    const first = env.NODE_A_STATE.get(id);
    const lock = await first.acquireRunLock(60_000);
    const metadata = (type: string, version: number, label: string) => new TextEncoder().encode(JSON.stringify({ signed: { type, version, label }, signatures: [] }));
    const rootV1 = metadata("root", 1, "root-v1");
    const rootV1Hash = createHash("sha256").update(rootV1).digest("hex");
    const savedV1 = await first.commitVerifiedTufMetadata(
      "root", null, { version: 1, sha256: rootV1Hash, data: rootV1 }, lock
    );
    const second = env.NODE_A_STATE.get(id);
    const restored = await second.readTufMetadata("root");
    expect(restored?.version).toBe(1);
    expect(restored?.sha256).toBe(rootV1Hash);
    expect(Array.from(restored!.data)).toEqual(Array.from(rootV1));

    const rootV2 = metadata("root", 2, "root-v2");
    const rootV2Hash = createHash("sha256").update(rootV2).digest("hex");
    const rootV3 = metadata("root", 3, "root-v3");
    const rootV3Hash = createHash("sha256").update(rootV3).digest("hex");
    await expectRemoteRejection(
      second.commitVerifiedTufMetadata("root", savedV1, { version: 3, sha256: rootV3Hash, data: rootV3 }, lock),
      "TUF root rotation must advance exactly one version"
    );
    await expectRemoteRejection(
      second.commitVerifiedTufMetadata("root", { version: 9, sha256: "f".repeat(64) }, { version: 2, sha256: rootV2Hash, data: rootV2 }, lock),
      "TUF metadata compare-and-set current identity changed"
    );
    const savedV2 = await second.commitVerifiedTufMetadata(
      "root", savedV1, { version: 2, sha256: rootV2Hash, data: rootV2 }, lock
    );
    expect(savedV2.version).toBe(2);
    await expectRemoteRejection(
      second.commitVerifiedTufMetadata("root", savedV2, { version: 1, sha256: rootV1Hash, data: rootV1 }, lock),
      "TUF metadata rollback rejected"
    );
    const replacement = metadata("root", 2, "different-root-v2");
    await expectRemoteRejection(
      second.commitVerifiedTufMetadata("root", savedV2, { version: 2, sha256: createHash("sha256").update(replacement).digest("hex"), data: replacement }, lock),
      "same-version TUF metadata replacement rejected"
    );
    await expectRemoteRejection(
      second.commitVerifiedTufMetadata("timestamp", null, { version: 1, sha256: "a".repeat(64), data: rootV1 }, lock),
      "TUF metadata candidate digest mismatch"
    );
    const wrongEnvelope = metadata("timestamp", 1, "wrong-role");
    await expectRemoteRejection(
      second.commitVerifiedTufMetadata("root", null, { version: 1, sha256: createHash("sha256").update(wrongEnvelope).digest("hex"), data: wrongEnvelope }, lock),
      "TUF metadata role or version does not match its signed envelope"
    );
    expect((await first.readTufMetadata("root"))?.version).toBe(2);

    const delegated = metadata("targets", 1, "delegated-role");
    const delegatedHash = createHash("sha256").update(delegated).digest("hex");
    await first.commitVerifiedTufMetadata(
      "delegations/team-a", null, { version: 1, sha256: delegatedHash, data: delegated }, lock
    );
    await expectRemoteRejection(
      first.commitVerifiedTufMetadata("../escape", null, { version: 1, sha256: delegatedHash, data: delegated }, lock),
      "TUF metadata role name is invalid"
    );
    expect((await first.readTufMetadata("delegations/team-a"))?.sha256).toBe(delegatedHash);
  });

  it("requires an explicit immutable baseline before any release pin can advance", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-baseline-test");
    const stub = env.NODE_A_STATE.get(id);
    const lock = await stub.acquireRunLock(60_000);
    await expectRemoteRejection(stub.advancePin(candidate("1.0.0"), lock), "independent release baseline has not been initialized");
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
    const original = await stub.advancePin(candidate("2.0.0"), lock);

    await expectRemoteRejection(stub.advancePin(candidate("1.9.9", "d"), lock), "release rollback rejected");
    await expectRemoteRejection(stub.advancePin({ ...candidate("2.0.0"), zipSha256: "e".repeat(64) }, lock), "same-version release identity or digest replacement rejected");
    expect(await stub.getPin()).toEqual(original);
  });

  it("will not advance a pin without a valid active run lock", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-lock-required-test");
    const stub = env.NODE_A_STATE.get(id);
    await stub.initializeBaseline(candidate("1.0.0"));
    await expectRemoteRejection(stub.advancePin(candidate("1.1.0"), { runId: "a".repeat(32), fence: 1, token: "a".repeat(64), expiresAt: Date.now() + 60_000 }), "valid active Node A run fence required");
    expect((await stub.getPin())?.version).toBe("1.0.0");
  });

  it("treats an exact same-version pin as idempotent", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-idempotent-test");
    const stub = env.NODE_A_STATE.get(id);
    const first = await stub.initializeBaseline(candidate("3.0.0"));
    const lock = await stub.acquireRunLock(60_000);
    const second = await stub.advancePin(candidate("3.0.0"), lock);
    expect(second).toEqual(first);
  });

  it("serializes runs with a durable lease and token-bound release", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-lock-test");
    const stub = env.NODE_A_STATE.get(id);
    const lock = await stub.acquireRunLock(60_000);
    await expectRemoteRejection(stub.acquireRunLock(60_000), "Node A run already holds the durable lock");
    await expectRemoteRejection(stub.releaseRunLock({ ...lock, token: "b".repeat(64) }), "valid active Node A run fence required");
    await stub.releaseRunLock(lock);
    const next = await stub.acquireRunLock(60_000);
    expect(next.token).toMatch(/^[a-f0-9]{64}$/);
    expect(next.token).not.toBe(lock.token);
    expect(next.fence).toBe(lock.fence + 1);
    expect(next.runId).not.toBe(lock.runId);
  });

  it("rejects stale owners after lease expiry and monotonic-fence takeover", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-fencing-takeover-test");
    const stub = env.NODE_A_STATE.get(id);
    await stub.initializeBaseline(candidate("1.0.0"));
    const first = await stub.acquireRunLock(1_000);
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const second = await stub.acquireRunLock(60_000);
    expect(second.fence).toBe(first.fence + 1);
    expect(second.runId).not.toBe(first.runId);
    await expectRemoteRejection(stub.advancePin(candidate("1.1.0"), first), "valid active Node A run fence required");
    await expectRemoteRejection(stub.renewRunLock(first, 60_000), "valid active Node A run fence required");
    await expectRemoteRejection(stub.releaseRunLock(first), "valid active Node A run fence required");
    expect((await stub.advancePin(candidate("1.1.0"), second)).version).toBe("1.1.0");
  });
  it("poisons a TUF updater after accepted metadata cannot be durably committed", async () => {
    let refreshCalls = 0;
    let targetCalls = 0;
    const upstream = {
      async refresh() {
        refreshCalls++;
        throw new TufPersistenceCommitError("durable root commit failed after upstream acceptance");
      },
      async getTarget(targetPath: string) {
        targetCalls++;
        return targetPath;
      },
      async getTargetInfo(targetPath: string) {
        return { path: targetPath };
      },
      async findCachedTarget() { return undefined; },
      async downloadTarget(targetInfo: unknown) { return targetInfo; }
    };
    const guarded = new GuardedTufUpdater(upstream);
    await expect(guarded.refresh()).rejects.toBeInstanceOf(TufPersistenceCommitError);
    expect(guarded.poisoned).toBe(true);
    await expect(guarded.getTarget("targets/release.zip")).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    await expect(guarded.getTargetInfo("targets/release.zip")).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    await expect(guarded.findCachedTarget({ path: "targets/release.zip" })).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    await expect(guarded.downloadTarget({ path: "targets/release.zip" })).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    await expect(guarded.refresh()).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    expect(refreshCalls).toBe(1);
    expect(targetCalls).toBe(0);
  });

  it("does not poison an updater for an ordinary rejected refresh", async () => {
    let attempts = 0;
    const guarded = new GuardedTufUpdater({
      async refresh() {
        attempts++;
        if (attempts === 1) throw new Error("network unavailable before trusted-state mutation");
      },
      async getTarget(targetPath: string) { return targetPath; },
      async getTargetInfo(targetPath: string) { return { path: targetPath }; },
      async findCachedTarget() { return undefined; },
      async downloadTarget(targetInfo: unknown) { return targetInfo; }
    });
    await expect(guarded.refresh()).rejects.toThrow("network unavailable");
    expect(guarded.poisoned).toBe(false);
    await expect(guarded.getTarget("targets/release.zip")).resolves.toBe("targets/release.zip");
    expect(attempts).toBe(1);
  });

  it("poisons a TUF updater when upstream validation throws after partial trusted-state mutation", async () => {
    let refreshCalls = 0;
    const guarded = new GuardedTufUpdater({
      async refresh() {
        refreshCalls++;
        throw new TufStateMutationError("timestamp trusted-set mutation preceded freeze-check failure");
      },
      async getTarget(targetPath: string) { return targetPath; },
      async getTargetInfo(targetPath: string) { return { path: targetPath }; },
      async findCachedTarget() { return undefined; },
      async downloadTarget(targetInfo: unknown) { return targetInfo; }
    });
    await expect(guarded.refresh()).rejects.toBeInstanceOf(TufStateMutationError);
    expect(guarded.poisoned).toBe(true);
    await expect(guarded.getTarget("targets/release.zip")).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    expect(refreshCalls).toBe(1);
  });

  it("serializes concurrent updater operations so queued work observes poison", async () => {
    let releaseRefresh!: () => void;
    let targetDownloads = 0;
    const refreshGate = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const guarded = new GuardedTufUpdater({
      async refresh() {
        await refreshGate;
        throw new TufStateMutationError("upstream trusted set mutated before failure");
      },
      async getTarget(targetPath: string) { return targetPath; },
      async getTargetInfo(targetPath: string) { return { path: targetPath }; },
      async findCachedTarget() { return undefined; },
      async downloadTarget(targetInfo: unknown) {
        targetDownloads++;
        return targetInfo;
      }
    });

    const refresh = guarded.refresh();
    const queuedDownload = guarded.downloadTarget({ path: "targets/release.zip" });
    releaseRefresh();
    await expect(refresh).rejects.toBeInstanceOf(TufStateMutationError);
    await expect(queuedDownload).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
    expect(targetDownloads).toBe(0);
  });

  it("preserves every hash algorithm declared by TUF target metadata", () => {
    const descriptor: TufTargetDescriptor = {
      targetPath: "targets/release.zip",
      length: 12,
      hashes: {
        sha256: "a".repeat(64),
        sha512: "b".repeat(128)
      }
    };
    expect(Object.keys(descriptor.hashes).sort()).toEqual(["sha256", "sha512"]);
    const stage: TufTargetStage = { stageId: "stage-1", descriptor, objectKey: "staging/1", fence: 1 };
    expect(stage.descriptor).toBe(descriptor);
  });

  it("fails closed when the internal TUF route has no API token configured", async () => {
    const response = await workerExports.default.fetch(
      new Request("https://node-a.test/internal/tuf/refresh", { method: "POST" }),
      env,
      {} as ExecutionContext
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: "Node A API token is not configured"
    });
  });

  it("rejects an undersized configured API token before accepting any request", async () => {
    const protectedEnv = Object.create(env) as typeof env & { NODE_A_API_TOKEN: string };
    protectedEnv.NODE_A_API_TOKEN = "short-secret";
    const response = await workerExports.default.fetch(
      new Request("https://node-a.test/internal/tuf/refresh", {
        method: "POST",
        headers: { authorization: "Bearer short-secret" }
      }),
      protectedEnv,
      {} as ExecutionContext
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: "Node A API token must be 32-512 bytes and contain no control characters"
    });
  });

  it("rejects control characters in the configured API token", async () => {
    const protectedEnv = Object.create(env) as typeof env & { NODE_A_API_TOKEN: string };
    protectedEnv.NODE_A_API_TOKEN = "a".repeat(31) + "\n";
    const response = await workerExports.default.fetch(
      new Request("https://node-a.test/internal/tuf/refresh", {
        method: "POST",
        headers: { authorization: "Bearer " + "a".repeat(32) }
      }),
      protectedEnv,
      {} as ExecutionContext
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: "Node A API token must be 32-512 bytes and contain no control characters"
    });
  });

  it("rejects an invalid bearer token before touching TUF or storage", async () => {
    const protectedEnv = Object.create(env) as typeof env & { NODE_A_API_TOKEN: string };
    protectedEnv.NODE_A_API_TOKEN = "a".repeat(64);
    const response = await workerExports.default.fetch(
      new Request("https://node-a.test/internal/tuf/refresh", {
        method: "POST",
        headers: { authorization: "Bearer " + "b".repeat(64) }
      }),
      protectedEnv,
      {} as ExecutionContext
    );
    expect(response.status).toBe(401);
  });

  it("requires explicit root and mirror configuration after authentication", async () => {
    const protectedEnv = Object.create(env) as typeof env & { NODE_A_API_TOKEN: string };
    protectedEnv.NODE_A_API_TOKEN = "expected-secret";
    const response = await workerExports.default.fetch(
      new Request("https://node-a.test/internal/tuf/refresh", {
        method: "POST",
        headers: { authorization: "Bearer " + "a".repeat(64) }
      }),
      protectedEnv,
      {} as ExecutionContext
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toMatchObject({
      error: "Node A TUF runtime is not fully configured"
    });
  });

  it("publishes and reads immutable R2 target pointers only under the active fence", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-tuf-target-pointer-test");
    const state = env.NODE_A_STATE.get(id);
    const lock = await state.acquireRunLock(60_000);
    const content = new TextEncoder().encode("abc");
    const descriptor: TufTargetDescriptor = {
      targetPath: "targets/do-pointer.bin",
      length: content.byteLength,
      hashes: { sha256: createHash("sha256").update(content).digest("hex") }
    };
    const stageId = "22222222-2222-4222-8222-222222222222";
    const objectKey = "objects/11111111-1111-4111-8111-111111111111";
    await state.registerTufTargetStage(stageId, objectKey, lock);
    const saved = await state.commitTufTargetPointer(descriptor, stageId, objectKey, lock);
    expect(saved.objectKey).toBe(objectKey);
    expect(await state.readTufTargetPointer(descriptor.targetPath)).toEqual(saved);

    const replacementStageId = "77777777-7777-4777-8777-777777777777";
    const replacementObjectKey = "objects/88888888-8888-4888-8888-888888888888";
    await state.registerTufTargetStage(replacementStageId, replacementObjectKey, lock);
    const replacement = await state.commitTufTargetPointer(
      descriptor, replacementStageId, replacementObjectKey, lock
    );
    expect(await state.readTufTargetPointer(descriptor.targetPath)).toEqual(replacement);
    await expect(state.listRetiredTufTargetObjects(lock)).resolves.toEqual([]);
    await expect(state.listRetiredTufTargetObjects(lock, 100, 0)).resolves.toEqual([objectKey]);
    await state.deleteRetiredTufTargetObject(objectKey, lock);
    await expect(state.listRetiredTufTargetObjects(lock, 100, 0)).resolves.toEqual([]);

    await state.releaseRunLock(lock);

  });

  it("streams a verified target through the Workerd R2 binding and publishes its DO pointer", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-real-r2-target-stream-test");
    const state = env.NODE_A_STATE.get(id);
    const lock = await state.acquireRunLock(60_000);
    const content = new TextEncoder().encode("workerd R2 verified target");
    const descriptor: TufTargetDescriptor = {
      targetPath: "targets/workerd-r2-integration.bin",
      length: content.byteLength,
      hashes: { sha256: createHash("sha256").update(content).digest("hex") }
    };
    const fence = { runId: lock.runId, fence: lock.fence, token: lock.token };
    const store = new R2TufTargetStore(env.NODE_A_TARGETS, state, () => lock);
    try {
      const committed = await stageVerifiedTufTarget(store, {
        descriptor,
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(content.slice(0, 8));
            controller.enqueue(content.slice(8));
            controller.close();
          }
        }),
        fence
      });
      expect(await state.readTufTargetPointer(descriptor.targetPath)).toEqual(committed);
      const reader = await store.openCommittedTarget(descriptor.targetPath, descriptor);
      expect(reader).not.toBeNull();
      const chunks: Uint8Array[] = [];
      const streamReader = reader!.getReader();
      while (true) {
        const { done, value } = await streamReader.read();
        if (done) break;
        chunks.push(value);
      }
      expect(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))).toEqual(Buffer.from(content));
      await expect(state.listStaleTufTargetStages(lock)).resolves.toEqual([]);
    } finally {
      await state.releaseRunLock(lock);
    }
  });

  it("records private target stages and permits cleanup only after a newer fence takes over", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-target-stage-registry-test");
    const first = env.NODE_A_STATE.get(id);
    const lock1 = await first.acquireRunLock(60_000);
    const stageId = "55555555-5555-4555-8555-555555555555";
    const objectKey = "objects/66666666-6666-4666-8666-666666666666";
    first.registerTufTargetStage(stageId, objectKey, lock1);
    await expect(first.listStaleTufTargetStages(lock1)).resolves.toEqual([]);

    await first.releaseRunLock(lock1);
    const second = env.NODE_A_STATE.get(id);
    const lock2 = await second.acquireRunLock(60_000);
    expect(lock2.fence).toBe(lock1.fence + 1);
    await expect(second.listStaleTufTargetStages(lock2)).resolves.toEqual([
      { stageId, objectKey, fence: lock1.fence }
    ]);
    // Only the replacement fencing epoch can remove the abandoned stage.
    await second.deleteTufTargetStage(stageId, objectKey, lock2);
    await expect(second.listStaleTufTargetStages(lock2)).resolves.toEqual([]);
    await second.releaseRunLock(lock2);
  });

  it("adapts TUF metadata commits to the fenced Durable Object store", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-tuf-metadata-store-adapter-test");
    const state = env.NODE_A_STATE.get(id);
    const lock = await state.acquireRunLock(60_000);
    const store = new DurableObjectTufMetadataStore(state, () => lock);
    const data = new TextEncoder().encode(JSON.stringify({
      signed: { type: "root", version: 1 },
      signatures: []
    }));
    const sha256 = createHash("sha256").update(data).digest("hex");
    const fence = { runId: lock.runId, fence: lock.fence, token: lock.token };

    const saved = await store.commitVerifiedRole(
      "root",
      null,
      { version: 1, sha256, data },
      fence
    );
    expect(saved).toEqual({ version: 1, sha256 });

    const restored = await store.readRole("root");
    expect(restored?.version).toBe(1);
    expect(restored?.sha256).toBe(sha256);
    expect(Array.from(restored!.data)).toEqual(Array.from(data));

    await expect(store.commitVerifiedRole(
      "timestamp",
      null,
      { version: 1, sha256, data },
      { ...fence, fence: fence.fence + 1 }
    )).rejects.toThrow("TUF storage fence does not match the active Node A run lock");

    // A caller retaining the old run identity must still be rejected by the
    // Durable Object after lease release and a new fencing epoch is acquired.
    await state.releaseRunLock(lock);
    const replacement = await state.acquireRunLock(60_000);
    expect(replacement.fence).toBe(lock.fence + 1);
    const staleData = new TextEncoder().encode(JSON.stringify({
      signed: { type: "timestamp", version: 1 },
      signatures: []
    }));
    const staleDigest = createHash("sha256").update(staleData).digest("hex");
    await expect(store.commitVerifiedRole(
      "timestamp",
      null,
      { version: 1, sha256: staleDigest, data: staleData },
      fence
    )).rejects.toMatchObject({ code: "TUF_METADATA_COMMIT_FAILED" });
    await state.releaseRunLock(replacement);

    const unavailableStore = new DurableObjectTufMetadataStore({
      readTufMetadata: () => { throw new Error("simulated Durable Object read outage"); },
      listTufMetadataRoles: () => [],
      commitVerifiedTufMetadata: () => { throw new Error("not used"); }
    }, () => replacement);
    await expect(unavailableStore.readRole("timestamp")).rejects.toMatchObject({ code: "TUF_METADATA_READ_FAILED" });
  });

});


describe("fenced asynchronous TUF metadata session", () => {
  const roleBytes = (type: string, version: number) =>
    new TextEncoder().encode(JSON.stringify({ signed: { type, version }, signatures: [] }));

  function memoryStore() {
    const roles = new Map<string, StoredTufMetadata>();
    let failCommit = false;
    const store: TufMetadataStore = {
      async listRoles() { return [...roles.keys()]; },
      async readRole(roleName) {
        const value = roles.get(roleName);
        return value ? { ...value, data: value.data.slice() } : null;
      },
      async commitVerifiedRole(roleName, expected, next) {
        if (failCommit) throw new Error("injected durable commit failure");
        const current = roles.get(roleName) ?? null;
        if (expected === null ? current !== null : !current || current.version !== expected.version || current.sha256 !== expected.sha256) {
          throw new Error("CAS mismatch");
        }
        if (current && next.version !== current.version + 1) throw new Error("version sequence mismatch");
        roles.set(roleName, { ...next, data: next.data.slice() });
        return { version: next.version, sha256: next.sha256 } satisfies TufMetadataIdentity;
      }
    };
    return { store, fail: () => { failCommit = true; } };
  }

  const fence = { runId: "a".repeat(32), fence: 1, token: "b".repeat(64) };

  it("rejects a durable root whose recorded digest does not match its bytes", async () => {
    const root1 = roleBytes("root", 1);
    const { store } = memoryStore();
    const valid = { version: 1, sha256: createHash("sha256").update(root1).digest("hex"), data: root1 };
    const corruptStore: TufMetadataStore = {
      async listRoles() { return ["root"]; },
      async readRole() { return { ...valid, sha256: "0".repeat(64), data: valid.data.slice() }; },
      async commitVerifiedRole() { throw new Error("not used"); }
    };
    let verifierCalls = 0;
    await expect(FencedTufMetadataSession.create(corruptStore, fence, root1, () => { verifierCalls++; }))
      .rejects.toThrow("durable TUF root identity does not match its stored bytes");
    expect(verifierCalls).toBe(0);
    expect(await store.readRole("root")).toBeNull();
  });

  it("does not persist a bootstrap root until the upstream verifier accepts it", async () => {
    const { store } = memoryStore();
    const root1 = roleBytes("root", 1);
    await expect(FencedTufMetadataSession.create(store, fence, root1, () => {
      throw new Error("root self-signature rejected");
    })).rejects.toThrow("root self-signature rejected");
    expect(await store.readRole("root")).toBeNull();
  });

  it("seeds an explicit root and commits root rotations one-by-one before fetching the next", async () => {
    const { store } = memoryStore();
    const root1 = roleBytes("root", 1);
    const { session, root } = await FencedTufMetadataSession.create(store, fence, root1, () => undefined);
    expect(root.version).toBe(1);
    const events: string[] = [];
    const identity = await session.rotateRoots(
      2,
      2,
      async (version) => {
        events.push(`fetch:${version}`);
        return roleBytes("root", version);
      },
      async (bytes) => {
        const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { signed: { version: number } };
        events.push(`accept:${parsed.signed.version}`);
      },
      { version: 1, sha256: root.sha256 }
    );
    expect(identity.version).toBe(3);
    expect(events).toEqual(["fetch:2", "accept:2", "fetch:3", "accept:3"]);
    expect((await store.readRole("root"))?.version).toBe(3);
  });

  it("poisons the session when upstream acceptance succeeds but durable commit fails", async () => {
    const { store, fail } = memoryStore();
    const { session } = await FencedTufMetadataSession.create(store, fence, roleBytes("root", 1), () => undefined);
    fail();
    await expect(session.acceptVerifiedRole("timestamp", roleBytes("timestamp", 1), {
      expectedCurrent: null,
      acceptIntoTrustedSet: () => undefined
    })).rejects.toMatchObject({ code: "TUF_METADATA_COMMIT_FAILED" });
    expect(session.isPoisoned).toBe(true);
    await expect(session.acceptVerifiedRole("snapshot", roleBytes("snapshot", 1), {
      expectedCurrent: null,
      acceptIntoTrustedSet: () => undefined
    })).rejects.toThrow("poisoned");
  });

  it("poisons the metadata session when upstream role acceptance fails ambiguously", async () => {
    const { store } = memoryStore();
    const { session } = await FencedTufMetadataSession.create(store, fence, roleBytes("root", 1), () => undefined);
    await expect(session.acceptVerifiedRole("timestamp", roleBytes("timestamp", 1), {
      expectedCurrent: null,
      acceptIntoTrustedSet: () => { throw new Error("validation failed after possible trusted-set mutation"); }
    })).rejects.toBeInstanceOf(TufStateMutationError);
    expect(session.isPoisoned).toBe(true);
    await expect(session.acceptVerifiedRole("snapshot", roleBytes("snapshot", 1), {
      expectedCurrent: null,
      acceptIntoTrustedSet: () => undefined
    })).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
  });

  it("poisons root rotation after an ambiguous upstream root-acceptance failure", async () => {
    const { store } = memoryStore();
    const { session, root } = await FencedTufMetadataSession.create(store, fence, roleBytes("root", 1), () => undefined);
    let fetched = 0;
    await expect(session.rotateRoots(
      2,
      2,
      async (version) => {
        fetched++;
        return roleBytes("root", version);
      },
      () => { throw new Error("root accepted partially before validation failure"); },
      { version: 1, sha256: root.sha256 }
    )).rejects.toBeInstanceOf(TufStateMutationError);
    expect(session.isPoisoned).toBe(true);
    expect(fetched).toBe(1);
    expect((await store.readRole("root"))?.version).toBe(1);
  });


  it("stops root rotation and poisons the verifier when a verified root cannot be durably committed", async () => {
    const { store, fail } = memoryStore();
    const { session, root } = await FencedTufMetadataSession.create(
      store, fence, roleBytes("root", 1), () => undefined
    );
    let fetched: number[] = [];
    let accepted: number[] = [];
    // The first rotation is accepted in memory, but its durable commit fails.
    fail();
    await expect(session.rotateRoots(
      2,
      3,
      async (version) => {
        fetched.push(version);
        return roleBytes("root", version);
      },
      (bytes) => {
        const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { signed: { version: number } };
        accepted.push(parsed.signed.version);
      },
      { version: 1, sha256: root.sha256 }
    )).rejects.toMatchObject({ code: "TUF_METADATA_COMMIT_FAILED" });

    expect(fetched).toEqual([2]);
    expect(accepted).toEqual([2]);
    expect(session.isPoisoned).toBe(true);
    expect((await store.readRole("root"))?.version).toBe(1);
    await expect(session.rotateRoots(
      2, 1,
      async (version) => roleBytes("root", version),
      () => undefined,
      { version: 1, sha256: root.sha256 }
    )).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
  });


  it("fails closed on a durable root read outage instead of treating it as a missing cache", async () => {
    const root1 = roleBytes("root", 1);
    let writes = 0;
    const unavailable: TufMetadataStore = {
      async listRoles() { throw new TufMetadataReadError("durable metadata store unavailable"); },
      async readRole() {
        throw new TufMetadataReadError("durable metadata store unavailable");
      },
      async commitVerifiedRole() {
        writes++;
        throw new Error("must not seed over an unavailable durable store");
      }
    };
    let verifierCalls = 0;
    await expect(FencedTufMetadataSession.create(
      unavailable,
      fence,
      root1,
      () => { verifierCalls++; }
    )).rejects.toBeInstanceOf(TufMetadataReadError);
    expect(writes).toBe(0);
    expect(verifierCalls).toBe(0);
  });

});
