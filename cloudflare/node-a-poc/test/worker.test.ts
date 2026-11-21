import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const candidate = (version: string, suffix = "a") => ({
  version,
  commit: suffix.repeat(40),
  manifestSha256: "b".repeat(64),
  zipSha256: "c".repeat(64)
});

describe("Node A Workers runtime proof", () => {
  it("loads the Sigstore verifier and TUF client in workerd and executes Ed25519 crypto", async () => {
    const response = await env.SELF.fetch("https://node-a-poc.test/runtime-check");
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body.cryptoOk).toBe(true);
    expect(body.sigstoreVerifierLoaded).toBe(true);
    expect(body.tufClientLoaded).toBe(true);
    expect(body.tufNetworkOrCacheInitialized).toBe(false);
    expect(body.productionReady).toBe(false);
  });

  it("persists the release pin across separate Durable Object stubs", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-persistence-test");
    const first = env.NODE_A_STATE.get(id);
    const saved = await first.advancePin(candidate("1.2.3"), 1_800_000_000_000);
    expect(saved.version).toBe("1.2.3");

    const second = env.NODE_A_STATE.get(id);
    expect(await second.getPin()).toEqual(saved);
  });

  it("rejects downgrade and same-version replacement without mutating the pin", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-rollback-test");
    const stub = env.NODE_A_STATE.get(id);
    const original = await stub.advancePin(candidate("2.0.0"), 1_800_000_000_000);

    await expect(stub.advancePin(candidate("1.9.9", "d"), 1_800_000_001_000))
      .rejects.toThrow("release rollback rejected");
    await expect(stub.advancePin({ ...candidate("2.0.0"), zipSha256: "e".repeat(64) }, 1_800_000_002_000))
      .rejects.toThrow("same-version release identity or digest replacement rejected");
    expect(await stub.getPin()).toEqual(original);
  });

  it("treats an exact same-version pin as idempotent", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-idempotent-test");
    const stub = env.NODE_A_STATE.get(id);
    const first = await stub.advancePin(candidate("3.0.0"), 1_800_000_000_000);
    const second = await stub.advancePin(candidate("3.0.0"), 1_800_000_010_000);
    expect(second).toEqual(first);
  });

  it("serializes runs with a durable lease and token-bound release", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-lock-test");
    const stub = env.NODE_A_STATE.get(id);
    const lock = await stub.acquireRunLock("a".repeat(64), 1_800_000_000_000, 60_000);
    await expect(stub.acquireRunLock("b".repeat(64), 1_800_000_001_000, 60_000))
      .rejects.toThrow("Node A run already holds the durable lock");
    await expect(stub.releaseRunLock("b".repeat(64))).rejects.toThrow("run lock token mismatch");
    await stub.releaseRunLock(lock.token);
    await expect(stub.acquireRunLock("b".repeat(64), 1_800_000_002_000, 60_000)).resolves.toMatchObject({
      token: "b".repeat(64)
    });
  });

  it("allows takeover only after the persisted lock lease expires", async () => {
    const id = env.NODE_A_STATE.idFromName("node-a-expiry-test");
    const stub = env.NODE_A_STATE.get(id);
    await stub.acquireRunLock("a".repeat(64), 1_800_000_000_000, 60_000);
    await expect(stub.acquireRunLock("b".repeat(64), 1_800_000_060_000, 60_000)).resolves.toMatchObject({
      token: "b".repeat(64)
    });
  });
});
