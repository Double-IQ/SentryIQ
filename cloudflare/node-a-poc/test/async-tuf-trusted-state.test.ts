import { describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { AsyncTufTrustedStateAdapter } from "../src/async-tuf-trusted-state";
import { TufStateMutationError } from "../src/guarded-tuf-updater";
import type {
  StoredTufMetadata,
  TufMetadataIdentity,
  TufMetadataStore,
  TufRunFence
} from "../src/tuf-storage-contract";

const fence: TufRunFence = {
  runId: "a".repeat(32),
  fence: 9,
  token: "b".repeat(64)
};

function metadata(version: number, role: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    signed: { _type: role, version }
  }));
}

function memoryStore() {
  const records = new Map<string, StoredTufMetadata>();
  const store: TufMetadataStore = {
    readRole: vi.fn(async (name: string) => records.get(name) ?? null),
    listRoles: vi.fn(async () => [...records.keys()]),
    commitVerifiedRole: vi.fn(async (
      name: string,
      expected: TufMetadataIdentity | null,
      next: StoredTufMetadata
    ) => {
      const current = records.get(name) ?? null;
      if (expected === null ? current !== null : !current ||
          current.version !== expected.version || current.sha256 !== expected.sha256) {
        throw new Error("CAS mismatch");
      }
      records.set(name, { ...next, data: next.data.slice() });
      return { version: next.version, sha256: next.sha256 };
    })
  };
  return { store, records };
}

describe("async adapter over pinned TUF trusted metadata store", () => {
  it("uses the upstream verifier for each role before durable persistence", async () => {
    const { store, records } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn()
    };
    const factory = vi.fn(() => upstream);
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), factory
    );

    const timestamp = metadata(1, "timestamp");
    await adapter.refreshTimestamp(timestamp);
    expect(upstream.updateTimestamp).toHaveBeenCalledWith(timestamp);
    expect(records.get("timestamp")?.data).toEqual(timestamp);
    expect(store.commitVerifiedRole).toHaveBeenCalledTimes(2);
  });

  it("reconstructs the trusted set from durable metadata after restart", async () => {
    const { store, records } = memoryStore();
    const firstTrusted = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn()
    };
    const first = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => firstTrusted
    );
    await first.refreshTimestamp(metadata(1, "timestamp"));
    await first.refreshSnapshot(metadata(1, "snapshot"));

    const restartedTrusted = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn()
    };
    await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => restartedTrusted
    );

    expect(records.has("timestamp")).toBe(true);
    expect(records.has("snapshot")).toBe(true);
    expect(restartedTrusted.updateTimestamp).toHaveBeenCalledWith(records.get("timestamp")?.data);
    expect(restartedTrusted.updateSnapshot).toHaveBeenCalledWith(records.get("snapshot")?.data);
  });

  it("does not persist when upstream TUF rejects a role", async () => {
    const { store, records } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(() => { throw new Error("signature threshold failed"); }),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn()
    };
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => upstream
    );

    await expect(adapter.refreshTimestamp(metadata(1, "timestamp")))
      .rejects.toMatchObject({
        constructor: TufStateMutationError,
        causeValue: expect.objectContaining({ message: "signature threshold failed" })
      });
    expect(records.has("timestamp")).toBe(false);
    expect(store.commitVerifiedRole).toHaveBeenCalledTimes(1);
  });

  it("poisons the adapter if upstream acceptance cannot be durably committed", async () => {
    const { store } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn()
    };
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => upstream
    );
    vi.mocked(store.commitVerifiedRole).mockRejectedValueOnce(new Error("DO commit unavailable"));

    await expect(adapter.refreshTimestamp(metadata(1, "timestamp")))
      .rejects.toThrow("durable commit failed");
    await expect(adapter.refreshSnapshot(metadata(1, "snapshot")))
      .rejects.toThrow("poisoned");
    expect(upstream.updateSnapshot).not.toHaveBeenCalled();
  });

  it("recognizes the canonical TUF _type role envelope", async () => {
    const { store, records } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn()
    };
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => upstream
    );
    await adapter.refreshSnapshot(metadata(1, "snapshot"));
    const saved = records.get("snapshot");
    expect(saved?.version).toBe(1);
    expect(saved?.sha256).toBe(createHash("sha256").update(metadata(1, "snapshot")).digest("hex"));
  });
});
