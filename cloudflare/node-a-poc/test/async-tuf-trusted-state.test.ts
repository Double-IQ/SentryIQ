import { Buffer } from "node:buffer";
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

function metadata(version: number, role: string, extra: Record<string, unknown> = {}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    signed: { _type: role, version, ...extra }
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
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    };
    const factory = vi.fn(() => upstream);
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), factory
    );

    const timestamp = metadata(1, "timestamp");
    await adapter.refreshTimestamp(timestamp);
    expect(upstream.updateTimestamp).toHaveBeenCalledWith(Buffer.from(timestamp));
    expect(records.get("timestamp")?.data).toEqual(timestamp);
    expect(store.commitVerifiedRole).toHaveBeenCalledTimes(2);
  });

  it("rejects same-version timestamp equivocation while allowing an identical cached timestamp", async () => {
    const { store, records } = memoryStore();
    const trusted: any = {
      root: { signed: { version: 1 } },
      timestamp: undefined,
      snapshot: undefined,
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    };
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => trusted
    );
    const accepted = metadata(1, "timestamp");
    await adapter.refreshTimestamp(accepted);
    trusted.timestamp = { signed: { version: 1 } };

    await expect(adapter.refreshTimestamp(accepted)).resolves.toEqual({
      version: 1,
      sha256: createHash("sha256").update(accepted).digest("hex")
    });
    await expect(adapter.refreshTimestamp(
      metadata(1, "timestamp", { expires: "2030-01-01T00:00:00Z" })
    )).rejects.toThrow("same-version TUF timestamp replacement or equivocation rejected");
    expect(trusted.updateTimestamp).toHaveBeenCalledTimes(1);
    expect(records.get("timestamp")?.data).toEqual(accepted);
  });

  it("reconstructs the trusted set from durable metadata after restart", async () => {
    const { store, records } = memoryStore();
    const firstTrusted = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
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
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    };
    await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => restartedTrusted
    );

    expect(records.has("timestamp")).toBe(true);
    expect(records.has("snapshot")).toBe(true);
    expect(restartedTrusted.updateTimestamp).toHaveBeenCalledWith(Buffer.from(records.get("timestamp")!.data));
    expect(restartedTrusted.updateSnapshot).not.toHaveBeenCalled();
  });

  it("passes delegated metadata to the upstream verifier in its exact API argument order", async () => {
    const { store } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    };
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => upstream
    );
    const delegated = metadata(1, "targets");
    await adapter.refreshDelegatedTargets("child", "targets", delegated);
    expect(upstream.updateDelegatedTargets).toHaveBeenCalledWith(
      Buffer.from(delegated), "child", "targets"
    );
  });

  it("recovers from an expired cached timestamp without weakening durable rollback checks", async () => {
    const { store, records } = memoryStore();
    const seed = await AsyncTufTrustedStateAdapter.create(store, fence, metadata(1, "root"), () => ({
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    }));
    await seed.refreshTimestamp(metadata(1, "timestamp"));

    const recoveredUpstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn()
        .mockImplementationOnce(() => { throw new Error("cached timestamp expired"); })
        .mockImplementation(() => undefined),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    };
    const recovered = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => recoveredUpstream
    );
    await recovered.refreshTimestamp(metadata(2, "timestamp"));

    expect(recoveredUpstream.updateTimestamp).toHaveBeenCalledTimes(2);
    expect(records.get("timestamp")?.version).toBe(2);
  });

  it("rotates roots sequentially through upstream validation and durable commits", async () => {
    const { store, records } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
    };
    const adapter = await AsyncTufTrustedStateAdapter.create(
      store, fence, metadata(1, "root"), () => upstream
    );
    const events: string[] = [];
    vi.mocked(store.commitVerifiedRole).mockImplementation(async (name, expected, next) => {
      events.push("commit:" + name + ":" + next.version);
      records.set(name, { ...next, data: next.data.slice() });
      return { version: next.version, sha256: next.sha256 };
    });
    upstream.updateRoot.mockImplementation(() => { events.push("accept:root"); });
    await adapter.rotateRoots(2, 2, async (version) => {
      events.push("fetch:" + version);
      if (version === 4) throw Object.assign(new Error("not found"), { statusCode: 404 });
      return metadata(version, "root");
    });
    expect(events).toEqual([
      "fetch:2", "accept:root", "commit:root:2",
      "fetch:3", "accept:root", "commit:root:3", "fetch:4"
    ]);
    expect(records.get("root")?.version).toBe(3);
  });

  it("does not persist when upstream TUF rejects a role", async () => {
    const { store, records } = memoryStore();
    const upstream = {
      updateRoot: vi.fn(),
      updateTimestamp: vi.fn(() => { throw new Error("signature threshold failed"); }),
      updateSnapshot: vi.fn(),
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
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
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
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
      updateDelegatedTargets: vi.fn(),
      getRole: vi.fn(() => undefined)
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
