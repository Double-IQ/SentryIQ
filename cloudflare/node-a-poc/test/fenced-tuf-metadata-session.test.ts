import { describe, expect, it, vi } from "vitest";
import {
  FencedTufMetadataSession
} from "../src/fenced-tuf-metadata-session";
import {
  TufPersistenceCommitError,
  TufUpdaterPoisonedError
} from "../src/guarded-tuf-updater";
import type {
  StoredTufMetadata,
  TufMetadataIdentity,
  TufMetadataStore,
  TufRunFence
} from "../src/tuf-storage-contract";

const fence: TufRunFence = {
  runId: "a".repeat(32),
  fence: 4,
  token: "b".repeat(64)
};

function role(version: number, type = "root"): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    signed: { _type: type, type, version }
  }));
}

function fakeStore(initial: StoredTufMetadata | null = null) {
  const records = new Map<string, StoredTufMetadata>();
  if (initial) records.set("root", initial);
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
  return { store, getCurrent: (name = "root") => records.get(name) ?? null };
}
describe("fenced asynchronous TUF metadata session", () => {
  it("verifies the explicit bootstrap root before its first durable write", async () => {
    const { store, getCurrent } = fakeStore();
    const verify = vi.fn(async () => {
      expect(store.commitVerifiedRole).not.toHaveBeenCalled();
    });

    const result = await FencedTufMetadataSession.create(
      store, fence, role(1), verify
    );

    expect(verify).toHaveBeenCalledOnce();
    expect(getCurrent()?.version).toBe(1);
    expect(result.root.version).toBe(1);
  });

  it("does not seed an invalid bootstrap root", async () => {
    const { store, getCurrent } = fakeStore();
    await expect(FencedTufMetadataSession.create(
      store, fence, role(2), vi.fn()
    )).rejects.toThrow("version 1");
    expect(store.commitVerifiedRole).not.toHaveBeenCalled();
    expect(getCurrent()).toBeNull();
  });

  it("fails closed on durable read errors instead of treating them as a cache miss", async () => {
    const { store } = fakeStore();
    vi.mocked(store.readRole).mockRejectedValueOnce(new Error("DO unavailable"));
    await expect(FencedTufMetadataSession.create(
      store, fence, role(1), vi.fn()
    )).rejects.toThrow("DO unavailable");
    expect(store.commitVerifiedRole).not.toHaveBeenCalled();
  });

  it("rejects durable root bytes whose identity does not match the stored record", async () => {
    const { store } = fakeStore({
      version: 1,
      sha256: "0".repeat(64),
      data: role(1)
    });
    const verify = vi.fn();
    await expect(FencedTufMetadataSession.create(
      store, fence, role(1), verify
    )).rejects.toThrow("identity does not match");
    expect(verify).not.toHaveBeenCalled();
  });

  it("poisons the session when upstream acceptance succeeds but durable commit fails", async () => {
    const { store } = fakeStore();
    const { session } = await FencedTufMetadataSession.create(
      store, fence, role(1), vi.fn()
    );
    vi.mocked(store.commitVerifiedRole).mockRejectedValueOnce(new Error("disk full"));

    await expect(session.acceptVerifiedRole("timestamp", role(2, "timestamp"), {
      expectedCurrent: null,
      acceptIntoTrustedSet: vi.fn()
    })).rejects.toBeInstanceOf(TufPersistenceCommitError);

    expect(session.isPoisoned).toBe(true);
    await expect(session.acceptVerifiedRole("snapshot", role(2, "snapshot"), {
      expectedCurrent: null,
      acceptIntoTrustedSet: vi.fn()
    })).rejects.toBeInstanceOf(TufUpdaterPoisonedError);
  });

  it("commits each root rotation before fetching the next root", async () => {
    const { store } = fakeStore();
    const { session } = await FencedTufMetadataSession.create(
      store, fence, role(1), vi.fn()
    );
    const events: string[] = [];
    vi.mocked(store.commitVerifiedRole).mockImplementation(async (
      name, expected, next
    ) => {
      events.push("commit:" + next.version);
      return { version: next.version, sha256: next.sha256 };
    });
    const fetch = vi.fn(async (version: number) => {
      events.push("fetch:" + version);
      return role(version);
    });
    const accept = vi.fn(async (bytes: Uint8Array) => {
      const parsed = JSON.parse(new TextDecoder().decode(bytes)) as {
        signed: { version: number }
      };
      events.push("accept:" + parsed.signed.version);
    });

    await session.rotateRoots(2, 2, fetch, accept, {
      version: 1,
      sha256: "1".repeat(64)
    });

    expect(events).toEqual([
      "fetch:2", "accept:2", "commit:2",
      "fetch:3", "accept:3", "commit:3"
    ]);
  });
});
