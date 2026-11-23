import { createHash } from "node:crypto";
import { describe, expect, it, vi, afterEach } from "vitest";
import { AsyncTufUpdater, TufMetadataHttpError } from "../src/async-tuf-updater";
import type { AsyncTufTrustedStateAdapter } from "../src/async-tuf-trusted-state";
import type {
  CommittedTufTarget,
  TufRunFence,
  TufTargetStage,
  TufTargetStore
} from "../src/tuf-storage-contract";

const fence: TufRunFence = {
  runId: "a".repeat(32),
  fence: 3,
  token: "b".repeat(64)
};

const payload = new TextEncoder().encode("signed release bytes");
const targetInfo = {
  path: "release.bin",
  length: payload.byteLength,
  hashes: { sha256: createHash("sha256").update(payload).digest("hex") }
};

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" }
  });
}

function stream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.slice());
      controller.close();
    }
  });
}

function makeTrustedAdapter() {
  let timestamp: { signed: { version: number; snapshotMeta: { version: number; length: number } } } | undefined;
  let snapshot: { signed: { version: number; meta: Record<string, { version: number; length: number }> } } | undefined;
  const roles = new Map<string, { signed: { targets?: Record<string, unknown> } }>();
  const adapter = {
    root: { signed: { version: 1, consistentSnapshot: false } },
    get timestamp() { return timestamp; },
    get snapshot() { return snapshot; },
    setTimestamp(value: typeof timestamp) { timestamp = value; },
    setSnapshot(value: typeof snapshot) { snapshot = value; },
    getRole: (name: string) => roles.get(name),
    rotateRoots: vi.fn(async (
      _first: number,
      _max: number,
      fetchRoot: (version: number) => Promise<Uint8Array>
    ) => {
      try { await fetchRoot(2); }
      catch (error) {
        if (!(error instanceof TufMetadataHttpError) || error.statusCode !== 404) throw error;
      }
      return { version: 1, sha256: "0".repeat(64) };
    }),
    refreshTimestamp: vi.fn(async (bytes: Uint8Array) => {
      timestamp = JSON.parse(new TextDecoder().decode(bytes)) as typeof timestamp;
      return { version: timestamp!.signed.version, sha256: "1".repeat(64) };
    }),
    refreshSnapshot: vi.fn(async (bytes: Uint8Array) => {
      snapshot = JSON.parse(new TextDecoder().decode(bytes)) as typeof snapshot;
      return { version: snapshot!.signed.version, sha256: "2".repeat(64) };
    }),
    refreshDelegatedTargets: vi.fn(async (roleName: string, _parent: string, bytes: Uint8Array) => {
      roles.set(roleName, JSON.parse(new TextDecoder().decode(bytes)) as { signed: { targets?: Record<string, unknown> } });
      return { version: 1, sha256: "3".repeat(64) };
    })
  };
  return adapter;
}

function fakeTargetStore() {
  const stage: TufTargetStage = {
    stageId: "stage-1",
    descriptor: { targetPath: targetInfo.path, length: targetInfo.length, hashes: targetInfo.hashes },
    objectKey: "private/stage-1",
    fence: fence.fence
  };
  const committed: CommittedTufTarget = {
    ...stage.descriptor,
    objectKey: "immutable/release",
    fence: fence.fence,
    committedAt: 1
  };
  const chunks: Uint8Array[] = [];
  let published = false;
  const store: TufTargetStore = {
    beginTarget: vi.fn(async () => stage),
    writeTargetChunk: vi.fn(async (_stage, chunk) => { chunks.push(chunk.slice()); }),
    commitTarget: vi.fn(async () => { published = true; return committed; }),
    openCommittedTarget: vi.fn(async () => published ? stream(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))) : null),
    abortTarget: vi.fn(async () => undefined)
  };
  return { store, chunks, committed };
}

afterEach(() => vi.unstubAllGlobals());

describe("async TUF updater workflow", () => {
  it("requires HTTPS mirror base URLs without credentials, queries, or fragments", () => {
    const { store } = fakeTargetStore();
    const trusted = makeTrustedAdapter() as unknown as AsyncTufTrustedStateAdapter;
    for (const metadataBaseUrl of [
      "http://mirror.test/metadata/",
      "https://user:pass@mirror.test/metadata/",
      "https://mirror.test/metadata/?override=1",
      "https://mirror.test/metadata/#fragment"
    ]) {
      expect(() => new AsyncTufUpdater(trusted, store, fence, {
        metadataBaseUrl,
        targetBaseUrl: "https://mirror.test/targets/"
      })).toThrow();
    }
  });

  it("keeps target requests beneath the configured HTTPS base and encodes path segments", async () => {
    const { store } = fakeTargetStore();
    const trusted = makeTrustedAdapter() as unknown as AsyncTufTrustedStateAdapter;
    const fetchMock = vi.fn(async () => new Response(stream(payload)));
    vi.stubGlobal("fetch", fetchMock);
    const updater = new AsyncTufUpdater(trusted, store, fence, {
      metadataBaseUrl: "https://mirror.test/metadata",
      targetBaseUrl: "https://mirror.test/targets"
    });

    await updater.downloadTarget({
      ...targetInfo,
      path: "release%2Fbundle.bin"
    });

    expect(fetchMock).toHaveBeenCalledWith("https://mirror.test/targets/release%252Fbundle.bin");
  });

  it("rejects traversal and query-bearing target paths before making a request", async () => {
    const { store } = fakeTargetStore();
    const trusted = makeTrustedAdapter() as unknown as AsyncTufTrustedStateAdapter;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const updater = new AsyncTufUpdater(trusted, store, fence, {
      metadataBaseUrl: "https://mirror.test/metadata/",
      targetBaseUrl: "https://mirror.test/targets/"
    });

    await expect(updater.getTargetInfo("../secret")).rejects.toThrow("TUF target path is invalid");
    await expect(updater.getTargetInfo("release.bin?redirect=1")).rejects.toThrow("TUF target path is invalid");
    await expect(updater.downloadTarget({ ...targetInfo, path: "../secret" })).rejects.toThrow("TUF target path is invalid");
    await expect(updater.downloadTarget({ ...targetInfo, path: "release.bin?redirect=1" })).rejects.toThrow("TUF target path is invalid");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refreshes root, timestamp, snapshot, and delegated targets in TUF order", async () => {
    const trusted = makeTrustedAdapter();
    const calls: string[] = [];
    const targetsDocument = {
      signed: { _type: "targets", version: 1, targets: {
        "release.bin": { length: targetInfo.length, hashes: targetInfo.hashes }
      } }
    };
    const targetsLength = new TextEncoder().encode(JSON.stringify(targetsDocument)).byteLength;
    const snapshotDocument = {
      signed: { _type: "snapshot", version: 7, meta: {
        "targets.json": { version: 1, length: targetsLength }
      } }
    };
    const snapshotLength = new TextEncoder().encode(JSON.stringify(snapshotDocument)).byteLength;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/2.root.json")) return new Response("not found", { status: 404 });
      if (url.endsWith("/timestamp.json")) {
        return json({ signed: { _type: "timestamp", version: 4, snapshotMeta: { version: 7, length: snapshotLength } } });
      }
      if (url.endsWith("/snapshot.json")) return json(snapshotDocument);
      if (url.endsWith("/targets.json")) return json(targetsDocument);
      return new Response("unexpected URL", { status: 500 });
    }));

    const { store } = fakeTargetStore();
    const updater = new AsyncTufUpdater(
      trusted as unknown as AsyncTufTrustedStateAdapter,
      store,
      fence,
      { metadataBaseUrl: "https://example.test/metadata", targetBaseUrl: "https://example.test/targets" }
    );

    const info = await updater.getTargetInfo("release.bin");
    expect(info).toEqual(targetInfo);
    expect(calls).toEqual([
      "https://example.test/metadata/2.root.json",
      "https://example.test/metadata/timestamp.json",
      "https://example.test/metadata/snapshot.json",
      "https://example.test/metadata/targets.json"
    ]);
    expect(trusted.refreshTimestamp).toHaveBeenCalledOnce();
    expect(trusted.refreshSnapshot).toHaveBeenCalledOnce();
    expect(trusted.refreshDelegatedTargets).toHaveBeenCalledWith(
      "targets", "root", expect.any(Uint8Array)
    );
  });

  it("rejects a signed snapshot length above the configured metadata cap before fetching it", async () => {
    const trusted = makeTrustedAdapter();
    const calls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/2.root.json")) return new Response("not found", { status: 404 });
      if (url.endsWith("/timestamp.json")) {
        return json({ signed: { _type: "timestamp", version: 4, snapshotMeta: { version: 7, length: 4096 } } });
      }
      return new Response("unexpected URL", { status: 500 });
    }));
    const { store } = fakeTargetStore();
    const updater = new AsyncTufUpdater(
      trusted as unknown as AsyncTufTrustedStateAdapter,
      store,
      fence,
      {
        metadataBaseUrl: "https://example.test/metadata",
        targetBaseUrl: "https://example.test/targets",
        snapshotMaxLength: 1024
      }
    );

    await expect(updater.getTargetInfo("release.bin")).rejects.toThrow("declared length is invalid or exceeds");
    expect(calls).toEqual([
      "https://example.test/metadata/2.root.json",
      "https://example.test/metadata/timestamp.json"
    ]);
  });

  it("rejects invalid updater resource limits at construction", () => {
    const { store } = fakeTargetStore();
    const trusted = makeTrustedAdapter() as unknown as AsyncTufTrustedStateAdapter;
    expect(() => new AsyncTufUpdater(trusted, store, fence, {
      metadataBaseUrl: "https://example.test/metadata",
      targetBaseUrl: "https://example.test/targets",
      targetsMaxLength: Number.MAX_SAFE_INTEGER + 1
    })).toThrow("targetsMaxLength");
    expect(() => new AsyncTufUpdater(trusted, store, fence, {
      metadataBaseUrl: "https://example.test/metadata",
      targetBaseUrl: "https://example.test/targets",
      maxDelegations: -1
    })).toThrow("maxDelegations");
  });

  it("rejects a target larger than the configured staging bound before download", async () => {
    const trusted = makeTrustedAdapter();
    trusted.getRole = () => ({ signed: { targets: { "release.bin": targetInfo } } });
    trusted.setTimestamp({ signed: { version: 4, snapshotMeta: { version: 7, length: 2048 } } });
    trusted.setSnapshot({ signed: { version: 7, meta: {} } });
    const { store } = fakeTargetStore();
    const updater = new AsyncTufUpdater(
      trusted as unknown as AsyncTufTrustedStateAdapter,
      store,
      fence,
      {
        metadataBaseUrl: "https://example.test/metadata",
        targetBaseUrl: "https://example.test/targets",
        targetMaxLength: 2
      }
    );

    await expect(updater.getTargetInfo("release.bin")).rejects.toThrow("configured bounds");
    expect(store.beginTarget).not.toHaveBeenCalled();
  });

  it("streams a target into private storage and returns only its committed reader", async () => {
    const trusted = makeTrustedAdapter();
    trusted.getRole = () => ({ signed: { targets: { "release.bin": targetInfo } } });
    trusted.setTimestamp({ signed: { version: 4, snapshotMeta: { version: 7, length: 2048 } } });
    trusted.setSnapshot({ signed: { version: 7, meta: {} } });
    const { store, chunks, committed } = fakeTargetStore();
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/release.bin")) return new Response(payload);
      throw new Error("unexpected fetch " + url);
    }));
    const updater = new AsyncTufUpdater(
      trusted as unknown as AsyncTufTrustedStateAdapter,
      store,
      fence,
      { metadataBaseUrl: "https://example.test/metadata", targetBaseUrl: "https://example.test/targets" }
    );

    const reader = await updater.getTarget("release.bin");
    expect(reader).not.toBeNull();
    const result = await reader!.getReader().read();
    expect(Array.from(result.value!)).toEqual(Array.from(payload));
    expect(chunks).toHaveLength(1);
    expect(store.commitTarget).toHaveBeenCalledOnce();
    expect(store.openCommittedTarget).toHaveBeenCalledTimes(2);
    expect(committed.objectKey).toBe("immutable/release");
  });
});
