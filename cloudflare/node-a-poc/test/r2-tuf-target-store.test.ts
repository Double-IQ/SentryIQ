import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { R2TufTargetStore } from "../src/r2-tuf-target-store";
import type { RunLock } from "../src/index";
import type {
  CommittedTufTarget,
  TufRunFence,
  TufTargetDescriptor
} from "../src/tuf-storage-contract";
import { stageVerifiedTufTarget } from "../src/verified-target-stream";

const bytes = new TextEncoder().encode("R2 staged target content");
const lock1: RunLock = {
  runId: "a".repeat(32), fence: 1, token: "b".repeat(64), expiresAt: Date.now() + 60_000
};
const lock2: RunLock = {
  runId: "c".repeat(32), fence: 2, token: "d".repeat(64), expiresAt: Date.now() + 60_000
};
const fence: TufRunFence = { runId: lock1.runId, fence: lock1.fence, token: lock1.token };
const descriptor: TufTargetDescriptor = {
  targetPath: "targets/release.bin",
  length: bytes.byteLength,
  hashes: { sha256: createHash("sha256").update(bytes).digest("hex") }
};

function readable(data: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(data.slice());
      controller.close();
    }
  });
}

class MemoryR2Bucket {
  readonly objects = new Map<string, Uint8Array>();

  async put(key: string, body: ReadableStream<Uint8Array>): Promise<{ size: number }> {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value.slice());
    }
    const data = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
    this.objects.set(key, new Uint8Array(data));
    return { size: data.byteLength };
  }

  async get(key: string) {
    const data = this.objects.get(key);
    return data ? { size: data.byteLength, body: readable(data) } : null;
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
}

function memoryPointers() {
  const pointers = new Map<string, CommittedTufTarget>();
  const stages = new Map<string, { objectKey: string; fence: number }>();
  const retired = new Set<string>();
  return {
    pointers,
    stages,
    retired,
    registerTufTargetStage(stageId: string, objectKey: string, lock: RunLock) {
      stages.set(stageId, { objectKey, fence: lock.fence });
    },
    listStaleTufTargetStages(lock: RunLock) {
      return [...stages.entries()]
        .filter(([, stage]) => stage.fence < lock.fence)
        .map(([stageId, stage]) => ({ stageId, objectKey: stage.objectKey, fence: stage.fence }));
    },
    deleteTufTargetStage(stageId: string, objectKey: string) {
      if (stages.get(stageId)?.objectKey === objectKey) stages.delete(stageId);
    },
    listRetiredTufTargetObjects() { return [...retired]; },
    deleteRetiredTufTargetObject(objectKey: string) { retired.delete(objectKey); },
    async commitTufTargetPointer(
      target: TufTargetDescriptor,
      stageId: string,
      objectKey: string,
      lock: RunLock
    ): Promise<CommittedTufTarget> {
      if (stages.get(stageId)?.objectKey !== objectKey) throw new Error("staging record missing");
      const previous = pointers.get(target.targetPath);
      if (previous && previous.objectKey !== objectKey) retired.add(previous.objectKey);
      const pointer = {
        ...target,
        objectKey,
        fence: lock.fence,
        committedAt: Date.now()
      };
      pointers.set(target.targetPath, pointer);
      stages.delete(stageId);
      return pointer;
    },
    readTufTargetPointer(targetPath: string) {
      return pointers.get(targetPath) ?? null;
    }
  };
}

describe("R2 TUF target store", () => {
  it("streams to R2 privately and publishes the pointer only after verified commit", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const store = new R2TufTargetStore(bucket, pointers, () => lock1);

    const committed = await stageVerifiedTufTarget(store, {
      descriptor,
      body: readable(bytes),
      fence
    });

    expect(committed.objectKey).toMatch(/^objects\/[a-f0-9-]{36}$/);
    expect(pointers.pointers.get(descriptor.targetPath)).toEqual(committed);
    expect(bucket.objects.get(committed.objectKey)).toEqual(bytes);

    const reader = await store.openCommittedTarget(descriptor.targetPath);
    expect(reader).not.toBeNull();
    const result = await reader!.getReader().read();
    expect(Array.from(result.value!)).toEqual(Array.from(bytes));
  });

  it("reconciles a lost Durable Object publication response without deleting a committed object", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const originalCommit = pointers.commitTufTargetPointer.bind(pointers);
    pointers.commitTufTargetPointer = async (...args) => {
      await originalCommit(...args);
      throw new Error("simulated lost DO RPC response after commit");
    };
    const store = new R2TufTargetStore(bucket, pointers, () => lock1);

    const committed = await stageVerifiedTufTarget(store, {
      descriptor,
      body: readable(bytes),
      fence
    });

    expect(committed.objectKey.startsWith("objects/")).toBe(true);
    expect(pointers.pointers.get(descriptor.targetPath)?.objectKey).toBe(committed.objectKey);
    expect(bucket.objects.has(committed.objectKey)).toBe(true);
  });

  it("preserves the staged R2 object when publication outcome cannot be read", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const originalCommit = pointers.commitTufTargetPointer.bind(pointers);
    pointers.commitTufTargetPointer = async (...args) => {
      await originalCommit(...args);
      throw new Error("simulated lost DO RPC response after commit");
    };
    pointers.readTufTargetPointer = () => { throw new Error("simulated DO read outage"); };
    const store = new R2TufTargetStore(bucket, pointers, () => lock1);

    await expect(stageVerifiedTufTarget(store, {
      descriptor,
      body: readable(bytes),
      fence
    })).rejects.toMatchObject({ name: "TufTargetCommitAmbiguousError" });

    const committed = [...pointers.pointers.values()][0];
    expect(committed).toBeDefined();
    expect(bucket.objects.has(committed.objectKey)).toBe(true);
  });

  it("garbage-collects superseded immutable R2 objects after pointer replacement", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const oldKey = "objects/77777777-7777-4777-8777-777777777777";
    const newKey = "objects/88888888-8888-4888-8888-888888888888";
    pointers.pointers.set(descriptor.targetPath, {
      ...descriptor, objectKey: oldKey, fence: lock1.fence, committedAt: 1
    });
    bucket.objects.set(oldKey, bytes.slice());
    const stageId = "99999999-9999-4999-8999-999999999999";
    pointers.registerTufTargetStage(stageId, newKey, lock2);
    const replacementStore = new R2TufTargetStore(bucket, pointers, () => lock2);

    await pointers.commitTufTargetPointer(descriptor, stageId, newKey, lock2);
    expect(pointers.listRetiredTufTargetObjects()).toEqual([oldKey]);
    await expect(replacementStore.cleanupRetiredObjects(lock2)).resolves.toBe(1);

    expect(bucket.objects.has(oldKey)).toBe(false);
    expect(pointers.listRetiredTufTargetObjects()).toEqual([]);
  });

  it("enforces the 24-hour reader grace period before retired-object garbage collection", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const listRetired = vi.fn(async () => []);
    pointers.listRetiredTufTargetObjects = listRetired;
    const store = new R2TufTargetStore(bucket, pointers, () => lock1);

    await expect(store.cleanupRetiredObjects(lock1)).resolves.toBe(0);

    expect(listRetired).toHaveBeenCalledOnce();
    expect(listRetired).toHaveBeenCalledWith(lock1, 100, 24 * 60 * 60 * 1000);
  });

  it("cleans crash-orphaned private R2 stages after a newer fencing epoch takes over", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const stageId = "33333333-3333-4333-8333-333333333333";
    const objectKey = "objects/44444444-4444-4444-8444-444444444444";
    pointers.registerTufTargetStage(stageId, objectKey, lock1);
    bucket.objects.set(objectKey, bytes.slice());

    const replacementStore = new R2TufTargetStore(bucket, pointers, () => lock2);
    await expect(replacementStore.cleanupStaleStages(lock2)).resolves.toBe(1);

    expect(bucket.objects.has(objectKey)).toBe(false);
    expect(pointers.stages.has(stageId)).toBe(false);
  });

  it("treats a committed pointer from an older TUF descriptor as a cache miss", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const objectKey = "objects/old-target-version";
    bucket.objects.set(objectKey, bytes.slice());
    pointers.pointers.set(descriptor.targetPath, {
      ...descriptor,
      objectKey,
      fence: lock1.fence,
      committedAt: 1
    });
    const store = new R2TufTargetStore(bucket, pointers, () => lock1);
    const currentDescriptor: TufTargetDescriptor = {
      ...descriptor,
      hashes: { sha256: "0".repeat(64) }
    };

    await expect(
      store.openCommittedTarget(descriptor.targetPath, currentDescriptor)
    ).resolves.toBeNull();
    await expect(store.openCommittedTarget(descriptor.targetPath)).resolves.not.toBeNull();
  });

  it("treats missing or truncated immutable R2 objects as cache misses", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    const objectKey = "objects/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    pointers.pointers.set(descriptor.targetPath, {
      ...descriptor, objectKey, fence: lock1.fence, committedAt: 1
    });
    const store = new R2TufTargetStore(bucket, pointers, () => lock1);

    await expect(store.openCommittedTarget(descriptor.targetPath, descriptor)).resolves.toBeNull();
    bucket.objects.set(objectKey, bytes.slice(0, bytes.byteLength - 1));
    await expect(store.openCommittedTarget(descriptor.targetPath, descriptor)).resolves.toBeNull();
    bucket.objects.set(objectKey, bytes.slice());
    await expect(store.openCommittedTarget(descriptor.targetPath, descriptor)).resolves.not.toBeNull();
  });

  it("stops accepting target chunks immediately after lease takeover", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    let activeLock = lock1;
    const store = new R2TufTargetStore(bucket, pointers, () => activeLock);
    const stage = await store.beginTarget(descriptor, fence);
    activeLock = lock2;

    await expect(store.writeTargetChunk(stage, bytes)).rejects.toThrow(
      "does not match the active Node A run lock"
    );
    await store.abortTarget(stage);
    expect(pointers.pointers.size).toBe(0);
    expect(bucket.objects.size).toBe(0);
  });

  it("rejects stale-owner publication and deletes the private R2 object", async () => {
    const bucket = new MemoryR2Bucket();
    const pointers = memoryPointers();
    let activeLock = lock1;
    const store = new R2TufTargetStore(bucket, pointers, () => activeLock);
    const originalWrite = store.writeTargetChunk.bind(store);
    store.writeTargetChunk = async (stage, chunk) => {
      await originalWrite(stage, chunk);
      activeLock = lock2;
    };

    await expect(stageVerifiedTufTarget(store, {
      descriptor,
      body: readable(bytes),
      fence
    })).rejects.toThrow("does not match the active Node A run lock");

    expect(pointers.pointers.size).toBe(0);
    expect(bucket.objects.size).toBe(0);
  });
});
