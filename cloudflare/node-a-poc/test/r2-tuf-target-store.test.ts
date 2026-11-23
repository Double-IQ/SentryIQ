import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
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
  return {
    pointers,
    async commitTufTargetPointer(
      target: TufTargetDescriptor,
      objectKey: string,
      lock: RunLock
    ): Promise<CommittedTufTarget> {
      const pointer = {
        ...target,
        objectKey,
        fence: lock.fence,
        committedAt: Date.now()
      };
      pointers.set(target.targetPath, pointer);
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
