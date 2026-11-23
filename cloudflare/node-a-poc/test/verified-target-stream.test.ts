import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type {
  CommittedTufTarget,
  TufRunFence,
  TufTargetDescriptor,
  TufTargetStage,
  TufTargetStore
} from "../src/tuf-storage-contract";
import {
  stageVerifiedTufTarget,
  TufTargetIntegrityError
} from "../src/verified-target-stream";

const fence: TufRunFence = { runId: "a".repeat(32), fence: 7, token: "b".repeat(64) };
const bytes = new TextEncoder().encode("verified target payload");

function descriptor(data = bytes): TufTargetDescriptor {
  return {
    targetPath: "targets/release.bundle",
    length: data.byteLength,
    hashes: {
      sha256: createHash("sha256").update(data).digest("hex"),
      sha512: createHash("sha512").update(data).digest("hex")
    }
  };
}

function stream(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    }
  });
}

function fakeStore() {
  const stage: TufTargetStage = {
    stageId: "stage-1",
    descriptor: descriptor(),
    objectKey: "private/stage-1",
    fence: fence.fence
  };
  const committed: CommittedTufTarget = {
    ...descriptor(),
    objectKey: "immutable/sha256",
    fence: fence.fence,
    committedAt: 123
  };
  const chunks: Uint8Array[] = [];
  const store: TufTargetStore = {
    beginTarget: vi.fn(async () => stage),
    writeTargetChunk: vi.fn(async (_stage, chunk) => { chunks.push(chunk.slice()); }),
    commitTarget: vi.fn(async () => committed),
    openCommittedTarget: vi.fn(async () => null),
    abortTarget: vi.fn(async () => undefined)
  };
  return { store, chunks, committed };
}

describe("streaming TUF target verification", () => {
  it("streams bounded chunks, checks every declared digest, then publishes", async () => {
    const { store, chunks, committed } = fakeStore();
    const split = Math.floor(bytes.byteLength / 2);
    const result = await stageVerifiedTufTarget(store, {
      descriptor: descriptor(),
      body: stream([bytes.slice(0, split), bytes.slice(split)]),
      fence
    });

    expect(result).toEqual(committed);
    expect(Buffer.concat(chunks).equals(Buffer.from(bytes))).toBe(true);
    expect(store.writeTargetChunk).toHaveBeenCalledTimes(2);
    expect(store.commitTarget).toHaveBeenCalledTimes(1);
    expect(store.abortTarget).not.toHaveBeenCalled();
  });

  it("aborts private staging when the stream exceeds the declared length", async () => {
    const { store } = fakeStore();
    await expect(stageVerifiedTufTarget(store, {
      descriptor: descriptor(),
      body: stream([bytes, new Uint8Array([1])]),
      fence
    })).rejects.toBeInstanceOf(TufTargetIntegrityError);

    expect(store.commitTarget).not.toHaveBeenCalled();
    expect(store.abortTarget).toHaveBeenCalledTimes(1);
  });

  it("aborts private staging when the stream is shorter than declared", async () => {
    const { store } = fakeStore();
    await expect(stageVerifiedTufTarget(store, {
      descriptor: descriptor(),
      body: stream([bytes.slice(0, -1)]),
      fence
    })).rejects.toThrow("target length mismatch");

    expect(store.commitTarget).not.toHaveBeenCalled();
    expect(store.abortTarget).toHaveBeenCalledTimes(1);
  });

  it("aborts private staging when any declared TUF digest fails", async () => {
    const { store } = fakeStore();
    const bad = { ...descriptor(), hashes: { ...descriptor().hashes, sha512: "0".repeat(128) } };
    await expect(stageVerifiedTufTarget(store, {
      descriptor: bad,
      body: stream([bytes]),
      fence
    })).rejects.toThrow("sha512 digest mismatch");

    expect(store.commitTarget).not.toHaveBeenCalled();
    expect(store.abortTarget).toHaveBeenCalledTimes(1);
  });

  it("does not create a stage for unsupported or malformed digest metadata", async () => {
    const { store } = fakeStore();
    await expect(stageVerifiedTufTarget(store, {
      descriptor: { ...descriptor(), hashes: { sha999: "00" } },
      body: stream([bytes]),
      fence
    })).rejects.toThrow("unsupported TUF target digest algorithm");

    expect(store.beginTarget).not.toHaveBeenCalled();
  });

  it("aborts private staging when the input stream is already locked", async () => {
    const { store } = fakeStore();
    const body = stream([bytes]);
    const heldReader = body.getReader();
    await expect(stageVerifiedTufTarget(store, {
      descriptor: descriptor(),
      body,
      fence
    })).rejects.toThrow();

    expect(store.commitTarget).not.toHaveBeenCalled();
    expect(store.abortTarget).toHaveBeenCalledTimes(1);
    heldReader.releaseLock();
  });

  it("aborts private staging when the durable chunk write fails", async () => {
    const { store } = fakeStore();
    vi.mocked(store.writeTargetChunk).mockRejectedValueOnce(new Error("R2 unavailable"));
    await expect(stageVerifiedTufTarget(store, {
      descriptor: descriptor(),
      body: stream([bytes]),
      fence
    })).rejects.toThrow("R2 unavailable");

    expect(store.commitTarget).not.toHaveBeenCalled();
    expect(store.abortTarget).toHaveBeenCalledTimes(1);
  });
});
