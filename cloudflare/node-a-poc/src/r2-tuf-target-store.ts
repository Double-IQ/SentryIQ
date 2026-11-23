import { randomUUID } from "node:crypto";
import type { RunLock } from "./index";
import type {
  CommittedTufTarget,
  TufRunFence,
  TufTargetDescriptor,
  TufTargetStage,
  TufTargetStore
} from "./tuf-storage-contract";

export interface R2ObjectLike {
  readonly size: number;
  readonly body: ReadableStream<Uint8Array>;
}

export interface R2BucketLike {
  put(
    key: string,
    value: ReadableStream<Uint8Array>
  ): Promise<{ size: number } | null>;
  get(key: string): Promise<R2ObjectLike | null>;
  delete(key: string): Promise<void>;
}

export interface DurableTargetPointerClient {
  registerTufTargetStage(stageId: string, objectKey: string, fence: RunLock): Promise<void> | void;
  listStaleTufTargetStages(fence: RunLock, limit?: number): Promise<Array<{ stageId: string; objectKey: string; fence: number }>> | Array<{ stageId: string; objectKey: string; fence: number }>;
  deleteTufTargetStage(stageId: string, objectKey: string, fence: RunLock): Promise<void> | void;
  commitTufTargetPointer(
    descriptor: TufTargetDescriptor,
    stageId: string,
    objectKey: string,
    fence: RunLock
  ): Promise<CommittedTufTarget> | CommittedTufTarget;
  readTufTargetPointer(targetPath: string): Promise<CommittedTufTarget | null> | CommittedTufTarget | null;
}

interface ActiveUpload {
  readonly stage: TufTargetStage;
  readonly runFence: TufRunFence;
  readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  readonly upload: Promise<{ size: number } | null>;
}

/**
 * R2 streaming target store. Upload bytes flow through a TransformStream
 * directly into R2; only the stream's backpressure queue is buffered.
 * Durable Object pointer publication occurs after R2 confirms object length.
 */
export class R2TufTargetStore implements TufTargetStore {
  private readonly active = new Map<string, ActiveUpload>();

  constructor(
    private readonly bucket: R2BucketLike,
    private readonly state: DurableTargetPointerClient,
    private readonly currentLock: () => RunLock
  ) {}

  async beginTarget(
    descriptor: TufTargetDescriptor,
    fence: TufRunFence
  ): Promise<TufTargetStage> {
    const lock = this.currentLock();
    assertFenceMatchesLock(fence, lock);

    const stageId = randomUUID();
    const objectKey = "objects/" + stageId;
    const stage: TufTargetStage = {
      stageId,
      descriptor,
      objectKey,
      fence: fence.fence
    };
    await this.state.registerTufTargetStage(stageId, objectKey, lock);
    try {
      const channel = new TransformStream<Uint8Array, Uint8Array>();
      const writer = channel.writable.getWriter();
      const upload = this.bucket.put(objectKey, channel.readable);
      this.active.set(stageId, { stage, runFence: fence, writer, upload });
      return stage;
    } catch (error) {
      try { await this.state.deleteTufTargetStage(stageId, objectKey, this.currentLock()); } catch { /* future stale-stage sweep retries */ }
      throw error;
    }
  }

  async writeTargetChunk(stage: TufTargetStage, chunk: Uint8Array): Promise<void> {
    const upload = this.requireActive(stage);
    assertFenceMatchesLock(upload.runFence, this.currentLock());
    await upload.writer.write(chunk.slice());
  }

  async commitTarget(
    stage: TufTargetStage,
    fence: TufRunFence
  ): Promise<CommittedTufTarget> {
    const upload = this.requireActive(stage);
    assertFenceMatchesLock(fence, this.currentLock());
    if (stage.fence !== fence.fence) throw new Error("target stage fence does not match publication fence");

    try {
      await upload.writer.close();
      const stored = await upload.upload;
      if (!stored || stored.size !== stage.descriptor.length) {
        throw new Error("R2 staged target size does not match the verified TUF length");
      }
      const committed = await this.state.commitTufTargetPointer(
        stage.descriptor,
        stage.stageId,
        stage.objectKey,
        this.currentLock()
      );
      this.active.delete(stage.stageId);
      return committed;
    } catch (error) {
      this.active.delete(stage.stageId);
      try { await upload.writer.abort(error); } catch { /* preserve original failure */ }
      try { await upload.upload; } catch { /* upload may already have failed */ }
      await this.bucket.delete(stage.objectKey);
      try { await this.state.deleteTufTargetStage(stage.stageId, stage.objectKey, this.currentLock()); } catch { /* future stale-stage sweep retries */ }
      throw error;
    }
  }

  async openCommittedTarget(
    targetPath: string,
    expected?: TufTargetDescriptor
  ): Promise<ReadableStream<Uint8Array> | null> {
    const pointer = await this.state.readTufTargetPointer(targetPath);
    if (!pointer) return null;
    if (expected && !targetDescriptorMatches(pointer, expected)) return null;
    const object = await this.bucket.get(pointer.objectKey);
    if (!object) throw new Error("committed TUF target object is missing from R2");
    if (object.size !== pointer.length) {
      throw new Error("committed TUF target object length no longer matches its pointer");
    }
    return object.body;
  }

  async abortTarget(stage: TufTargetStage): Promise<void> {
    const upload = this.active.get(stage.stageId);
    this.active.delete(stage.stageId);
    if (upload) {
      try { await upload.writer.abort(); } catch { /* cleanup continues */ }
      try { await upload.upload; } catch { /* failed upload is expected during abort */ }
    }
    await this.bucket.delete(stage.objectKey);
    await this.state.deleteTufTargetStage(stage.stageId, stage.objectKey, this.currentLock());
  }

  async cleanupStaleStages(lock: RunLock, limit = 100): Promise<number> {
    const stale = await this.state.listStaleTufTargetStages(lock, limit);
    let removed = 0;
    for (const stage of stale) {
      await this.bucket.delete(stage.objectKey);
      await this.state.deleteTufTargetStage(stage.stageId, stage.objectKey, lock);
      removed += 1;
    }
    return removed;
  }

  private requireActive(stage: TufTargetStage): ActiveUpload {
    const active = this.active.get(stage.stageId);
    if (!active || active.stage.objectKey !== stage.objectKey ||
        active.stage.fence !== stage.fence) {
      throw new Error("TUF target stage is unknown, already completed, or has a mismatched identity");
    }
    return active;
  }
}

function assertFenceMatchesLock(fence: TufRunFence, lock: RunLock): void {
  if (fence.runId !== lock.runId || fence.fence !== lock.fence || fence.token !== lock.token) {
    throw new Error("TUF target storage fence does not match the active Node A run lock");
  }
}

function targetDescriptorMatches(
  actual: TufTargetDescriptor,
  expected: TufTargetDescriptor
): boolean {
  if (actual.targetPath !== expected.targetPath || actual.length !== expected.length) return false;
  const actualAlgorithms = Object.keys(actual.hashes).sort();
  const expectedAlgorithms = Object.keys(expected.hashes).sort();
  if (actualAlgorithms.length !== expectedAlgorithms.length) return false;
  return actualAlgorithms.every((algorithm, index) =>
    algorithm === expectedAlgorithms[index] &&
    actual.hashes[algorithm] === expected.hashes[algorithm]
  );
}
