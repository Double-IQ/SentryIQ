import { createHash } from "node:crypto";
import type {
  CommittedTufTarget,
  TufRunFence,
  TufTargetDescriptor,
  TufTargetStore
} from "./tuf-storage-contract";

export class TufTargetIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TufTargetIntegrityError";
  }
}

export interface VerifiedTargetInput {
  readonly descriptor: TufTargetDescriptor;
  readonly body: ReadableStream<Uint8Array>;
  readonly fence: TufRunFence;
}

const MAX_TARGET_LENGTH = Number.MAX_SAFE_INTEGER;

/**
 * Streams a TUF target into private storage with backpressure.
 *
 * The target remains unreachable until the store's fenced commitTarget call.
 * No whole-object buffering or filesystem/temp-file path is used here.
 */
export async function stageVerifiedTufTarget(
  store: TufTargetStore,
  input: VerifiedTargetInput
): Promise<CommittedTufTarget> {
  const { descriptor, body, fence } = input;
  validateDescriptor(descriptor);

  const stage = await store.beginTarget(descriptor, fence);
  const reader = body.getReader();
  const hashers = new Map<string, ReturnType<typeof createHash>>();
  for (const algorithm of Object.keys(descriptor.hashes)) {
    hashers.set(algorithm, createHash(algorithm));
  }

  let received = 0;
  let completed = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new TufTargetIntegrityError("target stream yielded a non-byte chunk");
      }
      if (value.byteLength === 0) continue;
      received += value.byteLength;
      if (!Number.isSafeInteger(received) || received > descriptor.length) {
        throw new TufTargetIntegrityError("target stream exceeded its TUF-declared length");
      }
      for (const hasher of hashers.values()) hasher.update(value);
      // Await each write to preserve bounded memory and apply backpressure.
      await store.writeTargetChunk(stage, value);
    }

    if (received !== descriptor.length) {
      throw new TufTargetIntegrityError(
        `target length mismatch: expected ${descriptor.length}, received ${received}`
      );
    }

    for (const [algorithm, expected] of Object.entries(descriptor.hashes)) {
      const actual = hashers.get(algorithm)!.digest("hex");
      if (actual !== expected) {
        throw new TufTargetIntegrityError(`target ${algorithm} digest mismatch`);
      }
    }

    const committed = await store.commitTarget(stage, fence);
    completed = true;
    return committed;
  } catch (error) {
    try {
      await reader.cancel(error);
    } catch {
      // Preserve the integrity, stream, or durable-store failure.
    }
    throw error;
  } finally {
    if (!completed) {
      try {
        await store.abortTarget(stage);
      } catch {
        // Cleanup is best-effort; the stage is never reader-visible.
      }
    }
    reader.releaseLock();
  }
}

function validateDescriptor(descriptor: TufTargetDescriptor): void {
  if (!descriptor || typeof descriptor.targetPath !== "string" ||
      descriptor.targetPath.length === 0 || descriptor.targetPath.length > 1024 ||
      descriptor.targetPath.startsWith("/") || descriptor.targetPath.split("/").some(
        (part) => part === "" || part === "." || part === ".."
      )) {
    throw new TufTargetIntegrityError("TUF target path is invalid");
  }
  if (!Number.isSafeInteger(descriptor.length) || descriptor.length < 0 ||
      descriptor.length > MAX_TARGET_LENGTH) {
    throw new TufTargetIntegrityError("TUF target length is invalid");
  }
  const entries = Object.entries(descriptor.hashes);
  if (entries.length === 0) {
    throw new TufTargetIntegrityError("TUF target metadata declares no digests");
  }
  for (const [algorithm, digest] of entries) {
    let expectedLength: number;
    try {
      expectedLength = createHash(algorithm).digest("hex").length;
    } catch {
      throw new TufTargetIntegrityError(`unsupported TUF target digest algorithm: ${algorithm}`);
    }
    if (typeof digest !== "string" || !new RegExp(`^[a-f0-9]{${expectedLength}}$`).test(digest)) {
      throw new TufTargetIntegrityError(`TUF target ${algorithm} digest is malformed`);
    }
  }
}
