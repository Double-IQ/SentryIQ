/**
 * Explicit persistence boundary for the Node A TUF client integration.
 *
 * The async Node A updater uses this explicit boundary. Implementations must
 * never fall back to node:fs for durable metadata or verified targets. Durable
 * Objects own metadata and target-pointer commits; object storage owns bytes.
 */

export interface TufMetadataIdentity {
  readonly version: number;
  readonly sha256: string;
}

export interface StoredTufMetadata extends TufMetadataIdentity {
  /** Exact original bytes consumed by the upstream TUF verifier. */
  readonly data: Uint8Array;
}

export interface TufRunFence {
  readonly runId: string;
  readonly fence: number;
  /** Opaque bearer token; persist only its SHA-256 hash. */
  readonly token: string;
}

/**
 * A durable metadata read failed. Upstream recovery may fall back to remote
 * metadata only for a missing/corrupt cached record, never for this error.
 */
export class TufMetadataReadError extends Error {
  readonly code = "TUF_METADATA_READ_FAILED";
  readonly causeValue: unknown;

  constructor(message: string, causeValue?: unknown) {
    super(message);
    this.name = "TufMetadataReadError";
    this.causeValue = causeValue;
  }
}

export interface TufMetadataStore {
  readRole(roleName: string): Promise<StoredTufMetadata | null>;
  /** Enumerate durable role names for verified trusted-state reconstruction. */
  listRoles(): Promise<string[]>;

  /**
   * Compare-and-set one already-upstream-verified role version.
   * Must re-check the live run fence in the same transaction as the write.
   * Root updates are one version at a time; same-version/different-byte
   * replacement and rollback must fail closed.
   */
  commitVerifiedRole(
    roleName: string,
    expectedCurrent: TufMetadataIdentity | null,
    next: StoredTufMetadata,
    fence: TufRunFence
  ): Promise<TufMetadataIdentity>;
}

/**
 * The pointer-publication RPC failed and its commit outcome could not be
 * determined by reading durable state. Preserve the staged object: deleting
 * it could destroy a pointer whose transaction actually committed.
 */
export class TufTargetCommitAmbiguousError extends Error {
  readonly causeValue: unknown;

  constructor(message: string, causeValue?: unknown) {
    super(message);
    this.name = "TufTargetCommitAmbiguousError";
    this.causeValue = causeValue;
  }
}

export interface TufTargetDescriptor {
  readonly targetPath: string;
  readonly length: number;
  /** Every hash declared by the verified TUF target metadata; do not narrow to SHA-256. */
  readonly hashes: Readonly<Record<string, string>>;
}

export interface TufTargetStage {
  readonly stageId: string;
  readonly descriptor: TufTargetDescriptor;
  readonly objectKey: string;
  readonly fence: number;
}

export interface CommittedTufTarget extends TufTargetDescriptor {
  readonly objectKey: string;
  readonly fence: number;
  readonly committedAt: number;
}

export interface TufTargetStore {
  /**
   * Allocate a private, unreachable staging object. This must not publish a
   * target pointer or make the object visible to readers.
   */
  beginTarget(
    descriptor: TufTargetDescriptor,
    fence: TufRunFence
  ): Promise<TufTargetStage>;

  /** Stream bytes to the staging object; implementations may use R2 multipart. */
  writeTargetChunk(stage: TufTargetStage, chunk: Uint8Array): Promise<void>;

  /**
   * Confirm completed object length and every declared target digest, then publish its immutable
   * pointer in a short fenced Durable Object transaction. A stale owner may
   * leave an orphaned object but must never publish it.
   */
  commitTarget(
    stage: TufTargetStage,
    fence: TufRunFence
  ): Promise<CommittedTufTarget>;

  /**
   * Readers resolve committed pointers only. When an expected descriptor is
   * supplied, stale pointers for an older TUF target version are cache misses.
   */
  openCommittedTarget(
    targetPath: string,
    expected?: TufTargetDescriptor
  ): Promise<ReadableStream<Uint8Array> | null>;

  /** Best-effort cleanup for a stage that was never committed. */
  abortTarget(stage: TufTargetStage): Promise<void>;
}

/**
 * Composite boundary intended for an explicit tuf-js storage adapter.
 * Signature, threshold, expiry, delegation and snapshot-linkage validation
 * remain upstream TUF responsibilities and must complete before commits.
 */
export interface TufStorageAdapter extends TufMetadataStore, TufTargetStore {}
