import { Buffer } from "node:buffer";
import type {
  StoredTufMetadata,
  TufMetadataIdentity,
  TufMetadataStore,
  TufRunFence
} from "./tuf-storage-contract";
import { FencedTufMetadataSession } from "./fenced-tuf-metadata-session";

/**
 * Structural surface of tuf-js 6.0.3 TrustedMetadataStore. The parameter
 * order deliberately matches upstream: updateDelegatedTargets(bytes, role,
 * delegator). Buffer is required because upstream decodes metadata via
 * Buffer.toString("utf8").
 */
export interface PinnedTufRoleMetadata {
  signed: {
    version: number;
    consistentSnapshot?: boolean;
    snapshotMeta?: { version: number; length?: number };
    meta?: Record<string, { version: number; length?: number }>;
    targets?: Record<string, unknown>;
    delegations?: {
      roles?: Array<{ name?: string }>;
      rolesForTarget?: (targetPath: string) => Array<{ role: string; terminating: boolean }>;
    };
  };
}

export interface PinnedTufTrustedMetadataStore {
  readonly root: PinnedTufRoleMetadata;
  readonly timestamp?: PinnedTufRoleMetadata;
  readonly snapshot?: PinnedTufRoleMetadata;
  updateRoot(bytes: Buffer): unknown;
  updateTimestamp(bytes: Buffer): unknown;
  updateSnapshot(bytes: Buffer, trusted?: boolean): unknown;
  updateDelegatedTargets(bytes: Buffer, roleName: string, delegatorName: string): unknown;
  getRole(roleName: string): PinnedTufRoleMetadata | undefined;
}

export type PinnedTufTrustedMetadataStoreFactory = (
  trustedRootBytes: Buffer
) => PinnedTufTrustedMetadataStore;

export class AsyncTufTrustedStateAdapter {
  private operationQueue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly trusted: PinnedTufTrustedMetadataStore,
    private readonly session: FencedTufMetadataSession,
    private readonly metadata: TufMetadataStore
  ) {}

  /**
   * Construct the upstream trusted set from the explicit durable root, then
   * replay durable roles through upstream verification in dependency order.
   * No path, filesystem cache, or implicit root lookup is used.
   */
  static async create(
    metadata: TufMetadataStore,
    fence: TufRunFence,
    bootstrapRoot: Uint8Array,
    createTrustedStore: PinnedTufTrustedMetadataStoreFactory
  ): Promise<AsyncTufTrustedStateAdapter> {
    let trusted: PinnedTufTrustedMetadataStore | undefined;
    const { session } = await FencedTufMetadataSession.create(
      metadata,
      fence,
      bootstrapRoot,
      (rootBytes) => {
        trusted = createTrustedStore(Buffer.from(rootBytes));
      }
    );
    if (!trusted) throw new Error("pinned tuf-js trusted metadata store was not initialized");

    // Restore timestamp first so the upstream verifier retains rollback
    // protection across process restarts. Snapshot and targets are loaded only
    // after the next timestamp refresh, matching the TUF client workflow.
    const timestamp = await metadata.readRole("timestamp");
    if (timestamp) {
      await assertStoredRoleIdentity("timestamp", timestamp);
      trusted.updateTimestamp(Buffer.from(timestamp.data));
    }

    return new AsyncTufTrustedStateAdapter(trusted, session, metadata);
  }

  get root(): PinnedTufRoleMetadata {
    return this.trusted.root;
  }

  get timestamp(): PinnedTufRoleMetadata | undefined {
    return this.trusted.timestamp;
  }

  get snapshot(): PinnedTufRoleMetadata | undefined {
    return this.trusted.snapshot;
  }

  getRole(roleName: string): PinnedTufRoleMetadata | undefined {
    return this.trusted.getRole(roleName);
  }

  refreshRoot(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    return this.accept("root", bytes, () => this.trusted.updateRoot(Buffer.from(bytes)));
  }

  refreshTimestamp(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    const incomingVersion = readSignedVersion(bytes);
    if (this.trusted.timestamp?.signed.version === incomingVersion) {
      return this.metadata.readRole("timestamp").then((current) => {
        if (!current) throw new Error("trusted timestamp exists without a durable record");
        return { version: current.version, sha256: current.sha256 };
      });
    }
    return this.accept("timestamp", bytes, () => this.trusted.updateTimestamp(Buffer.from(bytes)));
  }

  refreshSnapshot(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    return this.accept("snapshot", bytes, () => this.trusted.updateSnapshot(Buffer.from(bytes)));
  }

  refreshDelegatedTargets(
    roleName: string,
    delegatorName: string,
    bytes: Uint8Array
  ): Promise<TufMetadataIdentity> {
    if (!roleName || roleName === "root" || roleName === "timestamp" ||
        roleName === "snapshot" || !delegatorName) {
      return Promise.reject(new Error("delegated TUF role or delegator name is invalid"));
    }
    return this.accept(roleName, bytes, () =>
      this.trusted.updateDelegatedTargets(Buffer.from(bytes), roleName, delegatorName)
    );
  }

  rotateRoots(
    firstVersion: number,
    maxRotations: number,
    fetchRoot: (version: number) => Promise<Uint8Array>
  ): Promise<TufMetadataIdentity> {
    return this.serialize(async () => {
      const current: StoredTufMetadata | null = await this.metadata.readRole("root");
      if (!current) throw new Error("durable TUF root is missing; recreate the trusted-state adapter");
      return this.session.rotateRoots(
        firstVersion,
        maxRotations,
        fetchRoot,
        (bytes) => this.trusted.updateRoot(Buffer.from(bytes)),
        { version: current.version, sha256: current.sha256 }
      );
    });
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.operationQueue.then(operation);
    this.operationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  private accept(
    roleName: string,
    bytes: Uint8Array,
    upstreamAccept: () => unknown
  ): Promise<TufMetadataIdentity> {
    return this.serialize(async () => {
      const current: StoredTufMetadata | null = await this.metadata.readRole(roleName);
      const expectedCurrent = current
        ? { version: current.version, sha256: current.sha256 }
        : null;

      return this.session.acceptVerifiedRole(roleName, bytes, {
        expectedCurrent,
        acceptIntoTrustedSet: upstreamAccept
      });
    });
  }
}

function findDelegator(
  trusted: PinnedTufTrustedMetadataStore,
  loadedRoleNames: Set<string>,
  roleName: string
): string | undefined {
  for (const parentName of loadedRoleNames) {
    const parent = trusted.getRole(parentName);
    const delegates = parent?.signed?.delegations?.roles ?? [];
    if (delegates.some((delegation) => delegation.name === roleName)) {
      return parentName;
    }
  }
  return undefined;
}

function parseSnapshotRoleNames(bytes: Uint8Array): string[] {
  let envelope: { signed?: { meta?: Record<string, unknown> } };
  try {
    envelope = JSON.parse(new TextDecoder().decode(bytes)) as typeof envelope;
  } catch {
    throw new Error("durable TUF snapshot is not valid JSON");
  }
  const meta = envelope.signed?.meta;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    throw new Error("durable TUF snapshot has no metadata index");
  }
  return Object.keys(meta)
    .filter((fileName) => fileName.endsWith(".json"))
    .map((fileName) => fileName.slice(0, -5));
}

async function assertStoredRoleIdentity(
  roleName: string,
  stored: StoredTufMetadata
): Promise<void> {
  const digest = await crypto.subtle.digest("SHA-256", stored.data);
  const sha256 = Array.from(new Uint8Array(digest), (value) =>
    value.toString(16).padStart(2, "0")
  ).join("");
  if (sha256 !== stored.sha256) {
    throw new Error("durable TUF role digest mismatch during trusted-state recovery: " + roleName);
  }
  let envelope: { signed?: { _type?: unknown; type?: unknown; version?: unknown } };
  try {
    envelope = JSON.parse(new TextDecoder().decode(stored.data)) as typeof envelope;
  } catch {
    throw new Error("durable TUF role is not valid JSON during recovery: " + roleName);
  }
  const expectedType = roleName === "root" || roleName === "timestamp" || roleName === "snapshot"
    ? roleName
    : "targets";
  if (!envelope.signed ||
      (envelope.signed._type ?? envelope.signed.type) !== expectedType ||
      envelope.signed.version !== stored.version) {
    throw new Error("durable TUF role identity mismatch during recovery: " + roleName);
  }
}

function readSignedVersion(bytes: Uint8Array): number {
  let envelope: { signed?: { version?: unknown } };
  try {
    envelope = JSON.parse(new TextDecoder().decode(bytes)) as typeof envelope;
  } catch {
    throw new Error("TUF metadata is not valid JSON");
  }
  if (!Number.isSafeInteger(envelope.signed?.version) || (envelope.signed!.version as number) < 1) {
    throw new Error("TUF metadata version is invalid");
  }
  return envelope.signed!.version as number;
}
