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

    const roleNames = await metadata.listRoles();
    if (!roleNames.includes("root")) {
      throw new Error("durable TUF role index is missing the trusted root");
    }

    const timestamp = roleNames.includes("timestamp")
      ? await metadata.readRole("timestamp")
      : null;
    if (timestamp) {
      await assertStoredRoleIdentity("timestamp", timestamp);
      trusted.updateTimestamp(Buffer.from(timestamp.data));
    }

    const snapshot = roleNames.includes("snapshot")
      ? await metadata.readRole("snapshot")
      : null;
    if (snapshot) {
      await assertStoredRoleIdentity("snapshot", snapshot);
      trusted.updateSnapshot(Buffer.from(snapshot.data));
    }

    if (snapshot) {
      const snapshotMeta = parseSnapshotRoleNames(snapshot.data);
      const pending = new Set(
        snapshotMeta.filter((name) => name !== "root" &&
          name !== "timestamp" && name !== "snapshot" && roleNames.includes(name))
      );
      const loaded = new Set<string>(["root"]);
      while (pending.size > 0) {
        let progressed = false;
        for (const roleName of [...pending]) {
          const delegatorName = roleName === "targets"
            ? "root"
            : findDelegator(trusted, loaded, roleName);
          if (!delegatorName) continue;

          const stored = await metadata.readRole(roleName);
          if (!stored) {
            throw new Error("durable delegated TUF role disappeared during recovery: " + roleName);
          }
          await assertStoredRoleIdentity(roleName, stored);
          trusted.updateDelegatedTargets(Buffer.from(stored.data), roleName, delegatorName);
          loaded.add(roleName);
          pending.delete(roleName);
          progressed = true;
        }
        if (!progressed) {
          throw new Error(
            "durable delegated TUF roles cannot be rehydrated from verified delegation parents: " +
            [...pending].join(", ")
          );
        }
      }
    }

    return new AsyncTufTrustedStateAdapter(trusted, session, metadata);
  }

  refreshRoot(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    return this.accept("root", bytes, () => this.trusted.updateRoot(Buffer.from(bytes)));
  }

  refreshTimestamp(bytes: Uint8Array): Promise<TufMetadataIdentity> {
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
