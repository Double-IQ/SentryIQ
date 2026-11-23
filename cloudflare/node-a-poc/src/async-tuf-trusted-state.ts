import type {
  StoredTufMetadata,
  TufMetadataIdentity,
  TufMetadataStore,
  TufRunFence
} from "./tuf-storage-contract";
import { FencedTufMetadataSession } from "./fenced-tuf-metadata-session";

/**
 * Structural surface of tuf-js 6.0.3 TrustedMetadataStore.
 *
 * The pinned upstream implementation remains responsible for all TUF
 * cryptographic and semantic validation. This adapter only sequences its
 * mutating acceptance methods with durable fenced commits.
 */
export interface PinnedTufTrustedMetadataStore {
  updateRoot(bytes: Uint8Array): void;
  updateTimestamp(bytes: Uint8Array): void;
  updateSnapshot(bytes: Uint8Array): void;
  updateDelegatedTargets(roleName: string, bytes: Uint8Array): void;
}

export type PinnedTufTrustedMetadataStoreFactory = (
  trustedRootBytes: Uint8Array
) => PinnedTufTrustedMetadataStore;

export class AsyncTufTrustedStateAdapter {
  private operationQueue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly trusted: PinnedTufTrustedMetadataStore,
    private readonly session: FencedTufMetadataSession,
    private readonly metadata: TufMetadataStore
  ) {}

  /**
   * Construct the actual pinned upstream trusted set from the explicit
   * durable root. No path, filesystem cache, or implicit root lookup is used.
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
        // The upstream constructor verifies the supplied root and creates
        // the trusted set. It is invoked for durable restore and bootstrap.
        trusted = createTrustedStore(rootBytes);
      }
    );
    if (!trusted) throw new Error("pinned tuf-js trusted metadata store was not initialized");
    return new AsyncTufTrustedStateAdapter(trusted, session, metadata);
  }

  refreshRoot(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    return this.accept("root", bytes, () => this.trusted.updateRoot(bytes));
  }

  refreshTimestamp(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    return this.accept("timestamp", bytes, () => this.trusted.updateTimestamp(bytes));
  }

  refreshSnapshot(bytes: Uint8Array): Promise<TufMetadataIdentity> {
    return this.accept("snapshot", bytes, () => this.trusted.updateSnapshot(bytes));
  }

  refreshDelegatedTargets(roleName: string, bytes: Uint8Array): Promise<TufMetadataIdentity> {
    if (!roleName || roleName === "root" || roleName === "timestamp" || roleName === "snapshot") {
      return Promise.reject(new Error("delegated TUF role name is invalid"));
    }
    return this.accept(roleName, bytes, () => this.trusted.updateDelegatedTargets(roleName, bytes));
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
        (bytes) => this.trusted.updateRoot(bytes),
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
    upstreamAccept: () => void
  ): Promise<TufMetadataIdentity> {
    return this.serialize(async () => {
      // Read the CAS identity inside the same adapter queue as acceptance.
      // Concurrent refresh calls therefore cannot race on a stale identity.
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
