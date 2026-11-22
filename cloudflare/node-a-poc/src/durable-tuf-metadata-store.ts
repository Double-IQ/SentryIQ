import type { RunLock } from "./index";
import type {
  StoredTufMetadata,
  TufMetadataIdentity,
  TufMetadataStore,
  TufRunFence
} from "./tuf-storage-contract";

export interface DurableMetadataStateClient {
  readTufMetadata(
    roleName: string
  ): Promise<StoredTufMetadata | null> | StoredTufMetadata | null;

  commitVerifiedTufMetadata(
    roleName: string,
    expectedCurrent: TufMetadataIdentity | null,
    next: StoredTufMetadata,
    lock: RunLock
  ): Promise<TufMetadataIdentity> | TufMetadataIdentity;
}

/**
 * Concrete metadata-store adapter over the Node A Durable Object RPC surface.
 *
 * The Durable Object remains authoritative for compare-and-set, rollback,
 * root-rotation and active-fence enforcement. This class only translates the
 * explicit TUF storage contract; it does not perform TUF verification.
 */
export class DurableObjectTufMetadataStore implements TufMetadataStore {
  constructor(
    private readonly state: DurableMetadataStateClient,
    private readonly currentLock: () => RunLock
  ) {}

  async readRole(roleName: string): Promise<StoredTufMetadata | null> {
    return this.state.readTufMetadata(roleName);
  }

  async commitVerifiedRole(
    roleName: string,
    expectedCurrent: TufMetadataIdentity | null,
    next: StoredTufMetadata,
    fence: TufRunFence
  ): Promise<TufMetadataIdentity> {
    const lock = this.currentLock();
    if (
      fence.runId !== lock.runId ||
      fence.fence !== lock.fence ||
      fence.token !== lock.token
    ) {
      throw new Error("TUF storage fence does not match the active Node A run lock");
    }

    return this.state.commitVerifiedTufMetadata(
      roleName,
      expectedCurrent,
      next,
      lock
    );
  }
}
