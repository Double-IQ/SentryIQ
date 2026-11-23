import type {
  StoredTufMetadata,
  TufMetadataIdentity,
  TufMetadataStore,
  TufRunFence
} from "./tuf-storage-contract";
import {
  TufPersistenceCommitError,
  TufStateMutationError,
  TufUpdaterPoisonedError
} from "./guarded-tuf-updater";

export type TufRoleName = "root" | "timestamp" | "snapshot" | string;

export interface AcceptedTufRole {
  readonly roleName: TufRoleName;
  readonly version: number;
  readonly bytes: Uint8Array;
}

export interface TufRoleAcceptance {
  /** The identity of the role currently durable, or null for initial root. */
  readonly expectedCurrent: TufMetadataIdentity | null;
  /** Must perform upstream TUF signature, threshold, expiry, linkage and delegation checks. */
  readonly acceptIntoTrustedSet: (bytes: Uint8Array) => void | Promise<void>;
}

/**
 * Small async persistence boundary for the pinned TUF verifier integration.
 *
 * It deliberately does not parse signatures or make trust decisions. The
 * caller must supply the upstream TrustedMetadataStore acceptance operation.
 * If that operation has advanced mutable trusted state and the durable CAS
 * then fails, this session is poisoned and must be discarded.
 */
export class FencedTufMetadataSession {
  private poisoned = false;
  private queue: Promise<void> = Promise.resolve();

  private constructor(
    private readonly store: TufMetadataStore,
    private readonly fence: TufRunFence
  ) {}

  static async create(
    store: TufMetadataStore,
    fence: TufRunFence,
    trustAnchor: Uint8Array
  ): Promise<{ session: FencedTufMetadataSession; root: StoredTufMetadata }> {
    if (!(trustAnchor instanceof Uint8Array) || trustAnchor.byteLength === 0 || trustAnchor.byteLength > 4 * 1024 * 1024) {
      throw new Error("explicit TUF trust anchor must be 1 byte to 4 MiB");
    }
    const session = new FencedTufMetadataSession(store, fence);
    const existing = await store.readRole("root");
    if (existing) return { session, root: existing };

    const candidate = await makeStoredRole(trustAnchor, "root");
    if (candidate.version !== 1) throw new Error("initial TUF trust anchor must be root version 1");
    try {
      await store.commitVerifiedRole("root", null, candidate, fence);
    } catch (error) {
      throw new TufPersistenceCommitError("initial TUF trust anchor could not be durably seeded", error);
    }
    return { session, root: candidate };
  }

  get isPoisoned(): boolean {
    return this.poisoned;
  }

  private assertHealthy(): void {
    if (this.poisoned) throw new TufUpdaterPoisonedError();
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(async () => {
      this.assertHealthy();
      try {
        return await operation();
      } catch (error) {
        if (error instanceof TufPersistenceCommitError || error instanceof TufStateMutationError) {
          this.poisoned = true;
        }
        throw error;
      }
    });
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  /**
   * Invoke only after the supplied upstream verifier accepts the exact bytes.
   * The callback and durable commit are serialized with every other role.
   */
  acceptVerifiedRole(
    roleName: TufRoleName,
    bytes: Uint8Array,
    acceptance: TufRoleAcceptance
  ): Promise<TufMetadataIdentity> {
    return this.serialize(async () => {
      const candidate = await makeStoredRole(bytes, roleName);
      try {
        await acceptance.acceptIntoTrustedSet(bytes);
      } catch (error) {
        // Unless the upstream adapter can prove it rolled back every mutation,
        // a verifier failure is ambiguous: it may have advanced trusted state
        // before a later validation step threw. Conservatively poison the
        // session so no subsequent role can use a possibly divergent trust set.
        throw error instanceof TufStateMutationError
          ? error
          : new TufStateMutationError(
              "upstream TUF acceptance failed; discard the possibly mutated trusted-state instance",
              error
            );
      }
      try {
        return await this.store.commitVerifiedRole(
          roleName,
          acceptance.expectedCurrent,
          candidate,
          this.fence
        );
      } catch (error) {
        throw new TufPersistenceCommitError(
          `verified TUF role ${roleName} was accepted in memory but its durable commit failed; discard this verifier instance`,
          error
        );
      }
    });
  }

  /**
   * Root rotation must be strictly sequential: accept and durably commit N+1
   * before the caller is asked to fetch N+2.
   */
  rotateRoots(
    firstVersion: number,
    maxRotations: number,
    fetchRoot: (version: number) => Promise<Uint8Array>,
    acceptRoot: (bytes: Uint8Array) => void | Promise<void>,
    current: TufMetadataIdentity
  ): Promise<TufMetadataIdentity> {
    return this.serialize(async () => {
      if (!Number.isSafeInteger(firstVersion) || firstVersion !== current.version + 1) {
        throw new Error("root rotation must begin at the next trusted version");
      }
      if (!Number.isSafeInteger(maxRotations) || maxRotations < 1 || maxRotations > 256) {
        throw new Error("root rotation bound must be between 1 and 256");
      }
      let identity = current;
      for (let version = firstVersion; version < firstVersion + maxRotations; version++) {
        let bytes: Uint8Array;
        try {
          bytes = await fetchRoot(version);
        } catch (error) {
          // The caller handles the repository's normal 403/404 end-of-chain
          // condition. Other fetch errors are not converted to cache misses.
          throw error;
        }
        const candidate = await makeStoredRole(bytes, "root");
        if (candidate.version !== version) throw new Error("fetched root version does not match requested rotation");
        try {
          await acceptRoot(bytes);
        } catch (error) {
          // Root acceptance can mutate the upstream trusted set before a
          // later validation error. Never continue rotations on ambiguity.
          throw error instanceof TufStateMutationError
            ? error
            : new TufStateMutationError(
                `upstream root ${version} acceptance failed; discard the possibly mutated trusted-state instance`,
                error
              );
        }
        try {
          identity = await this.store.commitVerifiedRole("root", identity, candidate, this.fence);
        } catch (error) {
          throw new TufPersistenceCommitError(
            `root ${version} was accepted in memory but not durably committed; discard this verifier instance`,
            error
          );
        }
      }
      return identity;
    });
  }
}

async function makeStoredRole(bytes: Uint8Array, roleName: string): Promise<StoredTufMetadata> {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1 || bytes.byteLength > 4 * 1024 * 1024) {
    throw new Error("TUF metadata must be a non-empty Uint8Array no larger than 4 MiB");
  }
  let envelope: { signed?: { type?: unknown; version?: unknown } };
  try {
    envelope = JSON.parse(new TextDecoder().decode(bytes)) as { signed?: { type?: unknown; version?: unknown } };
  } catch {
    throw new Error("TUF metadata is not valid JSON");
  }
  const expectedType = roleName === "root" || roleName === "timestamp" || roleName === "snapshot" ? roleName : "targets";
  if (!envelope.signed || envelope.signed.type !== expectedType ||
      !Number.isSafeInteger(envelope.signed.version) || (envelope.signed.version as number) < 1) {
    throw new Error("TUF metadata signed role/version envelope is invalid");
  }
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sha256 = Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
  return {
    version: envelope.signed.version as number,
    sha256,
    data: bytes.slice()
  };
}
