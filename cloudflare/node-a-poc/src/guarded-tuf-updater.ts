/**
 * Fail-closed lifecycle wrapper for a TUF updater whose trusted in-memory
 * metadata may have advanced before a durable metadata commit failed.
 *
 * The real tuf-js adapter must throw TufPersistenceCommitError when its
 * upstream TrustedMetadataStore has accepted metadata but durable persistence
 * did not complete. This wrapper then permanently poisons that updater
 * instance; callers must construct a fresh updater from durable state.
 */

export class TufPersistenceCommitError extends Error {
  readonly causeValue: unknown;

  constructor(message: string, causeValue?: unknown) {
    super(message);
    this.name = "TufPersistenceCommitError";
    this.causeValue = causeValue;
  }
}

/**
 * The upstream trusted-state object may have been partially mutated before
 * validation failed. The patched updater must emit this error unless it can
 * prove the mutation was rolled back atomically.
 */
export class TufStateMutationError extends Error {
  readonly causeValue: unknown;

  constructor(message: string, causeValue?: unknown) {
    super(message);
    this.name = "TufStateMutationError";
    this.causeValue = causeValue;
  }
}

export class TufUpdaterPoisonedError extends Error {
  constructor() {
    super("TUF updater instance is poisoned after a metadata persistence failure; recreate it from durable state");
    this.name = "TufUpdaterPoisonedError";
  }
}

export interface TufUpdaterOperations<TTarget = unknown, TInfo = unknown> {
  refresh(): Promise<void>;
  getTarget(targetPath: string): Promise<TTarget>;
  getTargetInfo(targetPath: string): Promise<TInfo>;
}

export class GuardedTufUpdater<TTarget = unknown, TInfo = unknown> {
  private poisonCause: unknown | null = null;

  constructor(private readonly upstream: TufUpdaterOperations<TTarget, TInfo>) {}

  get poisoned(): boolean {
    return this.poisonCause !== null;
  }

  private assertHealthy(): void {
    if (this.poisoned) throw new TufUpdaterPoisonedError();
  }

  private async invoke<T>(operation: () => Promise<T>): Promise<T> {
    this.assertHealthy();
    try {
      return await operation();
    } catch (error) {
      if (error instanceof TufPersistenceCommitError || error instanceof TufStateMutationError) {
        this.poisonCause = error;
        throw error;
      }
      throw error;
    }
  }

  refresh(): Promise<void> {
    return this.invoke(() => this.upstream.refresh());
  }

  getTarget(targetPath: string): Promise<TTarget> {
    return this.invoke(() => this.upstream.getTarget(targetPath));
  }

  getTargetInfo(targetPath: string): Promise<TInfo> {
    return this.invoke(() => this.upstream.getTargetInfo(targetPath));
  }
}
