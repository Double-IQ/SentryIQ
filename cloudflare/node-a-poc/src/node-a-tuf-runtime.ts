import type { RunLock } from "./index";
import {
  DurableObjectTufMetadataStore,
  type DurableMetadataStateClient
} from "./durable-tuf-metadata-store";
import {
  R2TufTargetStore,
  type DurableTargetPointerClient,
  type R2BucketLike
} from "./r2-tuf-target-store";
import { AsyncTufTrustedStateAdapter } from "./async-tuf-trusted-state";
import { AsyncTufUpdater, type AsyncTufUpdaterConfig } from "./async-tuf-updater";
import type { TufRunFence } from "./tuf-storage-contract";

export interface NodeAAsyncTufRuntimeOptions {
  /** The NodeAState Durable Object stub. */
  readonly state: DurableMetadataStateClient & DurableTargetPointerClient;
  /** The private R2 bucket bound to this Worker. */
  readonly bucket: R2BucketLike;
  /** Returns the latest local lease identity; renewals preserve run/fence/token. */
  readonly currentLock: () => RunLock;
  /** Explicitly provisioned, integrity-pinned TUF root bytes. */
  readonly trustAnchor: Uint8Array;
  readonly metadataBaseUrl: string;
  readonly targetBaseUrl: string;
  readonly updater?: Omit<AsyncTufUpdaterConfig, "metadataBaseUrl" | "targetBaseUrl">;
}

/**
 * Wires the pinned upstream verifier, Durable Object metadata/pointer store,
 * and R2 streaming object store into the async Node A updater.
 */
export async function createNodeAAsyncTufUpdater(
  options: NodeAAsyncTufRuntimeOptions
): Promise<AsyncTufUpdater> {
  const initialLock = options.currentLock();
  const fence: TufRunFence = {
    runId: initialLock.runId,
    fence: initialLock.fence,
    token: initialLock.token
  };

  const metadataStore = new DurableObjectTufMetadataStore(
    options.state,
    options.currentLock
  );
  const targetStore = new R2TufTargetStore(
    options.bucket,
    options.state,
    options.currentLock
  );
  const trustedState = await AsyncTufTrustedStateAdapter.create(
    metadataStore,
    fence,
    options.trustAnchor
  );

  return new AsyncTufUpdater(
    trustedState,
    targetStore,
    fence,
    {
      ...options.updater,
      metadataBaseUrl: options.metadataBaseUrl,
      targetBaseUrl: options.targetBaseUrl
    }
  );
}
