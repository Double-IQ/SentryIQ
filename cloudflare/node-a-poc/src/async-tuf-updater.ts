import { Buffer } from "node:buffer";
import type {
  CommittedTufTarget,
  TufTargetDescriptor,
  TufTargetStore,
  TufRunFence
} from "./tuf-storage-contract";
import { stageVerifiedTufTarget } from "./verified-target-stream";
import {
  AsyncTufTrustedStateAdapter,
  type PinnedTufRoleMetadata
} from "./async-tuf-trusted-state";

export interface AsyncTufUpdaterConfig {
  readonly metadataBaseUrl: string;
  readonly targetBaseUrl: string;
  readonly maxRootRotations?: number;
  readonly maxDelegations?: number;
  readonly rootMaxLength?: number;
  readonly timestampMaxLength?: number;
  readonly snapshotMaxLength?: number;
  readonly targetsMaxLength?: number;
  readonly targetMaxLength?: number;
  readonly prefixTargetsWithHash?: boolean;
}

interface TargetInfo {
  readonly path: string;
  readonly length: number;
  readonly hashes: Readonly<Record<string, string>>;
}

const DEFAULTS = {
  maxRootRotations: 256,
  maxDelegations: 32,
  rootMaxLength: 512_000,
  timestampMaxLength: 16_384,
  snapshotMaxLength: 2_000_000,
  targetsMaxLength: 5_000_000,
  targetMaxLength: 1_073_741_824,
  prefixTargetsWithHash: true
};

export class TufMetadataHttpError extends Error {
  readonly statusCode: number;

  constructor(statusCode: number, url: string) {
    super("TUF metadata request failed with HTTP " + statusCode + ": " + url);
    this.name = "TufMetadataHttpError";
    this.statusCode = statusCode;
  }
}

/**
 * Async Node A updater workflow. TUF metadata parsing, signatures, thresholds,
 * expiry, rollback, snapshot linkage, and delegation authorization are all
 * delegated to the pinned upstream TrustedMetadataStore through the adapter.
 * This class only performs bounded transport, workflow ordering, and target
 * streaming into the fenced target store.
 */
export class AsyncTufUpdater {
  private readonly config: typeof DEFAULTS;
  private refreshed = false;

  constructor(
    private readonly trusted: AsyncTufTrustedStateAdapter,
    private readonly targets: TufTargetStore,
    private readonly fence: TufRunFence,
    config: AsyncTufUpdaterConfig
  ) {
    if (!config.metadataBaseUrl || !config.targetBaseUrl) {
      throw new Error("TUF metadata and target base URLs are required");
    }
    this.config = {
      maxRootRotations: config.maxRootRotations ?? DEFAULTS.maxRootRotations,
      maxDelegations: config.maxDelegations ?? DEFAULTS.maxDelegations,
      rootMaxLength: config.rootMaxLength ?? DEFAULTS.rootMaxLength,
      timestampMaxLength: config.timestampMaxLength ?? DEFAULTS.timestampMaxLength,
      snapshotMaxLength: config.snapshotMaxLength ?? DEFAULTS.snapshotMaxLength,
      targetsMaxLength: config.targetsMaxLength ?? DEFAULTS.targetsMaxLength,
      targetMaxLength: config.targetMaxLength ?? DEFAULTS.targetMaxLength,
      prefixTargetsWithHash: config.prefixTargetsWithHash ?? DEFAULTS.prefixTargetsWithHash
    };
    this.metadataBaseUrl = normalizeHttpsBaseUrl(config.metadataBaseUrl, "metadata");
    this.targetBaseUrl = normalizeHttpsBaseUrl(config.targetBaseUrl, "target");
  }

  private readonly metadataBaseUrl: string;
  private readonly targetBaseUrl: string;

  async refresh(): Promise<void> {
    if (this.refreshed) return;

    await this.trusted.rotateRoots(
      this.trusted.root.signed.version + 1,
      this.config.maxRootRotations,
      (version) => this.fetchMetadata(
        this.metadataUrl(version + ".root.json"),
        this.config.rootMaxLength
      )
    );

    const timestampBytes = await this.fetchMetadata(
      this.metadataUrl("timestamp.json"),
      this.config.timestampMaxLength
    );
    await this.trusted.refreshTimestamp(timestampBytes);

    const timestamp = this.trusted.timestamp;
    if (!timestamp) throw new Error("upstream TUF verifier did not establish timestamp metadata");
    const snapshotMeta = timestamp.signed.snapshotMeta;
    if (!snapshotMeta) throw new Error("trusted timestamp has no snapshot metadata reference");

    const consistentSnapshot = this.trusted.root.signed.consistentSnapshot === true;
    const snapshotFile = consistentSnapshot
      ? snapshotMeta.version + ".snapshot.json"
      : "snapshot.json";
    const snapshotBytes = await this.fetchMetadata(
      this.metadataUrl(snapshotFile),
      snapshotMeta.length ?? this.config.snapshotMaxLength
    );
    await this.trusted.refreshSnapshot(snapshotBytes);
    this.refreshed = true;
  }

  async getTargetInfo(targetPath: string): Promise<TargetInfo | undefined> {
    if (!this.trusted.snapshot) await this.refresh();

    const stack: Array<{ roleName: string; parentRoleName: string }> = [
      { roleName: "targets", parentRoleName: "root" }
    ];
    const visited = new Set<string>();

    while (visited.size <= this.config.maxDelegations && stack.length > 0) {
      const { roleName, parentRoleName } = stack.pop()!;
      if (visited.has(roleName)) continue;

      const role = await this.loadTargetsRole(roleName, parentRoleName);
      const signed = role?.signed;
      if (!signed) continue;

      const target = signed.targets?.[targetPath] as TargetInfo | undefined;
      if (target) {
        if (!Number.isSafeInteger(target.length) || target.length < 0 ||
            target.length > this.config.targetMaxLength ||
            !target.hashes || Object.keys(target.hashes).length === 0) {
          throw new Error("TUF target length or digest descriptor is outside the configured bounds");
        }
        return { ...target, path: targetPath };
      }

      visited.add(roleName);
      const childRoles = signed.delegations?.rolesForTarget?.(targetPath) ?? [];
      const ordered: Array<{ roleName: string; parentRoleName: string }> = [];
      for (const child of childRoles) {
        ordered.push({ roleName: child.role, parentRoleName: roleName });
        if (child.terminating) {
          stack.splice(0);
          break;
        }
      }
      ordered.reverse();
      stack.push(...ordered);
    }
    return undefined;
  }

  async downloadTarget(targetInfo: TargetInfo): Promise<CommittedTufTarget> {
    const descriptor: TufTargetDescriptor = {
      targetPath: targetInfo.path,
      length: targetInfo.length,
      hashes: targetInfo.hashes
    };
    let targetPath = targetInfo.path;
    validateTargetPath(targetPath);
    if (this.trusted.root.signed.consistentSnapshot &&
        this.config.prefixTargetsWithHash) {
      const hash = Object.values(targetInfo.hashes)[0];
      if (!hash) throw new Error("verified TUF target has no digest for consistent snapshot naming");
      const parts = targetPath.split("/");
      const fileName = parts.pop()!;
      parts.push(hash + "." + fileName);
      targetPath = parts.join("/");
    }

    const encodedTargetPath = targetPath.split("/").map((part) => encodeURIComponent(part)).join("/");
    const targetUrl = new URL(encodedTargetPath, this.targetBaseUrl).toString();
    const response = await fetch(targetUrl);
    if (!response.ok) throw new TufMetadataHttpError(response.status, targetUrl);
    if (!response.body) throw new Error("TUF target response has no readable body");

    return stageVerifiedTufTarget(this.targets, {
      descriptor,
      body: response.body,
      fence: this.fence
    });
  }

  async getTarget(targetPath: string): Promise<ReadableStream<Uint8Array> | null> {
    const info = await this.getTargetInfo(targetPath);
    if (!info) return null;

    const expected: TufTargetDescriptor = {
      targetPath,
      length: info.length,
      hashes: info.hashes
    };
    const cached = await this.targets.openCommittedTarget(targetPath, expected);
    if (cached) return cached;

    await this.downloadTarget(info);
    const committed = await this.targets.openCommittedTarget(targetPath, expected);
    if (!committed) throw new Error("TUF target was committed but its immutable pointer cannot be reopened");
    return committed;
  }

  private async loadTargetsRole(
    roleName: string,
    parentRoleName: string
  ): Promise<PinnedTufRoleMetadata | undefined> {
    const cached = this.trusted.getRole(roleName);
    if (cached) {
      const parent = this.trusted.getRole(parentRoleName);
      if (!parent && parentRoleName !== "root") {
        throw new Error("upstream TUF trusted set is missing delegation parent " + parentRoleName);
      }
      return cached;
    }

    const snapshot = this.trusted.snapshot;
    const meta = snapshot?.signed.meta?.[roleName + ".json"];
    if (!meta) {
      throw new Error("delegated TUF role is not referenced by trusted snapshot: " + roleName);
    }
    const consistentSnapshot = this.trusted.root.signed.consistentSnapshot === true;
    const encodedRole = encodeURIComponent(roleName);
    const fileName = consistentSnapshot
      ? meta.version + "." + encodedRole + ".json"
      : encodedRole + ".json";
    const bytes = await this.fetchMetadata(
      this.metadataUrl(fileName),
      meta.length ?? this.config.targetsMaxLength
    );
    await this.trusted.refreshDelegatedTargets(roleName, parentRoleName, bytes);
    return this.trusted.getRole(roleName);
  }

  private metadataUrl(fileName: string): string {
    return new URL(fileName, this.metadataBaseUrl).toString();
  }

  private async fetchMetadata(url: string, maxLength: number): Promise<Uint8Array> {
    const response = await fetch(url);
    if (!response.ok) throw new TufMetadataHttpError(response.status, url);
    if (!response.body) throw new Error("TUF metadata response has no readable body: " + url);

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (!Number.isSafeInteger(total) || total > maxLength) {
          throw new Error("TUF metadata response exceeded its configured size limit: " + url);
        }
        chunks.push(value.slice());
      }
    } catch (error) {
      try { await reader.cancel(error); } catch { /* preserve original error */ }
      throw error;
    } finally {
      reader.releaseLock();
    }
    return new Uint8Array(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))));
  }
}

function normalizeHttpsBaseUrl(value: string, label: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("TUF " + label + " base URL is invalid");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("TUF " + label + " base URL must be HTTPS without credentials, query, or fragment");
  }
  url.pathname = url.pathname.endsWith("/") ? url.pathname : url.pathname + "/";
  return url.toString();
}

function validateTargetPath(targetPath: string): void {
  if (typeof targetPath !== "string" || targetPath.length === 0 ||
      targetPath.length > 1024 || targetPath.startsWith("/") || targetPath.includes("\\") ||
      /[\u0000-\u001f\u007f?#]/.test(targetPath) ||
      targetPath.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error("TUF target path is invalid");
  }
}
