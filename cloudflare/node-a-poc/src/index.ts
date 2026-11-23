import { DurableObject } from "cloudflare:workers";
import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";
import { Verifier } from "@sigstore/verify";
import { createNodeAAsyncTufUpdater } from "./node-a-tuf-runtime";
import { NodeAReleaseAssetFetcher } from "./release-assets";
import { NodeAReleaseMonitor, NodeAReleaseMonitorAlertAttemptedError } from "./node-a-release-monitor";
import { NodeAEventAlreadyAlertedError } from "./node-a-event-runner";
import { Node4EventClient } from "./node4-event-client";
import { NodeAReportSigner } from "./node-a-report-signer";
import { NodeAPrivateHostGate } from "./private-host-attestation";
import { NodeAEventRunner } from "./node-a-event-runner";
import { NodeAOwnerAlertWebhook } from "./node-a-owner-alert";
import type { CommittedTufTarget, TufTargetDescriptor } from "./tuf-storage-contract";

export interface Env {
  NODE_A_STATE: DurableObjectNamespace<NodeAState>;
  NODE_A_TARGETS: R2Bucket;
  NODE_A_API_TOKEN?: string;
  TUF_ROOT_B64?: string;
  TUF_METADATA_URL?: string;
  TUF_TARGET_URL?: string;
  NODE_A_GITHUB_TOKEN?: string;
  NODE_A_EVENT_TOKEN?: string;
  NODE_A_REPORT_PRIVATE_KEY_B64?: string;
  NODE_A_PRIVATE_HOST_TOKEN?: string;
  NODE_A_COLLECTOR_PUBLIC_KEY_B64?: string;
  NODE_A_EXPECTED_FILES_JSON?: string;
  NODE_A_EXPECTED_PRIVATE_CONFIG_JSON?: string;
  NODE_A_ALERT_URL?: string;
  NODE_A_ALERT_HOST?: string;
  NODE_A_ALERT_TOKEN?: string;
  NODE_A_BASELINE_APPROVAL_TOKEN?: string;
}

export interface ReleasePin {
  version: string;
  commit: string;
  manifestSha256: string;
  zipSha256: string;
  updatedAt: number;
}

type PinCandidate = Omit<ReleasePin, "updatedAt">;

export type RunLock = {
  runId: string;
  fence: number;
  token: string;
  expiresAt: number;
};

function parseVersion(version: string): [number, number, number] {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new Error("release version must be canonical MAJOR.MINOR.PATCH");
  }
  const parts = version.split(".").map(Number);
  if (!parts.every(Number.isSafeInteger)) throw new Error("release version component is too large");
  return [parts[0], parts[1], parts[2]];
}

function compareVersions(a: string, b: string): number {
  const av = parseVersion(a);
  const bv = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    if (av[i] !== bv[i]) return av[i] < bv[i] ? -1 : 1;
  }
  return 0;
}

function validatePin(candidate: PinCandidate): void {
  parseVersion(candidate.version);
  if (!/^[a-f0-9]{40}$/.test(candidate.commit)) {
    throw new Error("release commit must be a lowercase full Git SHA");
  }
  if (!/^[a-f0-9]{64}$/.test(candidate.manifestSha256)
      || !/^[a-f0-9]{64}$/.test(candidate.zipSha256)) {
    throw new Error("release artifact digests must be lowercase SHA-256");
  }
}

export class NodeAState extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS release_baseline (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL,
        zip_sha256 TEXT NOT NULL,
        initialized_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS release_pin (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL,
        zip_sha256 TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS run_lease (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        run_id TEXT NOT NULL,
        fence INTEGER NOT NULL CHECK (fence > 0),
        token_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS run_fence_counter (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        last_fence INTEGER NOT NULL CHECK (last_fence >= 0)
      );
      CREATE TABLE IF NOT EXISTS tuf_files (
        path TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_metadata (
        role_name TEXT PRIMARY KEY,
        version INTEGER NOT NULL CHECK (version > 0),
        sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
        data BLOB NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_target_pointers (
        target_path TEXT PRIMARY KEY,
        object_key TEXT NOT NULL UNIQUE,
        length INTEGER NOT NULL CHECK (length >= 0),
        hashes_json TEXT NOT NULL,
        fence INTEGER NOT NULL CHECK (fence > 0),
        committed_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_target_staging (
        stage_id TEXT PRIMARY KEY,
        object_key TEXT NOT NULL UNIQUE,
        run_id TEXT NOT NULL,
        fence INTEGER NOT NULL CHECK (fence > 0),
        token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_target_gc (
        object_key TEXT PRIMARY KEY,
        queued_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS run_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        outcome TEXT NOT NULL CHECK (outcome IN ('started', 'approved', 'rejected', 'failed')),
        release_version TEXT,
        recorded_at INTEGER NOT NULL
      );
    `);
  }

  getPin(): ReleasePin | null {
    const row = this.ctx.storage.sql
      .exec<{
        version: string;
        commit_sha: string;
        manifest_sha256: string;
        zip_sha256: string;
        updated_at: number;
      }>("SELECT version, commit_sha, manifest_sha256, zip_sha256, updated_at FROM release_pin WHERE singleton = 1")
      .toArray()[0];
    if (!row) return null;
    return {
      version: row.version,
      commit: row.commit_sha,
      manifestSha256: row.manifest_sha256,
      zipSha256: row.zip_sha256,
      updatedAt: row.updated_at
    };
  }

  initializeBaseline(candidate: PinCandidate): ReleasePin {
    validatePin(candidate);
    return this.ctx.storage.transactionSync(() => {
      const existing = this.ctx.storage.sql
        .exec<{ version: string; commit_sha: string; manifest_sha256: string; zip_sha256: string }>(
          "SELECT version, commit_sha, manifest_sha256, zip_sha256 FROM release_baseline WHERE singleton = 1"
        ).toArray()[0];
      if (existing) {
        if (existing.version !== candidate.version || existing.commit_sha !== candidate.commit
            || existing.manifest_sha256 !== candidate.manifestSha256 || existing.zip_sha256 !== candidate.zipSha256) {
          throw new Error("independently initialized baseline is immutable");
        }
        const current = this.getPin();
        if (!current) throw new Error("baseline exists but release pin is missing");
        return current;
      }
      const now = Date.now();
      this.ctx.storage.sql.exec(
        "INSERT INTO release_baseline (singleton, version, commit_sha, manifest_sha256, zip_sha256, initialized_at) VALUES (1, ?, ?, ?, ?, ?)",
        candidate.version, candidate.commit, candidate.manifestSha256, candidate.zipSha256, now
      );
      this.ctx.storage.sql.exec(
        "INSERT INTO release_pin (singleton, version, commit_sha, manifest_sha256, zip_sha256, updated_at) VALUES (1, ?, ?, ?, ?, ?)",
        candidate.version, candidate.commit, candidate.manifestSha256, candidate.zipSha256, now
      );
      const saved = this.getPin();
      if (!saved || saved.version !== candidate.version || saved.commit !== candidate.commit
          || saved.manifestSha256 !== candidate.manifestSha256 || saved.zipSha256 !== candidate.zipSha256) {
        throw new Error("baseline initialization transaction did not persist the requested identity");
      }
      return saved;
    });
  }

  advancePin(candidate: PinCandidate, lock: RunLock): ReleasePin {
    validatePin(candidate);
    this.validateRunLock(lock);
    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      const baseline = this.ctx.storage.sql
        .exec<{ version: string; commit_sha: string; manifest_sha256: string; zip_sha256: string }>(
          "SELECT version, commit_sha, manifest_sha256, zip_sha256 FROM release_baseline WHERE singleton = 1"
        ).toArray()[0];
      if (!baseline) throw new Error("independent release baseline has not been initialized");
      if (compareVersions(candidate.version, baseline.version) < 0) {
        throw new Error("release is older than independently initialized baseline");
      }
      const current = this.getPin();
      if (current) {
        const order = compareVersions(candidate.version, current.version);
        const sameIdentity = candidate.version === current.version
          && candidate.commit === current.commit
          && candidate.manifestSha256 === current.manifestSha256
          && candidate.zipSha256 === current.zipSha256;
        if (order < 0) throw new Error("release rollback rejected");
        if (order === 0 && !sameIdentity) {
          throw new Error("same-version release identity or digest replacement rejected");
        }
        if (sameIdentity) return current;
      }

      this.ctx.storage.sql.exec(
        `INSERT INTO release_pin (singleton, version, commit_sha, manifest_sha256, zip_sha256, updated_at)
         VALUES (1, ?, ?, ?, ?, ?)
         ON CONFLICT(singleton) DO UPDATE SET
           version = excluded.version,
           commit_sha = excluded.commit_sha,
           manifest_sha256 = excluded.manifest_sha256,
           zip_sha256 = excluded.zip_sha256,
           updated_at = excluded.updated_at`,
        candidate.version,
        candidate.commit,
        candidate.manifestSha256,
        candidate.zipSha256,
        Date.now()
      );
      const saved = this.getPin();
      if (!saved || saved.version !== candidate.version || saved.commit !== candidate.commit
          || saved.manifestSha256 !== candidate.manifestSha256 || saved.zipSha256 !== candidate.zipSha256) {
        throw new Error("release pin transaction did not persist the requested identity");
      }
      return saved;
    });
  }

  acquireRunLock(leaseMs: number): RunLock {
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 15 * 60_000) throw new Error("invalid run lock time or lease");
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      const current = this.ctx.storage.sql.exec<{ expires_at: number }>("SELECT expires_at FROM run_lease WHERE singleton = 1").toArray()[0];
      if (current && current.expires_at > now) throw new Error("Node A run already holds the durable lock");
      const previousFence = this.ctx.storage.sql.exec<{ last_fence: number }>("SELECT last_fence FROM run_fence_counter WHERE singleton = 1").toArray()[0]?.last_fence ?? 0;
      if (!Number.isSafeInteger(previousFence) || previousFence < 0 || previousFence >= Number.MAX_SAFE_INTEGER) throw new Error("run fencing counter is invalid or exhausted");
      const fence = previousFence + 1;
      const runId = randomBytes(16).toString("hex");
      const token = randomBytes(32).toString("hex");
      const expiresAt = now + leaseMs;
      this.ctx.storage.sql.exec("INSERT INTO run_fence_counter (singleton, last_fence) VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET last_fence = excluded.last_fence", fence);
      this.ctx.storage.sql.exec("INSERT INTO run_lease (singleton, run_id, fence, token_hash, expires_at) VALUES (1, ?, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET run_id = excluded.run_id, fence = excluded.fence, token_hash = excluded.token_hash, expires_at = excluded.expires_at", runId, fence, createHash("sha256").update(token).digest("hex"), expiresAt);
      return { runId, fence, token, expiresAt };
    });
  }

  renewRunLock(lock: RunLock, leaseMs: number): RunLock {
    this.validateRunLock(lock);
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 15 * 60_000) throw new Error("invalid run lock token or lease");
    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      const expiresAt = Date.now() + leaseMs;
      this.ctx.storage.sql.exec("UPDATE run_lease SET expires_at = ? WHERE singleton = 1 AND run_id = ? AND fence = ? AND token_hash = ?", expiresAt, lock.runId, lock.fence, createHash("sha256").update(lock.token).digest("hex"));
      return { ...lock, expiresAt };
    });
  }

  private validateRunLock(lock: RunLock): void {
    if (!lock || !/^[a-f0-9]{32}$/.test(lock.runId) || !Number.isSafeInteger(lock.fence) || lock.fence < 1 || !/^[a-f0-9]{64}$/.test(lock.token)) {
      throw new Error("run lock identity, fence or token is invalid");
    }
  }

  private assertRunLock(lock: RunLock): void {
    const current = this.ctx.storage.sql.exec<{ run_id: string; fence: number; token_hash: string; expires_at: number }>("SELECT run_id, fence, token_hash, expires_at FROM run_lease WHERE singleton = 1").toArray()[0];
    if (!current || current.run_id !== lock.runId || current.fence !== lock.fence || current.token_hash !== createHash("sha256").update(lock.token).digest("hex") || current.expires_at <= Date.now()) {
      throw new Error("valid active Node A run fence required");
    }
  }

  releaseRunLock(lock: RunLock): void {
    this.validateRunLock(lock);
    this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      this.ctx.storage.sql.exec("DELETE FROM run_lease WHERE singleton = 1 AND run_id = ? AND fence = ? AND token_hash = ?", lock.runId, lock.fence, createHash("sha256").update(lock.token).digest("hex"));
    });
  }
  recordOutcome(outcome: "started" | "approved" | "rejected" | "failed", version: string | null): void {
    if (version !== null) parseVersion(version);
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        "INSERT INTO run_audit (outcome, release_version, recorded_at) VALUES (?, ?, ?)",
        outcome,
        version,
        Date.now()
      );
      this.ctx.storage.sql.exec("DELETE FROM run_audit WHERE id NOT IN (SELECT id FROM run_audit ORDER BY id DESC LIMIT 200)");
    });
  }

  registerTufTargetStage(stageId: string, objectKey: string, lock: RunLock): void {
    this.validateRunLock(lock);
    if (!/^[a-f0-9-]{36}$/.test(stageId) || !/^objects\/[a-f0-9-]{36}$/.test(objectKey)) {
      throw new Error("TUF target staging identity is invalid");
    }
    this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      this.ctx.storage.sql.exec(
        "INSERT INTO tuf_target_staging (stage_id, object_key, run_id, fence, token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        stageId, objectKey, lock.runId, lock.fence,
        createHash("sha256").update(lock.token).digest("hex"), Date.now()
      );
    });
  }

  listStaleTufTargetStages(lock: RunLock, limit = 100): Array<{ stageId: string; objectKey: string; fence: number }> {
    this.validateRunLock(lock);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("TUF target cleanup limit is invalid");
    this.assertRunLock(lock);
    return this.ctx.storage.sql.exec<{ stage_id: string; object_key: string; fence: number }>(
      "SELECT stage_id, object_key, fence FROM tuf_target_staging WHERE fence < ? ORDER BY created_at LIMIT ?",
      lock.fence, limit
    ).toArray().map((row) => {
      if (!/^[a-f0-9-]{36}$/.test(row.stage_id) ||
          !/^objects\/[a-f0-9-]{36}$/.test(row.object_key) ||
          !Number.isSafeInteger(row.fence) || row.fence < 1 || row.fence >= lock.fence) {
        throw new Error("durable TUF staging registry contains an invalid identity");
      }
      return { stageId: row.stage_id, objectKey: row.object_key, fence: row.fence };
    });
  }

  deleteTufTargetStage(stageId: string, objectKey: string, lock: RunLock): void {
    this.validateRunLock(lock);
    this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      const stage = this.ctx.storage.sql.exec<{ run_id: string; fence: number; token_hash: string }>(
        "SELECT run_id, fence, token_hash FROM tuf_target_staging WHERE stage_id = ? AND object_key = ?",
        stageId, objectKey
      ).toArray()[0];
      if (!stage) return;
      const tokenHash = createHash("sha256").update(lock.token).digest("hex");
      if (stage.fence > lock.fence ||
          (stage.fence === lock.fence && (stage.run_id !== lock.runId || stage.token_hash !== tokenHash))) {
        throw new Error("TUF target staging record belongs to a different active run");
      }
      this.ctx.storage.sql.exec(
        "DELETE FROM tuf_target_staging WHERE stage_id = ? AND object_key = ?",
        stageId, objectKey
      );
    });
  }

  commitTufTargetPointer(
    descriptor: TufTargetDescriptor,
    stageId: string,
    objectKey: string,
    lock: RunLock
  ): CommittedTufTarget {
    this.validateRunLock(lock);
    this.validateTufTargetDescriptor(descriptor);
    if (!/^[a-f0-9-]{36}$/.test(stageId) || !/^objects\/[a-f0-9-]{36}$/.test(objectKey)) {
      throw new Error("TUF target object or staging identity is invalid");
    }
    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      const stage = this.ctx.storage.sql.exec<{ run_id: string; fence: number; token_hash: string }>(
        "SELECT run_id, fence, token_hash FROM tuf_target_staging WHERE stage_id = ? AND object_key = ?",
        stageId, objectKey
      ).toArray()[0];
      const tokenHash = createHash("sha256").update(lock.token).digest("hex");
      if (!stage || stage.run_id !== lock.runId || stage.fence !== lock.fence || stage.token_hash !== tokenHash) {
        throw new Error("TUF target staging record does not match the active run fence");
      }
      const previous = this.ctx.storage.sql.exec<{ object_key: string }>(
        "SELECT object_key FROM tuf_target_pointers WHERE target_path = ?",
        descriptor.targetPath
      ).toArray()[0];
      if (previous && previous.object_key !== objectKey) {
        this.ctx.storage.sql.exec(
          "INSERT OR IGNORE INTO tuf_target_gc (object_key, queued_at) VALUES (?, ?)",
          previous.object_key,
          Date.now()
        );
      }
      const committedAt = Date.now();
      this.ctx.storage.sql.exec(
        "INSERT INTO tuf_target_pointers (target_path, object_key, length, hashes_json, fence, committed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(target_path) DO UPDATE SET object_key = excluded.object_key, length = excluded.length, hashes_json = excluded.hashes_json, fence = excluded.fence, committed_at = excluded.committed_at",
        descriptor.targetPath, objectKey, descriptor.length, JSON.stringify(descriptor.hashes), lock.fence, committedAt
      );
      this.ctx.storage.sql.exec("DELETE FROM tuf_target_staging WHERE stage_id = ?", stageId);
      return { ...descriptor, hashes: { ...descriptor.hashes }, objectKey, fence: lock.fence, committedAt };
    });
  }

  listRetiredTufTargetObjects(
    lock: RunLock,
    limit = 100,
    minimumAgeMs = 24 * 60 * 60 * 1000
  ): string[] {
    this.validateRunLock(lock);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("TUF target garbage-collection limit is invalid");
    if (!Number.isSafeInteger(minimumAgeMs) || minimumAgeMs < 0 || minimumAgeMs > 30 * 24 * 60 * 60 * 1000) {
      throw new Error("TUF target garbage-collection retention is invalid");
    }
    this.assertRunLock(lock);
    return this.ctx.storage.sql.exec<{ object_key: string }>(
      "SELECT object_key FROM tuf_target_gc WHERE queued_at <= ? ORDER BY queued_at LIMIT ?",
      Date.now() - minimumAgeMs, limit
    ).toArray().map((row) => {
      if (!/^objects\/[a-f0-9-]{36}$/.test(row.object_key)) {
        throw new Error("durable TUF garbage-collection queue contains an invalid object key");
      }
      return row.object_key;
    });
  }

  deleteRetiredTufTargetObject(objectKey: string, lock: RunLock): void {
    this.validateRunLock(lock);
    if (!/^objects\/[a-f0-9-]{36}$/.test(objectKey)) throw new Error("retired TUF target object key is invalid");
    this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      this.ctx.storage.sql.exec("DELETE FROM tuf_target_gc WHERE object_key = ?", objectKey);
    });
  }

  readTufTargetPointer(targetPath: string): CommittedTufTarget | null {
    this.validateTufTargetPath(targetPath);
    const row = this.ctx.storage.sql.exec<{ object_key: string; length: number; hashes_json: string; fence: number; committed_at: number }>(
      "SELECT object_key, length, hashes_json, fence, committed_at FROM tuf_target_pointers WHERE target_path = ?", targetPath
    ).toArray()[0];
    if (!row) return null;
    let hashes: Record<string, string>;
    try { hashes = JSON.parse(row.hashes_json) as Record<string, string>; }
    catch { throw new Error("committed TUF target pointer hashes are corrupt"); }
    const descriptor = { targetPath, length: row.length, hashes };
    this.validateTufTargetDescriptor(descriptor);
    if (!/^objects\/[a-f0-9-]{36}$/.test(row.object_key) || !Number.isSafeInteger(row.fence) || row.fence < 1) {
      throw new Error("committed TUF target pointer identity is corrupt");
    }
    return { ...descriptor, objectKey: row.object_key, fence: row.fence, committedAt: row.committed_at };
  }

  private validateTufTargetDescriptor(descriptor: TufTargetDescriptor): void {
    this.validateTufTargetPath(descriptor.targetPath);
    if (!Number.isSafeInteger(descriptor.length) || descriptor.length < 0 || !descriptor.hashes || Object.keys(descriptor.hashes).length === 0) {
      throw new Error("TUF target descriptor is invalid");
    }
    for (const [algorithm, digest] of Object.entries(descriptor.hashes)) {
      let digestLength: number;
      try { digestLength = createHash(algorithm).digest("hex").length; }
      catch { throw new Error("unsupported TUF target hash algorithm: " + algorithm); }
      if (typeof digest !== "string" || !new RegExp("^[a-f0-9]{" + digestLength + "}$").test(digest)) {
        throw new Error("TUF target hash value is malformed");
      }
    }
  }

  private validateTufTargetPath(targetPath: string): void {
    if (typeof targetPath !== "string" || targetPath.length === 0 ||
        targetPath.length > 1024 || targetPath.startsWith("/") ||
        targetPath.includes("\\") || /[\u0000-\u001f\u007f?#]/.test(targetPath) ||
        targetPath.split("/").some((part) => part === "" || part === "." || part === "..")) {
      throw new Error("TUF target path is invalid");
    }
  }
  listTufMetadataRoles(): string[] {
    return this.ctx.storage.sql
      .exec<{ role_name: string }>("SELECT role_name FROM tuf_metadata ORDER BY role_name")
      .toArray()
      .map((row) => row.role_name);
  }

  readTufMetadata(roleName: string): { version: number; sha256: string; data: Uint8Array } | null {
    this.validateTufRoleName(roleName);
    const row = this.ctx.storage.sql.exec<{
      version: number; sha256: string; data: ArrayBuffer | Uint8Array
    }>("SELECT version, sha256, data FROM tuf_metadata WHERE role_name = ?", roleName).toArray()[0];
    if (!row) return null;
    return { version: row.version, sha256: row.sha256, data: new Uint8Array(row.data) };
  }

  commitVerifiedTufMetadata(
    roleName: string,
    expectedCurrent: { version: number; sha256: string } | null,
    next: { version: number; sha256: string; data: Uint8Array },
    lock: RunLock
  ): { version: number; sha256: string } {
    this.validateTufRoleName(roleName);
    this.validateRunLock(lock);
    if (!Number.isSafeInteger(next.version) || next.version < 1
        || !/^[a-f0-9]{64}$/.test(next.sha256)
        || !(next.data instanceof Uint8Array) || next.data.byteLength < 1 || next.data.byteLength > 4 * 1024 * 1024) {
      throw new Error("TUF metadata candidate is malformed or exceeds the storage limit");
    }
    const actualDigest = createHash("sha256").update(Buffer.from(next.data)).digest("hex");
    if (actualDigest !== next.sha256) throw new Error("TUF metadata candidate digest mismatch");
    let envelope: { signed?: { _type?: unknown; type?: unknown; version?: unknown } };
    try {
      envelope = JSON.parse(Buffer.from(next.data).toString("utf8")) as { signed?: { _type?: unknown; type?: unknown; version?: unknown } };
    } catch {
      throw new Error("TUF metadata candidate is not valid JSON");
    }
    const expectedType = roleName === "root" || roleName === "timestamp" || roleName === "snapshot"
      ? roleName
      : "targets";
    if (!envelope.signed || (envelope.signed._type ?? envelope.signed.type) !== expectedType || envelope.signed.version !== next.version) {
      throw new Error("TUF metadata role or version does not match its signed envelope");
    }
    if (expectedCurrent !== null
        && (!Number.isSafeInteger(expectedCurrent.version) || expectedCurrent.version < 1
          || !/^[a-f0-9]{64}$/.test(expectedCurrent.sha256))) {
      throw new Error("TUF metadata expected-current identity is invalid");
    }

    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      const current = this.ctx.storage.sql.exec<{
        version: number; sha256: string
      }>("SELECT version, sha256 FROM tuf_metadata WHERE role_name = ?", roleName).toArray()[0] ?? null;

      if (expectedCurrent === null) {
        if (current) throw new Error("TUF metadata compare-and-set expected an empty role");
      } else if (!current || current.version !== expectedCurrent.version || current.sha256 !== expectedCurrent.sha256) {
        throw new Error("TUF metadata compare-and-set current identity changed");
      }

      if (current) {
        if (next.version < current.version) throw new Error("TUF metadata rollback rejected");
        if (next.version === current.version) {
          if (next.sha256 !== current.sha256) throw new Error("same-version TUF metadata replacement rejected");
          return { version: current.version, sha256: current.sha256 };
        }
        if (roleName === "root" && next.version !== current.version + 1) {
          throw new Error("TUF root rotation must advance exactly one version");
        }
      } else if (roleName === "root" && next.version < 1) {
        throw new Error("initial TUF trust anchor version must be positive");
      }

      this.ctx.storage.sql.exec(
        "INSERT INTO tuf_metadata (role_name, version, sha256, data, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(role_name) DO UPDATE SET version = excluded.version, sha256 = excluded.sha256, data = excluded.data, updated_at = excluded.updated_at",
        roleName, next.version, next.sha256, Buffer.from(next.data), Date.now()
      );
      return { version: next.version, sha256: next.sha256 };
    });
  }

  private validateTufRoleName(roleName: string): void {
    if (typeof roleName !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/.test(roleName)
        || roleName.split("/").some((part) => part === "" || part === "." || part === "..")) {
      throw new Error("TUF metadata role name is invalid");
    }
  }

  getRecentOutcomes(): Array<{ outcome: string; releaseVersion: string | null; recordedAt: number }> {
    return this.ctx.storage.sql
      .exec<{ outcome: string; release_version: string | null; recorded_at: number }>(
        "SELECT outcome, release_version, recorded_at FROM run_audit ORDER BY id DESC LIMIT 50"
      )
      .toArray()
      .map((row) => ({
        outcome: row.outcome,
        releaseVersion: row.release_version,
        recordedAt: row.recorded_at
      }));
  }
}

function cryptoSelfTest(): boolean {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const message = Buffer.from("SentryIQ Node A Cloudflare runtime proof");
  const signature = sign(null, message, privateKey);
  if (!verify(null, message, publicKey, signature)) return false;
  if (verify(null, Buffer.from("tampered"), publicKey, signature)) return false;
  return createHash("sha256").update(message).digest("hex").length === 64;
}

export default {
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const stateId = env.NODE_A_STATE.idFromName("node-a-async-tuf-runtime");
    const state = env.NODE_A_STATE.get(stateId);
    try {
      const result = await runNodeAReleaseMonitor(env, state, false);
      await state.recordOutcome(result.event.approved && result.pin_advanced ? "approved" : "rejected", result.release_version);
    } catch (error) {
      if (!(error instanceof NodeAEventAlreadyAlertedError) &&
          !(error instanceof NodeAReleaseMonitorAlertAttemptedError)) {
        await notifyNodeAUncaughtFailure(env, "scheduled_entrypoint", error);
      }
      // Record only a minimal outcome; do not persist exception details or secrets.
      await state.recordOutcome("failed", null);
    }
  },

  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ ok: true, component: "node-a-workers-poc" });
    }
    if (url.pathname === "/runtime-check") {
      const cryptoOk = cryptoSelfTest();
      const sigstoreVerifierLoaded = typeof Verifier === "function";
      const asyncTufUpdaterLoaded = typeof createNodeAAsyncTufUpdater === "function";
      const durableMetadataBindingLoaded = Boolean(env.NODE_A_STATE);
      const r2TargetBindingLoaded = Boolean(env.NODE_A_TARGETS);
      return Response.json({
        cryptoOk,
        sigstoreVerifierLoaded,
        asyncTufUpdaterLoaded,
        durableMetadataBindingLoaded,
        r2TargetBindingLoaded,
        tufNetworkOrCacheInitialized: false,
        productionReady: false
      }, {
        status: cryptoOk && sigstoreVerifierLoaded &&
          asyncTufUpdaterLoaded && durableMetadataBindingLoaded && r2TargetBindingLoaded ? 200 : 503
      });
    }
    if (url.pathname === "/internal/monitor/run" || url.pathname === "/internal/baseline/initialize") {
      const authorization = authorizeNodeATufRequest(request, env.NODE_A_API_TOKEN);
      if (authorization) return authorization;
      const initializeBaseline = url.pathname === "/internal/baseline/initialize";
      if (request.method !== "POST") {
        return new Response("method not allowed", { status: 405, headers: { Allow: "POST" } });
      }
      const requestLength = request.headers.get("content-length");
      if (requestLength !== null && requestLength !== "0") {
        return Response.json({ error: "monitor routes do not accept request bodies" }, { status: 400 });
      }
      if (request.body) {
        try { await request.body.cancel(); } catch { /* body is deliberately unused */ }
      }
      if (initializeBaseline) {
        const baselineAuthorization = authorizeBaselineInitialization(
          request, env.NODE_A_BASELINE_APPROVAL_TOKEN
        );
        if (baselineAuthorization) return baselineAuthorization;
      }

      const missing = requiredNodeAMonitorConfiguration(env);
      if (missing.length > 0) {
        return Response.json({
          error: "Node A monitor is not fully configured",
          missing
        }, { status: 503 });
      }

      try {
        const stateId = env.NODE_A_STATE.idFromName("node-a-async-tuf-runtime");
        const state = env.NODE_A_STATE.get(stateId);
        const result = await runNodeAReleaseMonitor(env, state, initializeBaseline);
        return Response.json({
          ok: result.event.approved && result.pin_advanced,
          mode: initializeBaseline ? "baseline_initialized" : "monitor_run",
          release_version: result.release_version,
          release_commit: result.release_commit,
          release_manifest_sha256: result.release_manifest_sha256,
          release_artifact_sha256: result.release_artifact_sha256,
          approved: result.event.approved,
          pin_advanced: result.pin_advanced,
          mismatch_count: result.event.mismatches.length,
          node4_acknowledged: result.event.event_acknowledgement.status === "accepted"
        }, {
          status: result.event.approved ? 200 : 409,
          headers: { "Cache-Control": "private, no-store" }
        });
      } catch (error) {
        if (!(error instanceof NodeAEventAlreadyAlertedError) &&
            !(error instanceof NodeAReleaseMonitorAlertAttemptedError)) {
          await notifyNodeAUncaughtFailure(env, "manual_entrypoint", error);
        }
        return Response.json(
          { error: "Node A monitor failed; verify monitor configuration and independent alert delivery" },
          { status: 502, headers: { "Cache-Control": "private, no-store" } }
        );
      }
    }

    if (url.pathname === "/internal/tuf/refresh" || url.pathname.startsWith("/internal/tuf/targets/")) {
      const authorization = authorizeNodeATufRequest(request, env.NODE_A_API_TOKEN);
      if (authorization) return authorization;

      if (!env.TUF_ROOT_B64 || !env.TUF_METADATA_URL || !env.TUF_TARGET_URL) {
        return Response.json({ error: "Node A TUF runtime is not fully configured" }, { status: 503 });
      }
      if (url.pathname === "/internal/tuf/refresh" && request.method !== "POST") {
        return new Response("method not allowed", { status: 405, headers: { Allow: "POST" } });
      }
      if (url.pathname.startsWith("/internal/tuf/targets/") && request.method !== "GET") {
        return new Response("method not allowed", { status: 405, headers: { Allow: "GET" } });
      }

      try {
        const trustAnchor = Buffer.from(env.TUF_ROOT_B64, "base64");
        if (trustAnchor.byteLength === 0 || trustAnchor.toString("base64") !== env.TUF_ROOT_B64) {
          return Response.json({ error: "configured TUF trust anchor is not valid base64" }, { status: 503 });
        }
        const metadataUrl = new URL(env.TUF_METADATA_URL);
        const targetUrl = new URL(env.TUF_TARGET_URL);
        if (metadataUrl.protocol !== "https:" || targetUrl.protocol !== "https:") {
          return Response.json({ error: "TUF metadata and target URLs must use HTTPS" }, { status: 503 });
        }

        const stateId = env.NODE_A_STATE.idFromName("node-a-async-tuf-runtime");
        const state = env.NODE_A_STATE.get(stateId);
        return await withNodeARunLease(state, async (currentLock) => {
          const updater = await createNodeAAsyncTufUpdater({
            state,
            bucket: env.NODE_A_TARGETS,
            currentLock,
            trustAnchor: new Uint8Array(trustAnchor),
            metadataBaseUrl: metadataUrl.toString(),
            targetBaseUrl: targetUrl.toString()
          });

          if (url.pathname === "/internal/tuf/refresh") {
            await updater.refresh();
            return Response.json({ ok: true });
          }

          let targetPath: string;
          try {
            targetPath = decodeURIComponent(url.pathname.slice("/internal/tuf/targets/".length));
          } catch {
            return new Response("invalid target path", { status: 400 });
          }
          if (!targetPath) return new Response("target path required", { status: 400 });
          const body = await updater.getTarget(targetPath);
          if (!body) return new Response("target not found", { status: 404 });
          return new Response(body, {
            headers: {
              "Content-Type": "application/octet-stream",
              "Cache-Control": "private, no-store",
              "X-Content-Type-Options": "nosniff"
            }
          });
        });
      } catch {
        return Response.json({ error: "Node A TUF operation failed" }, { status: 502 });
      }
    }
    return new Response("not found", { status: 404 });
  }
};

export { createNodeAAsyncTufUpdater };

export function requiredNodeAMonitorConfiguration(env: Env): string[] {
  const required: Array<[keyof Env, string]> = [
    ["NODE_A_GITHUB_TOKEN", "NODE_A_GITHUB_TOKEN"],
    ["NODE_A_EVENT_TOKEN", "NODE_A_EVENT_TOKEN"],
    ["NODE_A_REPORT_PRIVATE_KEY_B64", "NODE_A_REPORT_PRIVATE_KEY_B64"],
    ["NODE_A_PRIVATE_HOST_TOKEN", "NODE_A_PRIVATE_HOST_TOKEN"],
    ["NODE_A_COLLECTOR_PUBLIC_KEY_B64", "NODE_A_COLLECTOR_PUBLIC_KEY_B64"],
    ["NODE_A_EXPECTED_FILES_JSON", "NODE_A_EXPECTED_FILES_JSON"],
    ["NODE_A_EXPECTED_PRIVATE_CONFIG_JSON", "NODE_A_EXPECTED_PRIVATE_CONFIG_JSON"],
    ["NODE_A_ALERT_URL", "NODE_A_ALERT_URL"],
    ["NODE_A_ALERT_HOST", "NODE_A_ALERT_HOST"],
    ["NODE_A_ALERT_TOKEN", "NODE_A_ALERT_TOKEN"],
    ["TUF_ROOT_B64", "TUF_ROOT_B64"],
    ["TUF_METADATA_URL", "TUF_METADATA_URL"],
    ["TUF_TARGET_URL", "TUF_TARGET_URL"]
  ];
  return required.filter(([key]) => {
    const value = env[key];
    return typeof value !== "string" || value.length === 0;
  }).map(([, label]) => label);
}

async function notifyNodeAUncaughtFailure(
  env: Env,
  phase: "scheduled_entrypoint" | "manual_entrypoint",
  error: unknown
): Promise<void> {
  if (!env.NODE_A_ALERT_URL || !env.NODE_A_ALERT_HOST || !env.NODE_A_ALERT_TOKEN) return;
  try {
    const webhook = new NodeAOwnerAlertWebhook(
      env.NODE_A_ALERT_URL, env.NODE_A_ALERT_HOST, env.NODE_A_ALERT_TOKEN
    );
    await webhook.send("monitor_preflight_failed", {
      node_id: "integrity-a",
      phase,
      exception: error instanceof Error ? error.name : "UnknownError"
    });
  } catch {
    // The independent endpoint is unavailable or invalid; never persist its credentials/details.
  }
}

function parseNodeADigestMap(source: string, label: string): Record<string, string> {
  let parsed: unknown;
  try { parsed = JSON.parse(source); }
  catch { throw new Error(label + " must be valid JSON"); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(label + " must be a JSON object");
  }
  return parsed as Record<string, string>;
}

export function authorizeBaselineInitialization(
  request: Request,
  expectedToken: string | undefined
): Response | null {
  if (!expectedToken) {
    return Response.json({ error: "one-time baseline approval token is not configured" }, { status: 503 });
  }
  if (expectedToken.length < 32 || expectedToken.length > 512 ||
      /[\x00-\x1f\x7f]/.test(expectedToken)) {
    return Response.json({ error: "baseline approval token configuration is invalid" }, { status: 503 });
  }
  const expected = Buffer.from(expectedToken, "utf8");
  const providedText = request.headers.get("x-node-a-baseline-approval") ?? "";
  const provided = Buffer.from(providedText, "utf8");
  if (providedText.length !== expectedToken.length ||
      provided.byteLength !== expected.byteLength || !timingSafeEqual(provided, expected)) {
    return Response.json({ error: "baseline approval required" }, { status: 401 });
  }
  return null;
}

async function runNodeAReleaseMonitor(
  env: Env,
  state: DurableObjectStub<NodeAState>,
  initializeBaseline: boolean
) {
  if (!env.TUF_ROOT_B64 || !env.TUF_METADATA_URL || !env.TUF_TARGET_URL ||
      !env.NODE_A_GITHUB_TOKEN || !env.NODE_A_EVENT_TOKEN ||
      !env.NODE_A_REPORT_PRIVATE_KEY_B64 || !env.NODE_A_PRIVATE_HOST_TOKEN ||
      !env.NODE_A_COLLECTOR_PUBLIC_KEY_B64 || !env.NODE_A_EXPECTED_FILES_JSON ||
      !env.NODE_A_EXPECTED_PRIVATE_CONFIG_JSON || !env.NODE_A_ALERT_URL ||
      !env.NODE_A_ALERT_HOST || !env.NODE_A_ALERT_TOKEN) {
    throw new Error("Node A monitor configuration is incomplete");
  }
  const trustAnchor = Buffer.from(env.TUF_ROOT_B64, "base64");
  if (trustAnchor.byteLength === 0 || trustAnchor.toString("base64") !== env.TUF_ROOT_B64) {
    throw new Error("configured TUF root is not canonical base64");
  }
  const metadataUrl = new URL(env.TUF_METADATA_URL);
  const targetUrl = new URL(env.TUF_TARGET_URL);
  if (metadataUrl.protocol !== "https:" || targetUrl.protocol !== "https:" ||
      metadataUrl.username !== "" || metadataUrl.password !== "" ||
      targetUrl.username !== "" || targetUrl.password !== "" ||
      (metadataUrl.port !== "" && metadataUrl.port !== "443") ||
      (targetUrl.port !== "" && targetUrl.port !== "443") ||
      metadataUrl.search !== "" || metadataUrl.hash !== "" ||
      targetUrl.search !== "" || targetUrl.hash !== "") {
    throw new Error("TUF metadata and target base URLs must be clean HTTPS URLs");
  }

  const expectedFiles = parseNodeADigestMap(env.NODE_A_EXPECTED_FILES_JSON, "NODE_A_EXPECTED_FILES_JSON");
  const expectedPrivateConfig = parseNodeADigestMap(
    env.NODE_A_EXPECTED_PRIVATE_CONFIG_JSON, "NODE_A_EXPECTED_PRIVATE_CONFIG_JSON"
  );
  const alertWebhook = new NodeAOwnerAlertWebhook(
    env.NODE_A_ALERT_URL, env.NODE_A_ALERT_HOST, env.NODE_A_ALERT_TOKEN
  );
  const notifyOwnerDirectly = (reason: string, context: Record<string, unknown>) =>
    alertWebhook.send(reason, context);
  const privateHost = new NodeAPrivateHostGate(
    env.NODE_A_PRIVATE_HOST_TOKEN,
    env.NODE_A_COLLECTOR_PUBLIC_KEY_B64,
    expectedFiles,
    expectedPrivateConfig
  );
  const eventRunner = new NodeAEventRunner(
    new Node4EventClient(env.NODE_A_EVENT_TOKEN),
    new NodeAReportSigner("integrity-a", env.NODE_A_REPORT_PRIVATE_KEY_B64),
    privateHost,
    notifyOwnerDirectly
  );

  let currentLock: (() => RunLock) | undefined;
  let updater: Awaited<ReturnType<typeof createNodeAAsyncTufUpdater>> | undefined;
  const monitor = new NodeAReleaseMonitor({
    fetcher: new NodeAReleaseAssetFetcher(),
    assertBaseline: initializeBaseline ? undefined : async () => {
      if (!await state.getPin()) throw new Error("independent release baseline has not been initialized");
    },
    refreshTuf: async () => {
      if (!currentLock) throw new Error("Node A run fence is unavailable");
      updater = await createNodeAAsyncTufUpdater({
        state,
        bucket: env.NODE_A_TARGETS,
        currentLock: () => {
          if (!currentLock) throw new Error("Node A run fence is unavailable");
          return currentLock();
        },
        trustAnchor: new Uint8Array(trustAnchor),
        metadataBaseUrl: metadataUrl.toString(),
        targetBaseUrl: targetUrl.toString()
      });
      await updater.refresh();
    },
    loadTrustedRoot: async () => {
      if (!updater) throw new Error("Sigstore TUF updater was not initialized");
      const target = await updater.getTarget("trusted_root.json");
      if (!target) throw new Error("verified Sigstore trusted_root.json target is unavailable");
      return new TextDecoder("utf-8", { fatal: true }).decode(target);
    },
    eventRunner,
    advancePin: (candidate) => initializeBaseline
      ? state.initializeBaseline(candidate)
      : state.advancePin(candidate, currentLock ? currentLock() : (() => { throw new Error("Node A run fence is unavailable"); })()),
    notifyOwnerDirectly,
    withRunLease: async <T>(operation: () => Promise<T>) =>
      withNodeARunLease(state, (lock) => {
        currentLock = lock;
        return operation();
      }),
    apiToken: env.NODE_A_GITHUB_TOKEN
  });
  return monitor.run();
}

export function authorizeNodeATufRequest(request: Request, expectedToken: string | undefined): Response | null {
  if (!expectedToken) return Response.json({ error: "Node A API token is not configured" }, { status: 503 });
  const tokenBytes = Buffer.from(expectedToken);
  if (tokenBytes.byteLength < 32 || tokenBytes.byteLength > 512 ||
      /[\u0000-\u001f\u007f]/.test(expectedToken)) {
    return Response.json(
      { error: "Node A API token must be 32-512 bytes and contain no control characters" },
      { status: 503 }
    );
  }
  const provided = request.headers.get("authorization") ?? "";
  const expected = "Bearer " + expectedToken;
  const left = Buffer.from(provided);
  const right = Buffer.from(expected);
  if (left.byteLength !== right.byteLength || !timingSafeEqual(left, right)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  return null;
}

async function withNodeARunLease<T>(
  state: DurableObjectStub<NodeAState>,
  operation: (currentLock: () => RunLock) => Promise<T>
): Promise<T> {
  let activeLock = await state.acquireRunLock(60_000);
  let stopped = false;
  let renewalError: unknown;
  let renewalQueue: Promise<void> = Promise.resolve();

  const timer = setInterval(() => {
    renewalQueue = renewalQueue.then(async () => {
      if (!stopped && !renewalError) {
        activeLock = await state.renewRunLock(activeLock, 60_000);
      }
    }).catch((error) => {
      renewalError = error;
    });
  }, 20_000);

  const currentLock = (): RunLock => {
    if (renewalError) throw renewalError;
    return activeLock;
  };

  try {
    return await operation(currentLock);
  } finally {
    stopped = true;
    clearInterval(timer);
    await renewalQueue;
    try { await state.releaseRunLock(activeLock); } catch { /* expired or taken over; stale owner cannot commit */ }
  }
}
