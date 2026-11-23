import { DurableObject } from "cloudflare:workers";
import { Buffer } from "node:buffer";
import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";
import { Verifier } from "@sigstore/verify";
import { createNodeAAsyncTufUpdater } from "./node-a-tuf-runtime";
import type { CommittedTufTarget, TufTargetDescriptor } from "./tuf-storage-contract";

export interface Env {
  NODE_A_STATE: DurableObjectNamespace<NodeAState>;
  NODE_A_TARGETS: R2Bucket;
  NODE_A_API_TOKEN?: string;
  TUF_ROOT_B64?: string;
  TUF_METADATA_URL?: string;
  TUF_TARGET_URL?: string;
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

  commitTufTargetPointer(
    descriptor: TufTargetDescriptor,
    objectKey: string,
    lock: RunLock
  ): CommittedTufTarget {
    this.validateRunLock(lock);
    this.validateTufTargetDescriptor(descriptor);
    if (!/^objects\/[a-f0-9-]{36}$/.test(objectKey)) {
      throw new Error("TUF target object key is invalid");
    }
    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lock);
      const committedAt = Date.now();
      this.ctx.storage.sql.exec(
        "INSERT INTO tuf_target_pointers (target_path, object_key, length, hashes_json, fence, committed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(target_path) DO UPDATE SET object_key = excluded.object_key, length = excluded.length, hashes_json = excluded.hashes_json, fence = excluded.fence, committed_at = excluded.committed_at",
        descriptor.targetPath, objectKey, descriptor.length, JSON.stringify(descriptor.hashes), lock.fence, committedAt
      );
      return { ...descriptor, hashes: { ...descriptor.hashes }, objectKey, fence: lock.fence, committedAt };
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
    if (typeof targetPath !== "string" || targetPath.length === 0 || targetPath.length > 1024 || targetPath.startsWith("/") ||
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
        status: cryptoOk && sigstoreVerifierLoaded && tufClientLoaded &&
          asyncTufUpdaterLoaded && durableMetadataBindingLoaded && r2TargetBindingLoaded ? 200 : 503
      });
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

function authorizeNodeATufRequest(request: Request, expectedToken: string | undefined): Response | null {
  if (!expectedToken) return Response.json({ error: "Node A API token is not configured" }, { status: 503 });
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
