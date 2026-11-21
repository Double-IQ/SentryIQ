import { DurableObject } from "cloudflare:workers";
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import * as tufFs from "fs";
import * as tufFsPromises from "fs/promises";
import { commitTufFsContext, createTufFsContext, discardTufFsContext, runWithTufFsContext } from "./tuf-fs-context";
import path from "node:path";
import { Verifier } from "@sigstore/verify";
import { initTUF } from "@sigstore/tuf";

export interface Env {
  NODE_A_STATE: DurableObjectNamespace<NodeAState>;
}

export interface ReleasePin {
  version: string;
  commit: string;
  manifestSha256: string;
  zipSha256: string;
  updatedAt: number;
}

type PinCandidate = Omit<ReleasePin, "updatedAt">;

type RunLock = {
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
      CREATE TABLE IF NOT EXISTS run_lock (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        token TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_files (
        path TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        updated_at INTEGER NOT NULL
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

  advancePin(candidate: PinCandidate, lockToken: string): ReleasePin {
    validatePin(candidate);
    if (!/^[a-f0-9]{64}$/.test(lockToken)) throw new Error("run lock token is invalid");
    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lockToken);
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
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 15 * 60_000) {
      throw new Error("invalid run lock time or lease");
    }
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      const token = randomBytes(32).toString("hex");
      const current = this.ctx.storage.sql
        .exec<{ token: string; expires_at: number }>(
          "SELECT token, expires_at FROM run_lock WHERE singleton = 1"
        ).toArray()[0];
      if (current && current.expires_at > now) {
        throw new Error("Node A run already holds the durable lock");
      }
      const lock = { token, expiresAt: now + leaseMs };
      this.ctx.storage.sql.exec(
        `INSERT INTO run_lock (singleton, token, expires_at) VALUES (1, ?, ?)
         ON CONFLICT(singleton) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at`,
        lock.token,
        lock.expiresAt
      );
      return lock;
    });
  }

  renewRunLock(token: string, leaseMs: number): RunLock {
    if (!/^[a-f0-9]{64}$/.test(token) || !Number.isSafeInteger(leaseMs)
        || leaseMs < 1_000 || leaseMs > 15 * 60_000) {
      throw new Error("invalid run lock token or lease");
    }
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.assertRunLock(token);
      const lock = { token, expiresAt: now + leaseMs };
      this.ctx.storage.sql.exec("UPDATE run_lock SET expires_at = ? WHERE singleton = 1", lock.expiresAt);
      return lock;
    });
  }

  private assertRunLock(token: string): void {
    const current = this.ctx.storage.sql
      .exec<{ token: string; expires_at: number }>("SELECT token, expires_at FROM run_lock WHERE singleton = 1")
      .toArray()[0];
    if (!current || current.token !== token || current.expires_at <= Date.now()) {
      throw new Error("valid active Node A run lock required");
    }
  }

  releaseRunLock(token: string): void {
    this.ctx.storage.transactionSync(() => {
      const current = this.ctx.storage.sql
        .exec<{ token: string }>("SELECT token FROM run_lock WHERE singleton = 1")
        .toArray()[0];
      if (!current || current.token !== token) throw new Error("run lock token mismatch");
      this.ctx.storage.sql.exec("DELETE FROM run_lock WHERE singleton = 1");
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

  async testUpstreamTufCacheBootstrap(rootBase64: string): Promise<{ rootVersion: number; cacheReadAfterBootstrap: boolean; expectedNetworkFailure: boolean; stagedPaths: string[]; refreshError: string | null }> {
    const context = createTufFsContext(this.ctx.storage.sql);
    return runWithTufFsContext(context, async () => {
      const rootPath = "/node-a/tuf-fixtures/root.json";
      const cachePath = "/node-a/tuf-upstream-cache";
      tufFs.mkdirSync("/node-a/tuf-fixtures", { recursive: true });
      tufFs.writeFileSync(rootPath, Buffer.from(rootBase64, "base64"));

      let expectedNetworkFailure = false;
      let refreshError: string | null = null;
      try {
        await initTUF({
          cachePath,
          rootPath,
          mirrorURL: "https://127.0.0.1:1",
          forceCache: false,
          forceInit: true,
          retry: { retries: 0 },
          timeout: 250
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        refreshError = message;
        if (/EPERM|EACCES|ENOENT/.test(message)) {
          throw new Error("upstream TUF cache initialization did not use the Durable Object filesystem adapter: " + message);
        }
        expectedNetworkFailure = true;
      }

      const cachedRootPath = path.join(cachePath, encodeURIComponent("127.0.0.1:1"), "root.json");
      const stagedPaths = [...context.stagedFiles.keys()];
      if (!tufFs.existsSync(cachedRootPath)) {
        discardTufFsContext(context);
        return { rootVersion: 0, cacheReadAfterBootstrap: false, expectedNetworkFailure, stagedPaths, refreshError };
      }
      const cachedRoot = JSON.parse(tufFs.readFileSync(cachedRootPath, "utf8") as string) as { signed?: { version?: number } };
      if (!Number.isSafeInteger(cachedRoot.signed?.version) || !cachedRoot.signed?.version) {
        throw new Error("upstream TUF client did not seed a readable root through Durable Object storage");
      }
      discardTufFsContext(context);
      return {
        rootVersion: cachedRoot.signed.version,
        cacheReadAfterBootstrap: true,
        expectedNetworkFailure,
        stagedPaths,
        refreshError
      };
    });
  }

  async testTufFilesystemAdapter(): Promise<{ persistentRead: string; copiedRead: string; temporaryRead: string; temporaryExistsAfterCleanup: boolean; seededTufRootVersion: number }> {
    const context = createTufFsContext(this.ctx.storage.sql);
    return runWithTufFsContext(context, async () => {
      const rootPath = "/node-a/tuf/repository/root.json";
      const copiedPath = "/node-a/tuf/cache/root.json";
      tufFs.mkdirSync("/node-a/tuf/repository", { recursive: true });
      tufFs.mkdirSync("/node-a/tuf/cache", { recursive: true });
      tufFs.writeFileSync(rootPath, Buffer.from("persistent-root-fixture"));
      tufFs.copyFileSync(rootPath, copiedPath);
      const persistentRead = tufFs.readFileSync(rootPath, "utf8") as string;
      const copiedRead = tufFs.readFileSync(copiedPath, "utf8") as string;

      const tempDir = await tufFsPromises.mkdtemp("/tmp/");
      const tempPath = path.join(tempDir, "tempfile");
      await tufFsPromises.open(tempPath, "a");
      const stream = tufFs.createWriteStream(tempPath);
      stream.write(Buffer.from("request-scoped-target"));
      await new Promise<void>((resolve, reject) => stream.close((error) => error ? reject(error) : resolve()));
      const temporaryRead = tufFs.readFileSync(tempPath, "utf8") as string;
      await tufFsPromises.rm(tempDir, { recursive: true, force: true });
      this.ctx.storage.transactionSync(() => commitTufFsContext(context));
      return {
        persistentRead,
        copiedRead,
        temporaryRead,
        temporaryExistsAfterCleanup: tufFs.existsSync(tempPath)
      };
    });
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
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ ok: true, component: "node-a-workers-poc" });
    }
    if (url.pathname === "/runtime-check") {
      const cryptoOk = cryptoSelfTest();
      const sigstoreVerifierLoaded = typeof Verifier === "function";
      const tufClientLoaded = typeof initTUF === "function";
      return Response.json({
        cryptoOk,
        sigstoreVerifierLoaded,
        tufClientLoaded,
        tufNetworkOrCacheInitialized: false,
        productionReady: false
      }, { status: cryptoOk && sigstoreVerifierLoaded && tufClientLoaded ? 200 : 503 });
    }
    return new Response("not found", { status: 404 });
  }
};
