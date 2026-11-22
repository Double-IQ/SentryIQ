import { DurableObject } from "cloudflare:workers";
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import * as tufFs from "./tuf-fs";
import * as tufFsPromises from "./tuf-fs-promises";
import { commitTufFsContext, createTufFsContext, discardTufFsContext, runWithTufFsContext } from "./tuf-fs-context";
import path from "node:path";
import { Verifier } from "@sigstore/verify";
import { initTUF } from "@sigstore/tuf";
import { TrustedRoot } from "@sigstore/protobuf-specs";

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
  fencingToken: number;
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
        expires_at INTEGER NOT NULL,
        fencing_token INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS run_fence (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        last_fence INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_metadata_state (
        path TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        version INTEGER NOT NULL,
        digest TEXT NOT NULL,
        metadata_type TEXT NOT NULL,
        expires TEXT,
        fencing_token INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tuf_metadata_history (
        path TEXT NOT NULL,
        version INTEGER NOT NULL,
        digest TEXT NOT NULL,
        accepted_at INTEGER NOT NULL,
        fencing_token INTEGER NOT NULL,
        PRIMARY KEY (path, version)
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
    const runLockColumns = ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(run_lock)").toArray();
    if (!runLockColumns.some((column) => column.name === "fencing_token")) {
      ctx.storage.sql.exec("ALTER TABLE run_lock ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 0");
    }
    ctx.storage.sql.exec("INSERT OR IGNORE INTO run_fence (singleton, last_fence) VALUES (1, 0)");
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

  advancePin(candidate: PinCandidate, lockToken: string, fencingToken: number): ReleasePin {
    validatePin(candidate);
    if (!/^[a-f0-9]{64}$/.test(lockToken)) throw new Error("run lock token is invalid");
    return this.ctx.storage.transactionSync(() => {
      this.assertRunLock(lockToken, fencingToken);
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
      const lastFence = this.ctx.storage.sql
        .exec<{ last_fence: number }>("SELECT last_fence FROM run_fence WHERE singleton = 1")
        .toArray()[0]?.last_fence ?? 0;
      const fencingToken = lastFence + 1;
      this.ctx.storage.sql.exec("UPDATE run_fence SET last_fence = ? WHERE singleton = 1", fencingToken);
      const lock = { token, fencingToken, expiresAt: now + leaseMs };
      this.ctx.storage.sql.exec(
        "INSERT INTO run_lock (singleton, token, expires_at, fencing_token) VALUES (1, ?, ?, ?) ON CONFLICT(singleton) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at, fencing_token = excluded.fencing_token",
        lock.token, lock.expiresAt, lock.fencingToken
      );
      return lock;
    });
  }

  renewRunLock(token: string, fencingToken: number, leaseMs: number): RunLock {
    if (!/^[a-f0-9]{64}$/.test(token) || !Number.isSafeInteger(fencingToken) || fencingToken < 1
        || !Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 15 * 60_000) {
      throw new Error("invalid run lock token, fencing token or lease");
    }
    return this.ctx.storage.transactionSync(() => {
      const now = Date.now();
      this.assertRunLock(token, fencingToken);
      const lock = { token, fencingToken, expiresAt: now + leaseMs };
      this.ctx.storage.sql.exec("UPDATE run_lock SET expires_at = ? WHERE singleton = 1", lock.expiresAt);
      return lock;
    });
  }

  private assertRunLock(token: string, fencingToken: number): void {
    const current = this.ctx.storage.sql
      .exec<{ token: string; expires_at: number; fencing_token: number }>(
        "SELECT token, expires_at, fencing_token FROM run_lock WHERE singleton = 1"
      ).toArray()[0];
    if (!current || current.token !== token || current.fencing_token !== fencingToken || current.expires_at <= Date.now()) {
      throw new Error("valid active Node A run lock required");
    }
  }

  releaseRunLock(token: string, fencingToken: number): void {
    this.ctx.storage.transactionSync(() => {
      const current = this.ctx.storage.sql
        .exec<{ token: string; fencing_token: number }>(
          "SELECT token, fencing_token FROM run_lock WHERE singleton = 1"
        ).toArray()[0];
      if (!current || current.token !== token || current.fencing_token !== fencingToken) {
        throw new Error("run lock token or fencing token mismatch");
      }
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

  private persistTufFile(path: string, data: Buffer, fencingToken: number): void {
    const metadataMarker = "/metadata/";
    const metadataIndex = path.lastIndexOf(metadataMarker);
    if (metadataIndex >= 0) {
      let parsed: { signed?: { _type?: string; version?: number; expires?: string } };
      try {
        parsed = JSON.parse(data.toString("utf8")) as typeof parsed;
      } catch {
        throw new Error("TUF metadata write is not valid JSON");
      }
      const signed = parsed.signed;
      if (!signed || typeof signed._type !== "string" || !Number.isSafeInteger(signed.version) || !signed.version) {
        throw new Error("TUF metadata write is missing a valid signed role and version");
      }
      const role = path.slice(metadataIndex + metadataMarker.length);
      const digest = createHash("sha256").update(data).digest("hex");
      const current = this.ctx.storage.sql.exec<{ version: number; digest: string }>(
        "SELECT version, digest FROM tuf_metadata_state WHERE path = ?", path
      ).toArray()[0];
      if (current) {
        if (signed.version! < current.version) throw new Error("TUF metadata rollback rejected");
        if (signed.version === current.version && digest !== current.digest) {
          throw new Error("same-version TUF metadata replacement rejected");
        }
        if (role === "root.json" && signed.version! > current.version + 1) {
          throw new Error("TUF root version skip rejected");
        }
      }
      const now = Date.now();
      this.ctx.storage.sql.exec(
        "INSERT INTO tuf_metadata_state (path, role, version, digest, metadata_type, expires, fencing_token, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET role = excluded.role, version = excluded.version, digest = excluded.digest, metadata_type = excluded.metadata_type, expires = excluded.expires, fencing_token = excluded.fencing_token, updated_at = excluded.updated_at",
        path, role, signed.version, digest, signed._type, signed.expires ?? null, fencingToken, now
      );
      this.ctx.storage.sql.exec(
        "INSERT OR IGNORE INTO tuf_metadata_history (path, version, digest, accepted_at, fencing_token) VALUES (?, ?, ?, ?, ?)",
        path, signed.version, digest, now, fencingToken
      );
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO tuf_files (path, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
      path, data, Date.now()
    );
  }

  async testDurableTufRefresh(rootBase64: string, forceCache = false): Promise<{
    rootVersion: number;
    rootHistory: number[];
    metadataRoles: Array<{ role: string; version: number }>;
    tlogCount: number;
    certificateAuthorityCount: number;
    trustedRootTargetPersisted: boolean;
    fencingToken: number;
    forceCache: boolean;
  }> {
    const lock = this.acquireRunLock(15 * 60_000);
    const cachePath = "/node-a/sigstore-tuf-cache";
    const rootPath = "/tmp/sentryiq-node-a-tuf-root.json";
    const context = createTufFsContext(this.ctx.storage.sql, (filePath, data) => {
      this.ctx.storage.transactionSync(() => {
        this.assertRunLock(lock.token, lock.fencingToken);
        this.persistTufFile(filePath, data, lock.fencingToken);
      });
    });
    try {
      return await runWithTufFsContext(context, async () => {
        tufFs.writeFileSync(rootPath, Buffer.from(rootBase64, "base64"));
        const client = await initTUF({
          cachePath,
          rootPath,
          mirrorURL: "https://tuf-repo-cdn.sigstore.dev",
          forceCache,
          forceInit: false,
          retry: { retries: 2 },
          timeout: 10_000
        });
        const trustedRootText = await client.getTarget("trusted_root.json");
        const trustedRoot = TrustedRoot.fromJSON(JSON.parse(trustedRootText));
        const rootRow = this.ctx.storage.sql.exec<{ path: string; data: ArrayBuffer | Uint8Array }>(
          "SELECT path, data FROM tuf_files WHERE path LIKE ? AND path LIKE '%/metadata/root.json' ORDER BY updated_at DESC LIMIT 1",
          cachePath + "%"
        ).toArray()[0];
        if (!rootRow) throw new Error("Durable TUF root metadata was not persisted");
        const rootMetadata = JSON.parse(Buffer.from(rootRow.data).toString("utf8")) as { signed?: { version?: number } };
        const rootVersion = rootMetadata.signed?.version;
        if (!Number.isSafeInteger(rootVersion) || !rootVersion) throw new Error("persisted TUF root version is invalid");
        const rootHistory = this.ctx.storage.sql.exec<{ version: number }>(
          "SELECT version FROM tuf_metadata_history WHERE path = ? ORDER BY version",
          rootRow.path
        ).toArray().map((row) => row.version);
        const metadataRoles = this.ctx.storage.sql.exec<{ role: string; version: number }>(
          "SELECT role, version FROM tuf_metadata_state WHERE path LIKE ? ORDER BY role",
          cachePath + "%"
        ).toArray();
        const target = this.ctx.storage.sql.exec<{ present: number }>(
          "SELECT 1 AS present FROM tuf_files WHERE path LIKE ? AND path LIKE '%trusted_root.json' LIMIT 1",
          cachePath + "%"
        ).toArray()[0];
        return {
          rootVersion,
          rootHistory,
          metadataRoles,
          tlogCount: trustedRoot.tlogs.length,
          certificateAuthorityCount: trustedRoot.certificateAuthorities.length,
          trustedRootTargetPersisted: Boolean(target),
          fencingToken: lock.fencingToken,
          forceCache
        };
      });
    } finally {
      discardTufFsContext(context);
      this.releaseRunLock(lock.token, lock.fencingToken);
    }
  }

  testTufFencedWrite(path: string, data: string, token: string, fencingToken: number): void {
    this.ctx.storage.transactionSync(() => {
      this.assertRunLock(token, fencingToken);
      this.persistTufFile(path, Buffer.from(data), fencingToken);
    });
  }

  async testTufFilesystemAdapter(): Promise<{ persistentRead: string; copiedRead: string; temporaryRead: string; temporaryExistsAfterCleanup: boolean; seededTufRootVersion: number; stagedWriteVisibleBeforeCommit: boolean; discardedWriteAbsentAfterRollback: boolean }> {
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
      const discardedPath = "/node-a/tuf/cache/uncommitted.json";
      tufFs.writeFileSync(discardedPath, "must-not-persist");
      const stagedWriteVisibleBeforeCommit = tufFs.existsSync(discardedPath);
      discardTufFsContext(context);
      const discardedWriteAbsentAfterRollback = !tufFs.existsSync(discardedPath);
      tufFs.writeFileSync(rootPath, Buffer.from("persistent-root-fixture"));
      tufFs.copyFileSync(rootPath, copiedPath);

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
        temporaryExistsAfterCleanup: tufFs.existsSync(tempPath),
        stagedWriteVisibleBeforeCommit,
        discardedWriteAbsentAfterRollback
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
