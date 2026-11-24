import { Buffer } from "node:buffer";
import { createPublicKey, verify } from "node:crypto";
import { assertNoDuplicateJsonKeys, type VerifiedReleaseManifest } from "./release-manifest";

const PRIVATE_HOST_ENDPOINT = "https://sentryiq.bichet.co.za/private-host-attestation";
const REPOSITORY = "Double-IQ/SentryIQ";
const REPOSITORY_ID = "1345956206";
const MAX_ENVELOPE_BYTES = 1_048_576;
const MAX_PAYLOAD_BYTES = 786_432;
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface PrivateHostResult {
  readonly approved: boolean;
  readonly collectorId: "sentryiq-host-attestor";
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly filesChecked: number;
  readonly privateConfigChecked: number;
  readonly mismatches: readonly { path: string; reason: string }[];
}

/** A-only private-host collector transport and independently pinned verifier. */
export class NodeAPrivateHostGate {
  private readonly collectorKey: ReturnType<typeof createPublicKey>;

  constructor(
    private readonly bearerToken: string,
    collectorPublicKeyBase64: string,
    private readonly expectedFiles: Readonly<Record<string, string>>,
    private readonly expectedPrivateConfig: Readonly<Record<string, string>>,
    private readonly request: typeof fetch = fetch,
    private readonly clock: () => number = () => Math.floor(Date.now() / 1000)
  ) {
    if (!/^[A-Za-z0-9_-]{40,128}$/.test(bearerToken)) {
      throw new Error("private-host gate requires a strong A-only bearer credential");
    }
    if (!/^[A-Za-z0-9+/]{43}=$/.test(collectorPublicKeyBase64)) {
      throw new Error("private-host collector public key is not canonical base64");
    }
    const rawKey = Buffer.from(collectorPublicKeyBase64, "base64");
    if (rawKey.byteLength !== 32 || rawKey.toString("base64") !== collectorPublicKeyBase64) {
      throw new Error("private-host collector key must be a canonical 32-byte Ed25519 public key");
    }
    this.collectorKey = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, rawKey]),
      format: "der",
      type: "spki"
    });
    validateExpectedMap(expectedFiles, false);
    validateExpectedMap(expectedPrivateConfig, true);
    if (Object.keys(expectedFiles).length < 1 || Object.keys(expectedFiles).length > 5000 ||
        Object.keys(expectedPrivateConfig).length > 100) {
      throw new Error("private-host pinned inventory is empty or exceeds its configured bounds");
    }
  }

  async verify(input: {
    readonly nonce: string;
    readonly releaseVersion: string;
    readonly commit: string;
    readonly manifestSha256: string;
    readonly artifactSha256: string;
    readonly manifest: VerifiedReleaseManifest;
  }): Promise<PrivateHostResult> {
    const version = normalizeVersion(input.releaseVersion);
    const commit = input.commit.toLowerCase();
    const nonce = input.nonce.toLowerCase();
    const manifestSha256 = input.manifestSha256.toLowerCase();
    const artifactSha256 = input.artifactSha256.toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(nonce) || !/^[a-f0-9]{40}$/.test(commit) ||
        !/^[a-f0-9]{64}$/.test(manifestSha256) || !/^[a-f0-9]{64}$/.test(artifactSha256) ||
        input.manifest.version !== version || input.manifest.commit !== commit ||
        input.manifest.sha256 !== manifestSha256) {
      throw new Error("private-host challenge context does not match verified release evidence");
    }
    const manifestEntries = new Map(input.manifest.files.map((entry) => [entry.path, entry.sha256]));
    for (const [path, digest] of Object.entries(this.expectedFiles)) {
      if (manifestEntries.get(path) !== digest) {
        throw new Error("private-host pinned file policy does not match the verified release manifest");
      }
    }

    const response = await this.request(PRIVATE_HOST_ENDPOINT, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      headers: {
        Authorization: "Bearer " + this.bearerToken,
        "Content-Type": "application/json",
        Accept: "application/json",
        "Cache-Control": "no-store"
      },
      body: JSON.stringify({
        schema_version: 1,
        node_id: "integrity-a",
        nonce,
        release_version: version,
        commit,
        manifest_sha256: manifestSha256,
        artifact_sha256: artifactSha256
      })
    });
    if (response.status !== 200) {
      if (response.body) await response.body.cancel();
      throw new Error("private-host collector returned an unexpected HTTP status");
    }
    const envelopeBytes = await readBounded(response, MAX_ENVELOPE_BYTES);
    const envelopeText = new TextDecoder("utf-8", { fatal: true }).decode(envelopeBytes);
    assertNoDuplicateJsonKeys(envelopeText);
    const envelope: unknown = JSON.parse(envelopeText);
    if (!isRecord(envelope) || Object.keys(envelope).length !== 2 ||
        typeof envelope.payload !== "string" || typeof envelope.signature !== "string") {
      throw new Error("private-host collector envelope schema is invalid");
    }
    const payloadBytes = decodeCanonicalBase64(envelope.payload, MAX_PAYLOAD_BYTES);
    const signature = decodeCanonicalBase64(envelope.signature, 64);
    if (signature.byteLength !== 64 || !verify(null, payloadBytes, this.collectorKey, signature)) {
      throw new Error("private-host collector Ed25519 signature is invalid");
    }
    return this.verifyPayload(payloadBytes, { nonce, version, commit, manifestSha256, artifactSha256 });
  }

  private verifyPayload(
    payloadBytes: Uint8Array,
    expected: { nonce: string; version: string; commit: string; manifestSha256: string; artifactSha256: string }
  ): PrivateHostResult {
    const payloadText = new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes);
    assertNoDuplicateJsonKeys(payloadText);
    const parsed: unknown = JSON.parse(payloadText);
    const requiredFields = [
      "schema_version", "collector_id", "issued_at", "expires_at", "nonce",
      "target_origin", "repository", "repository_id", "release_version",
      "tag", "commit", "manifest_sha256", "artifact_sha256", "files",
      "private_config", "decision"
    ];
    if (!isRecord(parsed) || !sameStringSet(Object.keys(parsed), requiredFields) ||
        parsed.schema_version !== 1 || parsed.collector_id !== "sentryiq-host-attestor" ||
        !Number.isSafeInteger(parsed.issued_at) || (parsed.issued_at as number) < 1 ||
        !Number.isSafeInteger(parsed.expires_at) ||
        (parsed.expires_at as number) <= (parsed.issued_at as number) ||
        (parsed.expires_at as number) > (parsed.issued_at as number) + 120 ||
        parsed.nonce !== expected.nonce || parsed.target_origin !== "https://sentryiq.bichet.co.za" ||
        parsed.repository !== REPOSITORY || parsed.repository_id !== REPOSITORY_ID ||
        parsed.release_version !== expected.version || parsed.tag !== "v" + expected.version ||
        parsed.commit !== expected.commit || parsed.manifest_sha256 !== expected.manifestSha256 ||
        parsed.artifact_sha256 !== expected.artifactSha256 ||
        !["approve", "reject"].includes(String(parsed.decision)) ||
        !Array.isArray(parsed.files) || parsed.files.length > 5000 ||
        !Array.isArray(parsed.private_config) || parsed.private_config.length > 100) {
      throw new Error("private-host signed payload identity, freshness or schema is invalid");
    }

    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 1 ||
        (parsed.issued_at as number) > now + 15 || (parsed.expires_at as number) < now) {
      throw new Error("private-host signed attestation is stale or not yet valid");
    }

    const mismatches: Array<{ path: string; reason: string }> = [];
    const seenFiles = new Set<string>();
    for (const raw of parsed.files) {
      if (!isRecord(raw) || typeof raw.path !== "string" || !isSafeRelativePath(raw.path) ||
          seenFiles.has(raw.path) ||
          !["match", "missing", "unreadable", "symlink", "permission_mismatch", "digest_mismatch", "unexpected"].includes(String(raw.result))) {
        throw new Error("private-host file evidence contains an invalid or duplicate entry");
      }
      const path = raw.path;
      seenFiles.add(path);
      if (raw.result === "unexpected") {
        if (Object.prototype.hasOwnProperty.call(this.expectedFiles, path)) {
          throw new Error("required private-host file cannot be marked unexpected");
        }
        mismatches.push({ path, reason: "unexpected" });
        continue;
      }
      const expectedDigest = this.expectedFiles[path];
      if (!expectedDigest || raw.expected_sha256 !== expectedDigest) {
        throw new Error("private-host file evidence does not match the node-pinned inventory");
      }
      const observed = raw.observed_sha256;
      if (raw.result === "match") {
        if (typeof observed !== "string" || !/^[a-f0-9]{64}$/.test(observed) || observed !== expectedDigest) {
          throw new Error("collector marked a private file as matching without the expected digest");
        }
      } else if (observed !== null && observed !== undefined &&
          (typeof observed !== "string" || !/^[a-f0-9]{64}$/.test(observed))) {
        throw new Error("private-host file evidence contains an invalid observed digest");
      } else if (raw.result === "digest_mismatch" &&
          (typeof observed !== "string" || observed === expectedDigest)) {
        throw new Error("private-host digest mismatch evidence does not show a changed digest");
      }
      if (raw.result !== "match") mismatches.push({ path, reason: String(raw.result) });
    }
    for (const path of Object.keys(this.expectedFiles)) {
      if (!seenFiles.has(path)) throw new Error("private-host attestation omitted a required deployed file");
    }

    const seenConfig = new Set<string>();
    for (const raw of parsed.private_config) {
      if (!isRecord(raw) || typeof raw.policy_id !== "string" ||
          !/^[a-z0-9][a-z0-9._-]{1,95}$/.test(raw.policy_id) ||
          seenConfig.has(raw.policy_id) ||
          !Object.prototype.hasOwnProperty.call(this.expectedPrivateConfig, raw.policy_id) ||
          raw.expected_sha256 !== this.expectedPrivateConfig[raw.policy_id] ||
          !["match", "missing", "unreadable", "digest_mismatch"].includes(String(raw.result))) {
        throw new Error("private-host configuration evidence is invalid or outside the pinned policy");
      }
      const id = raw.policy_id;
      seenConfig.add(id);
      const expectedDigest = this.expectedPrivateConfig[id]!;
      const observed = raw.observed_sha256;
      if (raw.result === "match") {
        if (typeof observed !== "string" || !/^[a-f0-9]{64}$/.test(observed) || observed !== expectedDigest) {
          throw new Error("collector marked private configuration as matching without the approved digest");
        }
      } else if (observed !== null && observed !== undefined &&
          (typeof observed !== "string" || !/^[a-f0-9]{64}$/.test(observed))) {
        throw new Error("private-host configuration evidence contains an invalid observed digest");
      } else if (raw.result === "digest_mismatch" &&
          (typeof observed !== "string" || observed === expectedDigest)) {
        throw new Error("private-host configuration mismatch does not show a changed digest");
      }
      if (raw.result !== "match") mismatches.push({ path: "@private-config/" + id, reason: String(raw.result) });
    }
    for (const id of Object.keys(this.expectedPrivateConfig)) {
      if (!seenConfig.has(id)) throw new Error("private-host attestation omitted an approved configuration policy entry");
    }

    const approved = parsed.decision === "approve";
    if (approved !== (mismatches.length === 0)) {
      throw new Error("private-host attestation decision does not match its signed evidence");
    }
    return {
      approved,
      collectorId: "sentryiq-host-attestor",
      issuedAt: parsed.issued_at as number,
      expiresAt: parsed.expires_at as number,
      filesChecked: parsed.files.length,
      privateConfigChecked: parsed.private_config.length,
      mismatches
    };
  }
}

function validateExpectedMap(map: Readonly<Record<string, string>>, policyIds: boolean): void {
  for (const [key, digest] of Object.entries(map)) {
    if ((policyIds ? !/^[a-z0-9][a-z0-9._-]{1,95}$/.test(key) : !isSafeRelativePath(key)) ||
        typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) {
      throw new Error("private-host expected inventory contains an invalid key or digest");
    }
  }
}

function isSafeRelativePath(path: string): boolean {
  return path.length > 0 && path.length <= 240 && !path.startsWith("/") &&
    !path.includes("\\") && !path.includes("%") && !path.includes("//") &&
    !/[\u0000-\u0020\u007f]/.test(path) &&
    !path.split("/").some((part) => part === "" || part === "." || part === "..");
}

function normalizeVersion(value: string): string {
  const version = value.startsWith("v") ? value.slice(1) : value;
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new Error("release version must use stable MAJOR.MINOR.PATCH");
  }
  return version;
}

function decodeCanonicalBase64(value: string, maximum: number): Buffer {
  if (value.length === 0 || value.length > Math.ceil(maximum / 3) * 4) {
    throw new Error("private-host base64 field is empty or exceeds its size limit");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value || decoded.byteLength > maximum) {
    throw new Error("private-host base64 field is not canonical or exceeds its size limit");
  }
  return decoded;
}

async function readBounded(response: Response, maximum: number): Promise<Uint8Array> {
  if (!response.body) throw new Error("private-host collector response body is missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) throw new Error("private-host collector response exceeds its size limit");
      chunks.push(value.slice());
    }
  } catch (error) {
    try { await reader.cancel(error); } catch { /* preserve original error */ }
    throw error;
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

function sameStringSet(actual: string[], expected: string[]): boolean {
  if (actual.length !== expected.length) return false;
  const left = [...actual].sort();
  const right = [...expected].sort();
  return left.every((value, index) => value === right[index]);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
