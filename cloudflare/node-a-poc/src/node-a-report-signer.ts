import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign, timingSafeEqual } from "node:crypto";

const REPOSITORY = "Double-IQ/SentryIQ";
const REPOSITORY_ID = "1345956206";
const WORKFLOW_PATH = ".github/workflows/release.yml";
const REPORT_TTL_SECONDS = 300;
const MAX_REPORT_BYTES = 16_384;
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface NodeAEventEvidence {
  readonly target_origin: string;
  readonly manifest_sha256: string;
  readonly checked_paths: readonly string[];
  readonly mismatches: readonly { readonly path: string; readonly reason: string }[];
}

/** A-only detached Ed25519 report signer compatible with Node 4 schema version 2. */
export class NodeAReportSigner {
  private readonly privateKey: ReturnType<typeof createPrivateKey>;
  private readonly publicKeyRaw: Buffer;

  constructor(
    private readonly nodeId: "integrity-a",
    base64SecretKey: string,
    private readonly clock: () => number = () => Math.floor(Date.now() / 1000)
  ) {
    if (nodeId !== "integrity-a" || typeof base64SecretKey !== "string" ||
        !/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/.test(base64SecretKey)) {
      throw new Error("Node A requires its own canonical base64 Ed25519 secret key");
    }
    const secretKey = Buffer.from(base64SecretKey, "base64");
    if (secretKey.byteLength !== 64 || secretKey.toString("base64") !== base64SecretKey) {
      throw new Error("Node A Ed25519 secret key must decode to exactly 64 canonical bytes");
    }
    this.privateKey = createPrivateKey({
      key: Buffer.concat([PKCS8_ED25519_PREFIX, secretKey.subarray(0, 32)]),
      format: "der",
      type: "pkcs8"
    });
    const publicDer = createPublicKey(this.privateKey).export({ format: "der", type: "spki" });
    const publicBytes = Buffer.from(publicDer).subarray(-32);
    if (publicBytes.byteLength !== 32 ||
        !timingSafeEqual(publicBytes, secretKey.subarray(32, 64))) {
      throw new Error("Node A Ed25519 secret and public key components do not match");
    }
    this.publicKeyRaw = Buffer.from(publicBytes);
  }

  publicKeyBase64(): string {
    return this.publicKeyRaw.toString("base64");
  }

  createReport(input: {
    readonly releaseVersion: string;
    readonly commit: string;
    readonly artifactSha256: string;
    readonly nonce: string;
    readonly decision: "approve" | "reject";
    readonly evidence: NodeAEventEvidence;
  }): string {
    const version = normalizeVersion(input.releaseVersion);
    const commit = input.commit.toLowerCase();
    const artifactSha256 = input.artifactSha256.toLowerCase();
    const nonce = input.nonce.toLowerCase();
    if (!/^[a-f0-9]{40}$/.test(commit) ||
        !/^[a-f0-9]{64}$/.test(artifactSha256) ||
        !/^[a-f0-9]{64}$/.test(nonce) ||
        !["approve", "reject"].includes(input.decision)) {
      throw new Error("Node A report release identity, nonce or decision is invalid");
    }
    const evidence = validateEvidence(input.evidence);
    if ((input.decision === "approve") !== (evidence.mismatches.length === 0)) {
      throw new Error("Node A report decision conflicts with its mismatch evidence");
    }

    const issuedAt = this.clock();
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 1) {
      throw new Error("Node A report clock returned an invalid timestamp");
    }
    const payload = {
      schema_version: 2,
      node_id: this.nodeId,
      decision: input.decision,
      issued_at: issuedAt,
      expires_at: issuedAt + REPORT_TTL_SECONDS,
      nonce,
      repository: REPOSITORY,
      repository_id: REPOSITORY_ID,
      release_version: version,
      tag: "v" + version,
      commit,
      artifact_sha256: artifactSha256,
      workflow_path: WORKFLOW_PATH,
      target_origin: evidence.target_origin,
      manifest_sha256: evidence.manifest_sha256,
      checked_paths: evidence.checked_paths,
      mismatches: evidence.mismatches
    };
    const payloadBytes = Buffer.from(JSON.stringify(payload), "utf8");
    const signature = sign(null, payloadBytes, this.privateKey);
    const envelope = JSON.stringify({
      payload: payloadBytes.toString("base64"),
      signature: signature.toString("base64")
    });
    if (Buffer.byteLength(envelope, "utf8") > MAX_REPORT_BYTES) {
      throw new Error("Node A signed report exceeds the 16 KB Node 4 limit");
    }
    return envelope;
  }
}

function validateEvidence(evidence: NodeAEventEvidence): NodeAEventEvidence {
  if (!evidence || evidence.target_origin !== "https://sentryiq.bichet.co.za" ||
      !/^[a-f0-9]{64}$/.test(evidence.manifest_sha256) ||
      !Array.isArray(evidence.checked_paths) || evidence.checked_paths.length > 100 ||
      !Array.isArray(evidence.mismatches) || evidence.mismatches.length > 100) {
    throw new Error("Node A event evidence is incomplete or outside its bounds");
  }
  const checked = new Set<string>();
  let publicCount = 0;
  for (const path of evidence.checked_paths) {
    if (typeof path !== "string" || !isSafeEvidencePath(path) || checked.has(path) ||
        (path.startsWith("@") && !["@origin-headers", "@private-host-attestation"].includes(path))) {
      throw new Error("Node A event evidence contains an unsafe or duplicate checked path");
    }
    checked.add(path);
    if (!path.startsWith("@")) publicCount++;
  }
  if (publicCount < 1 || !checked.has("@origin-headers") ||
      !checked.has("@private-host-attestation")) {
    throw new Error("Node A evidence must include a public asset, origin headers and private-host attestation");
  }

  const mismatchPaths = new Set<string>();
  const mismatches = evidence.mismatches.map((item) => {
    if (!item || typeof item.path !== "string" || !isSafeEvidencePath(item.path) ||
        !["content_mismatch", "fetch_failed", "security_header_mismatch", "private_host_attestation_failed"].includes(item.reason) ||
        !checked.has(item.path) || mismatchPaths.has(item.path)) {
      throw new Error("Node A event evidence contains an invalid or duplicate mismatch");
    }
    mismatchPaths.add(item.path);
    if ((item.reason === "security_header_mismatch" && item.path !== "@origin-headers") ||
        (item.reason === "private_host_attestation_failed" && item.path !== "@private-host-attestation") ||
        (["content_mismatch", "fetch_failed"].includes(item.reason) && item.path.startsWith("@"))) {
      throw new Error("Node A mismatch reason does not match its evidence path");
    }
    return { path: item.path, reason: item.reason };
  });
  return {
    target_origin: evidence.target_origin,
    manifest_sha256: evidence.manifest_sha256,
    checked_paths: [...evidence.checked_paths],
    mismatches
  };
}

function isSafeEvidencePath(path: string): boolean {
  return path.length > 0 && path.length <= 512 && !path.startsWith("/") &&
    !path.includes("\\") && !path.includes("//") && !/[\u0000-\u001f\u007f%?#]/.test(path) &&
    !path.split("/").some((part) => part === "" || part === "." || part === "..");
}

function normalizeVersion(value: string): string {
  const version = value.startsWith("v") ? value.slice(1) : value;
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new Error("release version must use stable MAJOR.MINOR.PATCH");
  }
  return version;
}
