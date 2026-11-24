import { assertNoDuplicateJsonKeys } from "./release-manifest";

const NODE4_ENDPOINT = "https://sentryiq.bichet.co.za/integrity_event.php";
const MAX_RESPONSE_BYTES = 16_384;
const MAX_REPORT_BYTES = 16_384;

export interface Node4Challenge {
  readonly nonce: string;
  readonly expiresAt: number;
  readonly nodeId: "integrity-a";
}

/** A-only authenticated client for the existing BTM-SA Node 4 event endpoint. */
export class Node4EventClient {
  constructor(
    private readonly bearerToken: string,
    private readonly request: typeof fetch = fetch,
    private readonly clock: () => number = () => Math.floor(Date.now() / 1000)
  ) {
    if (!/^[A-Za-z0-9_-]{40,128}$/.test(bearerToken)) {
      throw new Error("Node 4 A-only bearer credential is invalid");
    }
  }

  async requestChallenge(input: {
    readonly targetOrigin: string;
    readonly releaseVersion: string;
    readonly commit: string;
    readonly artifactSha256: string;
    readonly manifestSha256: string;
  }): Promise<Node4Challenge> {
    const version = normalizeVersion(input.releaseVersion);
    const commit = input.commit.toLowerCase();
    const artifactSha256 = input.artifactSha256.toLowerCase();
    const manifestSha256 = input.manifestSha256.toLowerCase();
    if (input.targetOrigin !== "https://sentryiq.bichet.co.za" ||
        !/^[a-f0-9]{40}$/.test(commit) ||
        !/^[a-f0-9]{64}$/.test(artifactSha256) ||
        !/^[a-f0-9]{64}$/.test(manifestSha256)) {
      throw new Error("Node 4 challenge release identity or target origin is invalid");
    }

    const response = await this.post({
      action: "challenge",
      node_id: "integrity-a",
      target_origin: input.targetOrigin,
      release_version: version,
      commit,
      artifact_sha256: artifactSha256,
      manifest_sha256: manifestSha256
    }, 201);
    const now = this.clock();
    if (response.status !== "ok" || response.node_id !== "integrity-a" ||
        typeof response.nonce !== "string" || !/^[a-f0-9]{64}$/.test(response.nonce) ||
        !Number.isSafeInteger(response.expires_at) ||
        (response.expires_at as number) <= now ||
        (response.expires_at as number) > now + 630) {
      throw new Error("Node 4 returned an invalid or expired A-only challenge");
    }
    return { nonce: response.nonce, expiresAt: response.expires_at as number, nodeId: "integrity-a" };
  }

  async submitReport(signedEnvelope: string): Promise<Record<string, unknown>> {
    if (typeof signedEnvelope !== "string" || signedEnvelope.length < 2 ||
        new TextEncoder().encode(signedEnvelope).byteLength > MAX_REPORT_BYTES) {
      throw new Error("signed Node 4 report is empty or exceeds the 16 KB limit");
    }
    const response = await this.post({ action: "report", envelope: signedEnvelope }, 202);
    if (response.status !== "accepted") throw new Error("Node 4 did not acknowledge the signed report");
    return response;
  }

  private async post(payload: Record<string, unknown>, expectedStatus: number): Promise<Record<string, unknown>> {
    const response = await this.request(NODE4_ENDPOINT, {
      method: "POST",
      redirect: "error",
      headers: {
        Authorization: "Bearer " + this.bearerToken,
        "Content-Type": "application/json",
        Accept: "application/json",
        "Cache-Control": "no-store"
      },
      body: JSON.stringify(payload)
    });
    if (response.status !== expectedStatus) {
      if (response.body) await response.body.cancel();
      throw new Error("Node 4 returned an unexpected HTTP status");
    }
    if (!response.body) throw new Error("Node 4 response body is missing");
    const bytes = await readBounded(response, MAX_RESPONSE_BYTES);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    assertNoDuplicateJsonKeys(text);
    const parsed: unknown = JSON.parse(text);
    if (!isRecord(parsed) || Array.isArray(parsed)) {
      throw new Error("Node 4 response must be a JSON object");
    }
    return parsed;
  }
}

function normalizeVersion(value: string): string {
  const version = value.startsWith("v") ? value.slice(1) : value;
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new Error("release version must use canonical MAJOR.MINOR.PATCH");
  }
  return version;
}

async function readBounded(response: Response, maximum: number): Promise<Uint8Array> {
  const reader = response.body!.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) throw new Error("Node 4 response exceeds the 16 KB limit");
      chunks.push(value.slice());
    }
  } catch (error) {
    try { await reader.cancel(error); } catch { /* preserve original error */ }
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
