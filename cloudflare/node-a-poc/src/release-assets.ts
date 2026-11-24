import { createHash } from "node:crypto";

const CANONICAL_ORIGIN = "https://sentryiq.bichet.co.za";
const GITHUB_RELEASE_BASE = "https://github.com/Double-IQ/SentryIQ/releases/download/";
const REDIRECT_HOSTS = new Set([
  "github.com",
  "release-assets.githubusercontent.com",
  "objects.githubusercontent.com"
]);
const MAX_MANIFEST_BYTES = 5_000_000;
const MAX_ZIP_BYTES = 250_000_000;

export interface StagedReleaseAssets {
  readonly version: string;
  readonly manifestBytes: Uint8Array;
  readonly zipSha256: string;
  readonly zipSize: number;
}

/** Bounded read-only release transport with an explicit GitHub redirect allowlist. */
export class NodeAReleaseAssetFetcher {
  constructor(private readonly request: typeof fetch = fetch) {}

  async fetchDeployedVersion(): Promise<string> {
    const response = await this.request(CANONICAL_ORIGIN + "/VERSION", {
      method: "GET",
      redirect: "error",
      headers: {
        "Cache-Control": "no-cache, no-store, no-transform",
        Pragma: "no-cache"
      }
    });
    if (response.status !== 200) {
      if (response.body) await response.body.cancel();
      throw new Error("canonical origin VERSION endpoint returned a non-200 response");
    }
    const bytes = await readBounded(response, 64);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const version = text.endsWith("\n") ? text.slice(0, -1) : text;
    if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
      throw new Error("canonical origin VERSION value is not a stable release version");
    }
    return version;
  }

  async fetchReleaseAssets(versionInput: string): Promise<StagedReleaseAssets> {
    const version = normalizeVersion(versionInput);
    const base = GITHUB_RELEASE_BASE + "v" + version + "/";
    const [manifestBytes, zip] = await Promise.all([
      this.fetchBytes(base + "release-manifest.json", MAX_MANIFEST_BYTES),
      this.fetchSha256(base + "sentryiq-" + version + ".zip", MAX_ZIP_BYTES)
    ]);
    return {
      version,
      manifestBytes,
      zipSha256: zip.sha256,
      zipSize: zip.size
    };
  }

  private async fetchBytes(url: string, maximum: number): Promise<Uint8Array> {
    const response = await this.openAsset(url);
    return readBounded(response, maximum);
  }

  private async fetchSha256(url: string, maximum: number): Promise<{ sha256: string; size: number }> {
    const response = await this.openAsset(url);
    if (!response.body) throw new Error("GitHub release ZIP response has no body");
    const reader = response.body.getReader();
    const hash = createHash("sha256");
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maximum) throw new Error("GitHub release ZIP exceeds the 250 MB limit");
        hash.update(value);
      }
    } catch (error) {
      try { await reader.cancel(error); } catch { /* preserve original error */ }
      throw error;
    } finally {
      reader.releaseLock();
    }
    if (size < 1) throw new Error("GitHub release ZIP is empty");
    return { sha256: hash.digest("hex"), size };
  }

  private async openAsset(url: string): Promise<Response> {
    let current = validateAssetUrl(url, true);
    for (let redirects = 0; redirects <= 3; redirects++) {
      const response = await this.request(current, {
        method: "GET",
        redirect: "manual",
        headers: {
          Accept: "application/octet-stream",
          "Cache-Control": "no-cache, no-store",
          "User-Agent": "SentryIQ-Integrity-Node-A/1.0"
        }
      });
      if (response.status === 200) return response;
      if (![301, 302, 303, 307, 308].includes(response.status)) {
        if (response.body) await response.body.cancel();
        throw new Error("GitHub release asset returned an unexpected HTTP status");
      }
      const location = response.headers.get("location");
      if (response.body) await response.body.cancel();
      if (!location || redirects === 3) {
        throw new Error("GitHub release asset exceeded the bounded redirect policy");
      }
      current = validateAssetUrl(new URL(location, current).toString(), false);
    }
    throw new Error("GitHub release asset redirect policy was exhausted");
  }
}

function validateAssetUrl(value: string, initial: boolean): string {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("GitHub release asset URL is invalid"); }
  if (url.protocol !== "https:" || !REDIRECT_HOSTS.has(url.hostname.toLowerCase()) ||
      (url.port !== "" && url.port !== "443") || url.username !== "" || url.password !== "" ||
      url.hash !== "") {
    throw new Error("GitHub release asset URL is outside the HTTPS redirect allowlist");
  }
  if (initial) {
    const allowedPath = /^\/Double-IQ\/SentryIQ\/releases\/download\/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\/(?:release-manifest\.json|sentryiq-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.zip)$/;
    if (url.hostname !== "github.com" || !allowedPath.test(url.pathname) || url.search !== "") {
      throw new Error("initial release asset URL is not the canonical SentryIQ GitHub release path");
    }
  }
  return url.toString();
}

function normalizeVersion(value: string): string {
  const version = value.startsWith("v") ? value.slice(1) : value;
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new Error("release asset version must use canonical MAJOR.MINOR.PATCH");
  }
  return version;
}

async function readBounded(response: Response, maximum: number): Promise<Uint8Array> {
  if (!response.body) throw new Error("release asset response body is missing");
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && /^\d+$/.test(contentLength) && Number(contentLength) > maximum) {
    await response.body.cancel();
    throw new Error("release asset response exceeds its configured size limit");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) throw new Error("release asset response exceeds its configured size limit");
      chunks.push(value.slice());
    }
  } catch (error) {
    try { await reader.cancel(error); } catch { /* preserve original error */ }
    throw error;
  } finally {
    reader.releaseLock();
  }
  if (length < 1) throw new Error("release asset response is empty");
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}
