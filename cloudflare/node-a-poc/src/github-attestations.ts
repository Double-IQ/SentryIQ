import { assertNoDuplicateJsonKeys } from "./release-manifest";
import { decodeSnappyBlock } from "./snappy-block";

const API_BASE = "https://api.github.com";
const REPOSITORY = "Double-IQ/SentryIQ";
const REPOSITORY_ID = "1345956206";
const MAX_API_BYTES = 2_000_000;
const MAX_BUNDLE_BYTES = 8_000_000;

export async function fetchGithubReleaseAttestationBundles(
  sha256: string,
  request: typeof fetch = fetch,
  apiToken?: string
): Promise<string[]> {
  if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("attestation lookup requires a lowercase SHA-256 digest");
  if (apiToken !== undefined && !/^[A-Za-z0-9_\-]{20,255}$/.test(apiToken)) {
    throw new Error("GitHub API token format is invalid");
  }

  const headers = new Headers({
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "SentryIQ-Integrity-Node-A/1.0"
  });
  if (apiToken !== undefined) headers.set("Authorization", "Bearer " + apiToken);
  const apiResponse = await request(
    API_BASE + "/repos/" + REPOSITORY + "/attestations/sha256:" + sha256 + "?per_page=100",
    { method: "GET", redirect: "error", headers }
  );
  if (apiResponse.status !== 200) throw new Error("GitHub attestation API returned a non-200 response");
  const apiBytes = await readBounded(apiResponse, MAX_API_BYTES);
  const apiText = new TextDecoder("utf-8", { fatal: true }).decode(apiBytes);
  assertNoDuplicateJsonKeys(apiText);
  const document: unknown = JSON.parse(apiText);
  if (!isRecord(document) || !Array.isArray(document.attestations) ||
      document.attestations.length < 1 || document.attestations.length > 100) {
    throw new Error("GitHub returned an empty or malformed attestation list");
  }

  const bundleUrls: string[] = [];
  for (const entry of document.attestations) {
    if (!isRecord(entry) || entry.repository_id !== Number(REPOSITORY_ID)) continue;
    if (typeof entry.bundle_url !== "string") continue;
    const url = validateBundleUrl(entry.bundle_url);
    bundleUrls.push(url);
  }
  if (bundleUrls.length < 1) throw new Error("GitHub returned no attestation bundle for the trusted repository");

  const bundles: string[] = [];
  for (const url of bundleUrls) {
    const response = await request(url, {
      method: "GET",
      redirect: "error",
      headers: { "Accept": "application/json", "User-Agent": "SentryIQ-Integrity-Node-A/1.0" }
    });
    if (response.status !== 200) continue;
    const compressed = await readBounded(response, MAX_BUNDLE_BYTES);
    try {
      const decoded = decodeSnappyBlock(compressed, MAX_BUNDLE_BYTES);
      const bundleJson = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
      assertNoDuplicateJsonKeys(bundleJson);
      const parsed: unknown = JSON.parse(bundleJson);
      if (!isRecord(parsed)) continue;
      bundles.push(bundleJson);
    } catch {
      // A malformed or invalid individual bundle is not trusted. Other
      // repository-bound entries may still contain a valid bundle.
    }
  }
  if (bundles.length < 1) throw new Error("No repository-bound GitHub attestation bundle could be decoded");
  return bundles;
}

function validateBundleUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("GitHub attestation bundle URL is invalid"); }
  const host = url.hostname.toLowerCase();
  const repositoryBundlePath = new RegExp("^/attestations/" + REPOSITORY_ID + "/[0-9]{4}/[0-9]{2}/[0-9]{2}/[A-Za-z0-9._-]+\\.json\\.sn$");
  if (url.protocol !== "https:" || !host.endsWith(".blob.core.windows.net") ||
      url.username !== "" || url.password !== "" ||
      (url.port !== "" && url.port !== "443") || url.hash !== "" ||
      !repositoryBundlePath.test(url.pathname) ||
      !url.searchParams.has("sig") || !url.searchParams.has("se") ||
      url.searchParams.get("sp") !== "r") {
    throw new Error("GitHub attestation bundle URL is outside the approved repository-scoped HTTPS blob boundary");
  }
  return url.toString();
}

async function readBounded(response: Response, maximumBytes: number): Promise<Uint8Array> {
  if (!response.body) throw new Error("remote response has no body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) throw new Error("remote response exceeded its configured byte limit");
      chunks.push(value.slice());
    }
  } catch (error) {
    try { await reader.cancel(error); } catch { /* preserve original error */ }
    throw error;
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
