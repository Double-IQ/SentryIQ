import { assertNoDuplicateJsonKeys } from "./release-manifest";

const API_BASE = "https://api.github.com";
const REPOSITORY = "Double-IQ/SentryIQ";
const MAX_RESPONSE_BYTES = 64_000;
const MAX_TAG_DEPTH = 4;

/** Resolve the exact vMAJOR.MINOR.PATCH Git ref to its final commit object. */
export async function resolveGithubReleaseTagCommit(
  version: string,
  request: typeof fetch = fetch,
  apiToken?: string
): Promise<string> {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new Error("release tag version is not canonical");
  }
  if (apiToken !== undefined && !/^[A-Za-z0-9_\-]{20,255}$/.test(apiToken)) {
    throw new Error("GitHub API token format is invalid");
  }

  const tagName = "v" + version;
  const headers = new Headers({
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "SentryIQ-Integrity-Node-A/1.0"
  });
  if (apiToken !== undefined) headers.set("Authorization", "Bearer " + apiToken);

  const ref = await getJson(
    API_BASE + "/repos/" + REPOSITORY + "/git/ref/tags/" + tagName,
    headers,
    request
  );
  if (!isRecord(ref) || ref.ref !== "refs/tags/" + tagName || !isRecord(ref.object)) {
    throw new Error("GitHub release tag reference does not match the requested canonical tag");
  }

  let objectType = ref.object.type;
  let objectSha = ref.object.sha;
  if (typeof objectType !== "string" || typeof objectSha !== "string" ||
      !/^[a-f0-9]{40}$/.test(objectSha)) {
    throw new Error("GitHub release tag reference contains an invalid Git object");
  }
  if (objectType === "commit") return objectSha;
  if (objectType !== "tag") throw new Error("GitHub release tag must resolve to a commit or annotated tag");

  const visited = new Set<string>();
  for (let depth = 0; depth < MAX_TAG_DEPTH; depth++) {
    if (visited.has(objectSha)) throw new Error("GitHub annotated release tag contains a cycle");
    visited.add(objectSha);
    const tag = await getJson(
      API_BASE + "/repos/" + REPOSITORY + "/git/tags/" + objectSha,
      headers,
      request
    );
    if (!isRecord(tag) || tag.tag !== tagName ||
        tag.tag.length > 256 || !isRecord(tag.object)) {
      throw new Error("GitHub annotated release tag object is malformed");
    }
    objectType = tag.object.type;
    objectSha = tag.object.sha;
    if (typeof objectType !== "string" || typeof objectSha !== "string" ||
        !/^[a-f0-9]{40}$/.test(objectSha)) {
      throw new Error("GitHub annotated release tag contains an invalid target object");
    }
    if (objectType === "commit") return objectSha;
    if (objectType !== "tag") throw new Error("GitHub annotated release tag target is not a commit or tag");
  }
  throw new Error("GitHub annotated release tag exceeds the maximum tag depth");
}

async function getJson(
  url: string,
  headers: Headers,
  request: typeof fetch
): Promise<unknown> {
  const response = await request(url, { method: "GET", redirect: "error", headers });
  if (response.status !== 200) throw new Error("GitHub release tag API returned a non-200 response");
  if (!response.body) throw new Error("GitHub release tag API returned an empty body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_RESPONSE_BYTES) throw new Error("GitHub release tag API response exceeds its size limit");
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
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assertNoDuplicateJsonKeys(text);
  return JSON.parse(text);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
