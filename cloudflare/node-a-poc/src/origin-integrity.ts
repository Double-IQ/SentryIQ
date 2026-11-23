import { createHash } from "node:crypto";
import type { VerifiedReleaseManifest } from "./release-manifest";

export const NODE_A_CANONICAL_ORIGIN = "https://sentryiq.bichet.co.za";
const MAX_PUBLIC_ASSET_BYTES = 10_000_000;

export interface OriginIntegrityResult {
  readonly approved: boolean;
  readonly checkedPaths: readonly string[];
  readonly mismatches: readonly { path: string; reason: string }[];
  readonly headerMismatches: readonly string[];
}

/** Read-only canonical-origin verifier. It never follows redirects or accepts a caller-selected host. */
export async function verifyCanonicalOrigin(
  origin: string,
  manifest: VerifiedReleaseManifest,
  request: typeof fetch = fetch
): Promise<OriginIntegrityResult> {
  if (normalizeCanonicalOrigin(origin) !== NODE_A_CANONICAL_ORIGIN) {
    throw new Error("Node A only verifies the canonical SentryIQ HTTPS origin");
  }

  const mismatches: Array<{ path: string; reason: string }> = [];
  const checkedPaths: string[] = [];
  for (const entry of manifest.publicHttpFiles) {
    checkedPaths.push(entry.path);
    try {
      const response = await request(assetUrl(entry.path), {
        method: "GET",
        redirect: "error",
        headers: {
          "Cache-Control": "no-cache, no-store, no-transform",
          "Pragma": "no-cache"
        }
      });
      if (response.status !== 200 || !response.body) {
        mismatches.push({ path: entry.path, reason: "fetch_failed" });
        continue;
      }
      const bytes = await readBounded(response, Math.min(MAX_PUBLIC_ASSET_BYTES, entry.size + 1));
      if (bytes.byteLength !== entry.size || sha256(bytes) !== entry.sha256) {
        mismatches.push({ path: entry.path, reason: "content_mismatch" });
      }
    } catch {
      mismatches.push({ path: entry.path, reason: "fetch_failed" });
    }
  }

  let headerMismatches: string[];
  try {
    const response = await request(assetUrl("VERSION"), {
      method: "GET",
      redirect: "error",
      headers: { "Cache-Control": "no-cache, no-store, no-transform", "Pragma": "no-cache" }
    });
    headerMismatches = response.status === 200 ? checkSecurityHeaders(response.headers) : [
      "origin-security-header-probe"
    ];
    if (response.body) await response.body.cancel();
  } catch {
    headerMismatches = ["origin-security-header-probe"];
  }
  checkedPaths.push("@origin-headers");
  for (const header of headerMismatches) {
    mismatches.push({ path: "@origin-headers", reason: "security_header_mismatch:" + header });
  }

  return {
    approved: mismatches.length === 0,
    checkedPaths,
    mismatches,
    headerMismatches
  };
}

function normalizeCanonicalOrigin(value: string): string {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("Node A origin URL is invalid"); }
  if (url.protocol !== "https:" || url.hostname.toLowerCase() !== "sentryiq.bichet.co.za" ||
      (url.port !== "" && url.port !== "443") || url.username !== "" || url.password !== "" ||
      url.pathname !== "/" && url.pathname !== "" || url.search !== "" || url.hash !== "") {
    throw new Error("Node A origin must be the canonical HTTPS origin without path, credentials, query, or fragment");
  }
  return NODE_A_CANONICAL_ORIGIN;
}

function assetUrl(path: string): string {
  if (path.length === 0 || path.startsWith("/") || path.includes("\\") ||
      path.split("/").some((part) => part === "" || part === "." || part === "..") ||
      /[\u0000-\u001f\u007f%?#]/.test(path)) {
    throw new Error("signed public asset path is unsafe");
  }
  return NODE_A_CANONICAL_ORIGIN + "/" + path.split("/").map(encodeURIComponent).join("/");
}

function checkSecurityHeaders(headers: Headers): string[] {
  const mismatches: string[] = [];
  const hsts = headers.get("strict-transport-security") ?? "";
  const match = /(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(hsts);
  if (!match || Number(match[1]) < 31_536_000) mismatches.push("strict-transport-security");
  if ((headers.get("x-content-type-options") ?? "").toLowerCase() !== "nosniff") mismatches.push("x-content-type-options");
  if ((headers.get("x-frame-options") ?? "").toLowerCase() !== "deny") mismatches.push("x-frame-options");
  if ((headers.get("referrer-policy") ?? "").toLowerCase() !== "strict-origin-when-cross-origin") mismatches.push("referrer-policy");

  const permissions = (headers.get("permissions-policy") ?? "").toLowerCase();
  for (const feature of ["camera", "microphone", "geolocation"]) {
    if (!new RegExp("(?:^|,)\\s*" + feature + "\\s*=\\s*\\(\\)").test(permissions)) {
      mismatches.push("permissions-policy:" + feature);
    }
  }
  const csp = (headers.get("content-security-policy") ?? "").toLowerCase();
  for (const directive of ["frame-ancestors 'none'", "base-uri 'self'", "object-src 'none'"]) {
    if (!csp.includes(directive)) mismatches.push("content-security-policy:" + directive);
  }
  return mismatches;
}

async function readBounded(response: Response, maximumBytes: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0 || maximumBytes > MAX_PUBLIC_ASSET_BYTES) {
    throw new Error("signed public asset length is outside the allowed bound");
  }
  if (!response.body) throw new Error("public asset response has no body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) throw new Error("public asset response exceeded signed length");
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

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
