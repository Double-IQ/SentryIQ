import { describe, expect, it } from "vitest";
import { NODE_A_CANONICAL_ORIGIN, verifyCanonicalOrigin } from "../src/origin-integrity";
import { parseAndValidateReleaseManifest } from "../src/release-manifest";

const commit = "a".repeat(40);
const digest = "b".repeat(64);
const manifest = parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify({
  format: 2, repository: "Double-IQ/SentryIQ", repository_id: "1345956206",
  version: "0.1.3", commit, workflow_path: ".github/workflows/release.yml",
  public_files: ["VERSION", "assets/app.js"], runtime_files: ["config.php"],
  files: [
    { path: "VERSION", size: 6, sha256: "b9b9e4c6e8a4e2c7c9d6b8a0f2f0a9e4c1d8b7a6f5e4d3c2b1a09876543210ff" },
    { path: "assets/app.js", size: 3, sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { path: "runtime/config.php", size: 1, sha256: digest }
  ]
})), "0.1.3", commit);

const headers = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
};

describe("Node A canonical-origin integrity", () => {
  it("hashes signed static assets and checks origin security headers without redirects", async () => {
    const calls: Array<[string, RequestInit | undefined]> = [];
    const request: typeof fetch = async (input, init) => {
      const url = String(input);
      calls.push([url, init]);
      if (url.endsWith("/assets/app.js")) return new Response("abc", { status: 200 });
      if (url.endsWith("/VERSION")) return new Response("0.1.3\\n", { status: 200, headers });
      return new Response("1.2.3", { status: 200, headers });
    };
    const result = await verifyCanonicalOrigin(NODE_A_CANONICAL_ORIGIN, manifest, request);
    expect(result.approved).toBe(true);
    expect(result.checkedPaths).toEqual(["VERSION", "assets/app.js", "@origin-headers"]);
    expect(calls.every(([, init]) => init?.redirect === "error")).toBe(true);
  });

  it("rejects non-canonical hosts and records redirects/network failures as mismatches", async () => {
    await expect(verifyCanonicalOrigin("https://attacker.example", manifest, fetch)).rejects.toThrow("canonical");
    const request: typeof fetch = async () => new Response(null, { status: 302, headers: { location: "https://attacker.example/" } });
    const result = await verifyCanonicalOrigin(NODE_A_CANONICAL_ORIGIN, manifest, request);
    expect(result.approved).toBe(false);
    expect(result.mismatches.some((item) => item.reason === "fetch_failed")).toBe(true);
  });

  it("rejects asset body length/digest mismatch and missing required headers", async () => {
    const request: typeof fetch = async (input) => String(input).endsWith("/assets/app.js")
      ? new Response("abd", { status: 200 })
      : new Response("1.2.3", { status: 200 });
    const result = await verifyCanonicalOrigin(NODE_A_CANONICAL_ORIGIN, manifest, request);
    expect(result.approved).toBe(false);
    expect(result.mismatches.some((item) => item.reason === "content_mismatch")).toBe(true);
    expect(result.headerMismatches).toContain("strict-transport-security");
  });
});
