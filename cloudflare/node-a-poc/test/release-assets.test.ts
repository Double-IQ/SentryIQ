import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { NodeAReleaseAssetFetcher } from "../src/release-assets";

describe("Node A bounded release asset fetcher", () => {
  it("reads the exact deployed version without following redirects", async () => {
    let init: RequestInit | undefined;
    const fetcher = new NodeAReleaseAssetFetcher(async (_input, requestInit) => {
      init = requestInit;
      return new Response("1.2.3\n", { status: 200 });
    });
    await expect(fetcher.fetchDeployedVersion()).resolves.toBe("1.2.3");
    expect(init?.redirect).toBe("error");
  });

  it("downloads the manifest and streams the ZIP digest through approved GitHub redirect hosts", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const zip = new Uint8Array([1, 2, 3, 4]);
    const fetcher = new NodeAReleaseAssetFetcher(async (input, init) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.endsWith("/release-manifest.json")) {
        return new Response('{"format":2}', { status: 200 });
      }
      if (url.includes("github.com/releases/download/")) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://release-assets.githubusercontent.com/signed.zip?sig=opaque" }
        });
      }
      return new Response(zip, { status: 200 });
    });
    const result = await fetcher.fetchReleaseAssets("v1.2.3");
    expect(result.version).toBe("1.2.3");
    expect(new TextDecoder().decode(result.manifestBytes)).toBe('{"format":2}');
    expect(result.zipSize).toBe(4);
    expect(result.zipSha256).toBe(createHash("sha256").update(zip).digest("hex"));
    expect(calls.every(call => call.init?.redirect === "manual")).toBe(true);
    expect(calls.every(call => !new Headers(call.init?.headers).has("authorization"))).toBe(true);
  });

  it("rejects unapproved redirect hosts, wrong initial paths, oversized bodies and invalid versions", async () => {
    const badRedirect = new NodeAReleaseAssetFetcher(async () => new Response(null, {
      status: 302, headers: { location: "https://attacker.example/payload" }
    }));
    await expect(badRedirect.fetchReleaseAssets("1.2.3")).rejects.toThrow("allowlist");

    const oversized = new NodeAReleaseAssetFetcher(async (input) => String(input).endsWith("/release-manifest.json")
      ? new Response(new Uint8Array(100), { status: 200, headers: { "content-length": "5000001" } })
      : new Response(new Uint8Array([1]), { status: 200 }));
    await expect(oversized.fetchReleaseAssets("1.2.3")).rejects.toThrow("size limit");
    await expect(oversized.fetchReleaseAssets("../1.2.3")).rejects.toThrow("canonical");

    const invalidVersion = new NodeAReleaseAssetFetcher(async () => new Response("v1.2.3\n", { status: 200 }));
    await expect(invalidVersion.fetchDeployedVersion()).rejects.toThrow("stable release version");
  });
});
