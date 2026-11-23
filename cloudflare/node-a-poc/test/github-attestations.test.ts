import { describe, expect, it } from "vitest";
import { fetchGithubReleaseAttestationBundles } from "../src/github-attestations";

const digest = "a".repeat(64);

function rawSnappyLiteral(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  const prefix = bytes.length < 128
    ? [bytes.length]
    : [bytes.length & 0x7f, (bytes.length >>> 7) | 0x80];
  const literal = bytes.length < 60
    ? [(bytes.length - 1) << 2]
    : [60 << 2, (bytes.length - 1) & 0xff];
  return new Uint8Array([...prefix, ...literal, ...bytes]);
}

describe("GitHub release attestation retrieval", () => {
  it("restricts API lookup to the repository and fetches bundles only from GitHub blob storage", async () => {
    const bundle = JSON.stringify({ mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3" });
    const calls: Array<[string, RequestInit | undefined]> = [];
    const request: typeof fetch = async (input, init) => {
      const url = String(input);
      calls.push([url, init]);
      if (url.startsWith("https://api.github.com/")) {
        return new Response(JSON.stringify({ attestations: [
          { repository_id: "0", bundle_url: "https://evil.blob.core.windows.net/bundle" },
          { repository_id: "1345956206", bundle_url: "https://sentryiq.blob.core.windows.net/container/bundle?sig=opaque" }
        ] }), { status: 200 });
      }
      return new Response(rawSnappyLiteral(bundle), { status: 200 });
    };
    const result = await fetchGithubReleaseAttestationBundles(digest, request);
    expect(result).toEqual([bundle]);
    expect(calls).toHaveLength(2);
    expect(calls[0]![0]).toContain("/repos/Double-IQ/SentryIQ/attestations/sha256:");
    expect(calls.every(([, init]) => init?.redirect === "error")).toBe(true);
    expect((calls[1]![1]?.headers as Headers).has("Authorization")).toBe(false);
  });

  it("rejects invalid digests, malformed token values, and untrusted blob URLs", async () => {
    await expect(fetchGithubReleaseAttestationBundles("not-a-digest")).rejects.toThrow("SHA-256");
    await expect(fetchGithubReleaseAttestationBundles(digest, fetch, "short")).rejects.toThrow("token");
    const request: typeof fetch = async () => new Response(JSON.stringify({ attestations: [
      { repository_id: "1345956206", bundle_url: "https://attacker.example/bundle" }
    ] }), { status: 200 });
    await expect(fetchGithubReleaseAttestationBundles(digest, request)).rejects.toThrow("outside the approved HTTPS blob host boundary");
  });

  it("rejects API redirects and malformed/oversized bundle responses", async () => {
    const redirect: typeof fetch = async () => new Response(null, { status: 302 });
    await expect(fetchGithubReleaseAttestationBundles(digest, redirect)).rejects.toThrow("non-200");
    const malformed: typeof fetch = async (input) => String(input).startsWith("https://api.github.com/")
      ? new Response(JSON.stringify({ attestations: [
          { repository_id: "1345956206", bundle_url: "https://sentryiq.blob.core.windows.net/bundle" }
        ] }), { status: 200 })
      : new Response(new Uint8Array([2, 0, 1]), { status: 200 });
    await expect(fetchGithubReleaseAttestationBundles(digest, malformed)).rejects.toThrow("No repository-bound");
  });
});
