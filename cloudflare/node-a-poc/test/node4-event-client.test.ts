import { describe, expect, it } from "vitest";
import { Node4EventClient } from "../src/node4-event-client";

const token = "A".repeat(48);
const commit = "a".repeat(40);
const digest = "b".repeat(64);

describe("Node A authenticated Node 4 event client", () => {
  it("requests an A-only challenge bound to exact target and both release digests", async () => {
    let captured: { url: string; init?: RequestInit } | undefined;
    const request: typeof fetch = async (input, init) => {
      captured = { url: String(input), init };
      return Response.json({
        status: "ok", node_id: "integrity-a", nonce: "c".repeat(64), expires_at: 1_800_000_300
      }, { status: 201 });
    };
    const client = new Node4EventClient(token, request, () => 1_800_000_000);
    const result = await client.requestChallenge({
      targetOrigin: "https://sentryiq.bichet.co.za",
      releaseVersion: "v1.2.3",
      commit,
      artifactSha256: digest,
      manifestSha256: "d".repeat(64)
    });
    expect(result).toEqual({ nonce: "c".repeat(64), expiresAt: 1_800_000_300, nodeId: "integrity-a" });
    expect(captured?.url).toBe("https://sentryiq.bichet.co.za/integrity_event.php");
    expect(captured?.init?.redirect).toBe("error");
    expect(new Headers(captured?.init?.headers).get("authorization")).toBe("Bearer " + token);
    expect(JSON.parse(String(captured?.init?.body))).toMatchObject({
      action: "challenge", node_id: "integrity-a", release_version: "1.2.3",
      artifact_sha256: digest, manifest_sha256: "d".repeat(64)
    });
  });

  it("submits the exact signed envelope and requires Node 4 acknowledgement", async () => {
    let payload: Record<string, unknown> | undefined;
    const request: typeof fetch = async (_input, init) => {
      payload = JSON.parse(String(init?.body));
      return Response.json({ status: "accepted", report_id: "report-1" }, { status: 202 });
    };
    const client = new Node4EventClient(token, request);
    await expect(client.submitReport('{"payload":"abc","signature":"def"}'))
      .resolves.toMatchObject({ status: "accepted", report_id: "report-1" });
    expect(payload).toEqual({ action: "report", envelope: '{"payload":"abc","signature":"def"}' });
  });

  it("rejects wrong node, expired challenge, invalid identity, redirects and oversized reports", async () => {
    const wrongNode: typeof fetch = async () => Response.json({
      status: "ok", node_id: "integrity-b", nonce: "c".repeat(64), expires_at: 1_800_000_100
    }, { status: 201 });
    const client = new Node4EventClient(token, wrongNode, () => 1_800_000_000);
    await expect(client.requestChallenge({
      targetOrigin: "https://sentryiq.bichet.co.za", releaseVersion: "1.2.3",
      commit, artifactSha256: digest, manifestSha256: "d".repeat(64)
    })).rejects.toThrow("invalid or expired");
    await expect(client.requestChallenge({
      targetOrigin: "https://attacker.example", releaseVersion: "1.2.3",
      commit, artifactSha256: digest, manifestSha256: "d".repeat(64)
    })).rejects.toThrow("target origin");
    const redirect: typeof fetch = async () => new Response(null, { status: 302 });
    await expect(new Node4EventClient(token, redirect).submitReport("{}")).rejects.toThrow("HTTP status");
    await expect(new Node4EventClient(token, fetch).submitReport("x".repeat(16_385))).rejects.toThrow("16 KB");
  });
});
