import { describe, expect, it } from "vitest";
import { NodeAOwnerAlertWebhook } from "../src/node-a-owner-alert";

const token = "A".repeat(48);

describe("Node A independent direct owner-alert webhook", () => {
  it("sends a bounded sanitized event to an exact external HTTPS host without redirects", async () => {
    let captured: { url: string; init?: RequestInit } | undefined;
    const webhook = new NodeAOwnerAlertWebhook(
      "https://alerts.example.net/hooks/sentryiq", "alerts.example.net", token,
      async (input, init) => {
        captured = { url: String(input), init };
        return new Response(null, { status: 204 });
      },
      () => 1_800_000_000
    );
    await webhook.send("integrity_mismatch", {
      node_id: "integrity-a", release_version: "1.2.3", mismatch_count: 2
    });
    expect(captured?.url).toBe("https://alerts.example.net/hooks/sentryiq");
    expect(captured?.init?.redirect).toBe("error");
    expect(new Headers(captured?.init?.headers).get("authorization")).toBe("Bearer " + token);
    expect(JSON.parse(String(captured?.init?.body))).toMatchObject({
      schema_version: 1, node_id: "integrity-a", event: "integrity_mismatch",
      issued_at: 1_800_000_000
    });
  });

  it("rejects same-host, local, non-HTTPS and non-allowlisted destinations", () => {
    expect(() => new NodeAOwnerAlertWebhook(
      "https://sentryiq.bichet.co.za/alert", "sentryiq.bichet.co.za", token
    )).toThrow("independent HTTPS host");
    expect(() => new NodeAOwnerAlertWebhook("http://alerts.example.net/hook", "alerts.example.net", token))
      .toThrow("independent HTTPS host");
    expect(() => new NodeAOwnerAlertWebhook("https://localhost/hook", "localhost", token))
      .toThrow("independent HTTPS host");
    expect(() => new NodeAOwnerAlertWebhook("https://alerts.example.net/hook", "other.example.net", token))
      .toThrow("independent HTTPS host");
  });

  it("refuses to send credentials or arbitrary caller-supplied fields in alert context", async () => {
    const webhook = new NodeAOwnerAlertWebhook(
      "https://alerts.example.net/hooks/sentryiq", "alerts.example.net", token,
      async () => new Response(null, { status: 204 })
    );
    await expect(webhook.send("integrity_mismatch", {
      node_id: "integrity-a", release_version: "1.2.3", token: "do-not-send"
    })).rejects.toThrow("non-alert data");
  });

  it("surfaces delivery failure, redirect rejection and oversized payloads", async () => {
    const failed = new NodeAOwnerAlertWebhook(
      "https://alerts.example.net/hooks/sentryiq", "alerts.example.net", token,
      async () => new Response(null, { status: 500 })
    );
    await expect(failed.send("integrity_mismatch", { node_id: "integrity-a" })).rejects.toThrow("did not acknowledge");
    const redirect = new NodeAOwnerAlertWebhook(
      "https://alerts.example.net/hooks/sentryiq", "alerts.example.net", token,
      async (_input, init) => {
        expect(init?.redirect).toBe("error");
        return new Response(null, { status: 302 });
      }
    );
    await expect(redirect.send("integrity_mismatch", { node_id: "integrity-a" })).rejects.toThrow("did not acknowledge");
    const oversized = new NodeAOwnerAlertWebhook(
      "https://alerts.example.net/hooks/sentryiq", "alerts.example.net", token,
      async () => new Response(null, { status: 204 })
    );
    await expect(oversized.send("integrity_mismatch", { node_id: "integrity-a", phase: "x".repeat(9000) })).rejects.toThrow("8 KB");
  });
});
