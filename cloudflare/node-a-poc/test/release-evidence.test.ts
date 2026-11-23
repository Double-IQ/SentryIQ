import { describe, expect, it } from "vitest";
import { verifyReleaseEvidence } from "../src/release-evidence";

describe("complete release evidence gate", () => {
  it("rejects an empty or oversized ZIP before contacting GitHub", async () => {
    let called = false;
    const request: typeof fetch = async () => {
      called = true;
      return new Response(null, { status: 500 });
    };
    await expect(verifyReleaseEvidence({
      manifestBytes: new TextEncoder().encode("{}"),
      zipBytes: new Uint8Array(),
      expectedVersion: "0.1.3",
      expectedCommit: "a".repeat(40),
      trustedRootJson: "{}",
      request
    })).rejects.toThrow("ZIP is empty");
    expect(called).toBe(false);
  });

  it("rejects a missing pinned trusted root before network access", async () => {
    let called = false;
    const request: typeof fetch = async () => {
      called = true;
      return new Response(null, { status: 500 });
    };
    await expect(verifyReleaseEvidence({
      manifestBytes: new TextEncoder().encode("{}"),
      zipBytes: new Uint8Array([1]),
      expectedVersion: "0.1.3",
      expectedCommit: "a".repeat(40),
      trustedRootJson: "",
      request
    })).rejects.toThrow("trusted root");
    expect(called).toBe(false);
  });

  it("rejects a manifest identity mismatch before contacting GitHub", async () => {
    let called = false;
    const request: typeof fetch = async () => {
      called = true;
      return new Response(null, { status: 500 });
    };
    await expect(verifyReleaseEvidence({
      manifestBytes: new TextEncoder().encode(JSON.stringify({ format: 2 })),
      zipBytes: new Uint8Array([1]),
      expectedVersion: "0.1.3",
      expectedCommit: "a".repeat(40),
      trustedRootJson: "{}",
      request
    })).rejects.toThrow("identity or schema");
    expect(called).toBe(false);
  });
});
