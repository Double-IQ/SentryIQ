import { describe, expect, it } from "vitest";
import { verifyReleaseAttestationBundle } from "../src/release-attestation-policy";
import { genuineV012BundleJson } from "./fixtures/genuine-v012-bundle";
import { genuineV012TrustedRootJson } from "./fixtures/genuine-v012-trusted-root";

describe("Node A Sigstore/SLSA release policy", () => {
  it("cryptographically verifies the genuine release bundle and binds its ZIP subject to the tag commit", () => {
    if (!genuineV012BundleJson || !genuineV012TrustedRootJson) {
      throw new Error("CI must inject the genuine GitHub attestation and trusted root");
    }
    const claims = verifyReleaseAttestationBundle(
      genuineV012BundleJson,
      genuineV012TrustedRootJson,
      "0.1.2",
      "9c639a4792cadd5421f01ed198ba2a9261c5145f",
      "sentryiq-0.1.2.zip",
      "41cc5fc46055836ebb21ed4501bd6bd3ace249c4f352da0373b85e5a57d9c49e"
    );
    expect(claims).toMatchObject({
      repository: "Double-IQ/SentryIQ",
      repositoryId: "1345956206",
      version: "0.1.2",
      sourceCommit: "9c639a4792cadd5421f01ed198ba2a9261c5145f",
      workflowCommit: "9c639a4792cadd5421f01ed198ba2a9261c5145f",
      subjectName: "sentryiq-0.1.2.zip"
    });
  });

  it("rejects mismatched tag commits and artifact digests", () => {
    if (!genuineV012BundleJson || !genuineV012TrustedRootJson) {
      throw new Error("CI must inject the genuine GitHub attestation and trusted root");
    }
    expect(() => verifyReleaseAttestationBundle(
      genuineV012BundleJson, genuineV012TrustedRootJson, "0.1.2",
      "0".repeat(40), "sentryiq-0.1.2.zip", "41cc5fc46055836ebb21ed4501bd6bd3ace249c4f352da0373b85e5a57d9c49e"
    )).toThrow("source commit");
    expect(() => verifyReleaseAttestationBundle(
      genuineV012BundleJson, genuineV012TrustedRootJson, "0.1.2",
      "9c639a4792cadd5421f01ed198ba2a9261c5145f", "sentryiq-0.1.2.zip", "0".repeat(64)
    )).toThrow("subject name or digest");
  });
});
