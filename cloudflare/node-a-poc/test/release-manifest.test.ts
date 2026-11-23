import { describe, expect, it } from "vitest";
import { assertNoDuplicateJsonKeys, parseAndValidateReleaseManifest } from "../src/release-manifest";

const commit = "a".repeat(40);
const digest = "b".repeat(64);

function manifest() {
  return {
    format: 2,
    repository: "Double-IQ/SentryIQ",
    repository_id: "1345956206",
    version: "0.1.3",
    commit,
    workflow_path: ".github/workflows/release.yml",
    public_files: ["index.php", "assets/app.js", "assets/site.css"],
    runtime_files: ["config.php"],
    files: [
      { path: "index.php", size: 10, sha256: digest },
      { path: "assets/app.js", size: 20, sha256: digest },
      { path: "assets/site.css", size: 30, sha256: digest },
      { path: "runtime/config.php", size: 40, sha256: digest }
    ]
  };
}

describe("Node A signed release manifest policy", () => {
  it("validates exact repository, version, commit, and complete public/runtime inventory", () => {
    const result = parseAndValidateReleaseManifest(
      new TextEncoder().encode(JSON.stringify(manifest())), "0.1.3", commit
    );
    expect(result.publicHttpFiles.map((entry) => entry.path)).toEqual(["assets/app.js", "assets/site.css"]);
    expect(result.files).toHaveLength(4);
  });

  it("rejects duplicate JSON object keys including escaped-equivalent keys", () => {
    expect(() => assertNoDuplicateJsonKeys('{"version":"0.1.3","\\u0076ersion":"0.1.4"}')).toThrow("duplicate");
  });

  it("rejects malformed UTF-8, wrong identity, duplicate paths, and unassigned files", () => {
    expect(() => parseAndValidateReleaseManifest(new Uint8Array([0xff, 0xfe]), "0.1.3", commit)).toThrow();
    const wrong = manifest();
    wrong.repository_id = "0";
    expect(() => parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify(wrong)), "0.1.3", commit)).toThrow();
    const numericRepositoryId = manifest();
    (numericRepositoryId as unknown as { repository_id: number }).repository_id = 1345956206;
    expect(() => parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify(numericRepositoryId)), "0.1.3", commit)).toThrow();
    const duplicate = manifest();
    duplicate.files.push({ ...duplicate.files[0]! });
    expect(() => parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify(duplicate)), "0.1.3", commit)).toThrow("duplicate");
    const unassigned = manifest();
    unassigned.files.push({ path: "hidden.bin", size: 1, sha256: digest });
    expect(() => parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify(unassigned)), "0.1.3", commit)).toThrow("complete file set");
  });

  it("rejects traversal, encoded paths, and a public inventory entry pointing into runtime", () => {
    const traversal = manifest();
    traversal.public_files[0] = "../secret";
    expect(() => parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify(traversal)), "0.1.3", commit)).toThrow();
    const privatePath = manifest();
    privatePath.public_files[0] = "runtime/config.php";
    expect(() => parseAndValidateReleaseManifest(new TextEncoder().encode(JSON.stringify(privatePath)), "0.1.3", commit)).toThrow();
  });
});
