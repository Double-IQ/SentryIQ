import { describe, expect, it } from "vitest";
import { resolveGithubReleaseTagCommit } from "../src/github-release-tag";

const commit = "a".repeat(40);
const tagObject = "b".repeat(40);

describe("GitHub release tag resolution", () => {
  it("resolves a lightweight release tag directly to its commit", async () => {
    const calls: Array<[string, RequestInit | undefined]> = [];
    const request: typeof fetch = async (input, init) => {
      calls.push([String(input), init]);
      return new Response(JSON.stringify({
        ref: "refs/tags/v1.2.3",
        object: { type: "commit", sha: commit }
      }), { status: 200 });
    };
    await expect(resolveGithubReleaseTagCommit("1.2.3", request)).resolves.toBe(commit);
    expect(calls).toHaveLength(1);
    expect(calls[0]![1]?.redirect).toBe("error");
  });

  it("dereferences an annotated release tag and validates the exact ref", async () => {
    const request: typeof fetch = async (input) => String(input).endsWith("/git/ref/tags/v1.2.3")
      ? new Response(JSON.stringify({
          ref: "refs/tags/v1.2.3",
          object: { type: "tag", sha: tagObject }
        }), { status: 200 })
      : new Response(JSON.stringify({
          tag: "v1.2.3",
          object: { type: "commit", sha: commit }
        }), { status: 200 });
    await expect(resolveGithubReleaseTagCommit("1.2.3", request)).resolves.toBe(commit);
  });

  it("rejects wrong refs, non-commit terminal objects, malformed versions and redirects", async () => {
    const wrongRef: typeof fetch = async () => new Response(JSON.stringify({
      ref: "refs/tags/v9.9.9", object: { type: "commit", sha: commit }
    }), { status: 200 });
    await expect(resolveGithubReleaseTagCommit("1.2.3", wrongRef)).rejects.toThrow("canonical tag");
    await expect(resolveGithubReleaseTagCommit("01.2.3", fetch)).rejects.toThrow("not canonical");
    const wrongType: typeof fetch = async () => new Response(JSON.stringify({
      ref: "refs/tags/v1.2.3", object: { type: "tree", sha: commit }
    }), { status: 200 });
    await expect(resolveGithubReleaseTagCommit("1.2.3", wrongType)).rejects.toThrow("commit or annotated tag");
    const redirect: typeof fetch = async () => new Response(null, { status: 302 });
    await expect(resolveGithubReleaseTagCommit("1.2.3", redirect)).rejects.toThrow("non-200");
  });
});
