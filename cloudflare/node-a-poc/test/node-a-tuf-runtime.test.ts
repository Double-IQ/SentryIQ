import { Buffer } from "node:buffer";
import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { canonicalize } from "@tufjs/canonical-json";
import { Metadata, MetadataKind } from "@tufjs/models";
import { getPublicKey } from "@tufjs/models/dist/utils/key.js";
import { verifySignature as verifyTufSignature } from "@tufjs/models/dist/utils/verify.js";
import { describe, expect, it } from "vitest";
import { createNodeAAsyncTufUpdater } from "../src/node-a-tuf-runtime";
import { AsyncTufUpdater } from "../src/async-tuf-updater";
import { tufRootBase64 } from "./fixtures/tuf-root";
import type { RunLock } from "../src/index";
import type { CommittedTufTarget, StoredTufMetadata } from "../src/tuf-storage-contract";

const lock: RunLock = {
  runId: "a".repeat(32),
  fence: 2,
  token: "b".repeat(64),
  expiresAt: Date.now() + 60_000
};

function fakeState() {
  const metadata = new Map<string, StoredTufMetadata>();
  const pointers = new Map<string, CommittedTufTarget>();
  return {
    metadata,
    async readTufMetadata(roleName: string) {
      return metadata.get(roleName) ?? null;
    },
    listTufMetadataRoles() {
      return [...metadata.keys()];
    },
    commitVerifiedTufMetadata(
      roleName: string,
      expected: { version: number; sha256: string } | null,
      next: StoredTufMetadata,
      receivedLock: RunLock
    ) {
      if (receivedLock.runId !== lock.runId || receivedLock.fence !== lock.fence ||
          receivedLock.token !== lock.token) throw new Error("stale lock");
      const current = metadata.get(roleName) ?? null;
      if (expected === null ? current !== null : !current ||
          current.version !== expected.version || current.sha256 !== expected.sha256) {
        throw new Error("metadata CAS mismatch");
      }
      metadata.set(roleName, { ...next, data: next.data.slice() });
      return { version: next.version, sha256: next.sha256 };
    },
    registerTufTargetStage() {},
    listStaleTufTargetStages() { return []; },
    deleteTufTargetStage() {},
    commitTufTargetPointer(
      descriptor: { targetPath: string; length: number; hashes: Readonly<Record<string, string>> },
      _stageId: string,
      objectKey: string,
      receivedLock: RunLock
    ) {
      if (receivedLock.runId !== lock.runId || receivedLock.fence !== lock.fence ||
          receivedLock.token !== lock.token) throw new Error("stale lock");
      const pointer = {
        ...descriptor, objectKey, fence: receivedLock.fence, committedAt: Date.now()
      };
      pointers.set(descriptor.targetPath, pointer);
      return pointer;
    },
    readTufTargetPointer(targetPath: string) {
      return pointers.get(targetPath) ?? null;
    }
  };
}

describe("Node A async TUF runtime assembly", () => {
  it("supports the ECDSA verification primitive required by TUF", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const signed = { _type: "root", version: 1, expires: "2030-01-01T00:00:00Z" };
    const data = Buffer.from(canonicalize(signed));
    const signature = sign("sha256", data, privateKey);
    expect(verify("sha256", data, publicKey, signature)).toBe(true);
  });

  it("preserves the canonical signed root through the upstream TUF model parser", () => {
    const raw = JSON.parse(Buffer.from(tufRootBase64, "base64").toString("utf8"));
    const parsed = Metadata.fromJSON(MetadataKind.Root, raw);
    expect(canonicalize(parsed.signed.toJSON())).toBe(canonicalize(raw.signed));
  });

  it("verifies the provisioned Sigstore TUF root signatures with Workerd crypto", () => {
    const root = JSON.parse(Buffer.from(tufRootBase64, "base64").toString("utf8")) as {
      signed: Record<string, unknown> & { keys: Record<string, { keyval: { public: string } }> };
      signatures: Array<{ keyid: string; sig: string }>;
    };
    const data = Buffer.from(canonicalize(root.signed));
    const valid = root.signatures.filter((signature) => {
      const key = root.signed.keys[signature.keyid];
      return verify(
        "sha256",
        data,
        createPublicKey(key.keyval.public),
        Buffer.from(signature.sig, "hex")
      );
    });
    const parsed = Metadata.fromJSON(MetadataKind.Root, root);
    const modelErrors: string[] = [];
    let modelValid = 0;
    for (const signature of root.signatures) {
      try {
        parsed.signed.keys[signature.keyid].verifySignature(parsed);
        modelValid++;
      } catch (error) {
        modelErrors.push(error instanceof Error ? error.message : String(error));
      }
    }
    expect(valid.length).toBeGreaterThanOrEqual(3);
    const first = root.signatures[0];
    const parsedKey = parsed.signed.keys[first.keyid];
    const parsedPublicKey = getPublicKey({
      keyType: parsedKey.keyType,
      scheme: parsedKey.scheme,
      keyVal: parsedKey.keyVal.public
    });
    const parsedSignature = parsed.signatures[first.keyid].sig;
    const parsedRawVerify = verify(
      "sha256",
      Buffer.from(canonicalize(parsed.signed.toJSON())),
      parsedPublicKey.key,
      Buffer.from(parsedSignature, "hex")
    );
    const tufVerify = verifyTufSignature(
      parsed.signed.toJSON(),
      parsedPublicKey,
      parsedSignature
    );
    expect({ modelValid, modelErrors, parsedRawVerify, tufVerify }).toMatchObject({
      modelValid: 5,
      parsedRawVerify: true,
      tufVerify: true
    });
  });

  it("constructs the real pinned upstream TrustedMetadataStore from the explicit root", async () => {
    const state = fakeState();
    const bucket = {
      async put() { return { size: 0 }; },
      async get() { return null; },
      async delete() {}
    };
    const updater = await createNodeAAsyncTufUpdater({
      state,
      bucket,
      currentLock: () => lock,
      trustAnchor: new Uint8Array(Buffer.from(tufRootBase64, "base64")),
      metadataBaseUrl: "https://tuf.example.test/metadata",
      targetBaseUrl: "https://tuf.example.test/targets"
    });

    expect(updater).toBeInstanceOf(AsyncTufUpdater);
    expect(state.metadata.get("root")?.version).toBeGreaterThan(0);
  });
});

