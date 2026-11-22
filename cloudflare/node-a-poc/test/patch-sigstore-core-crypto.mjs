import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const coreEntry = fileURLToPath(import.meta.resolve("@sigstore/core"));
const cryptoPath = path.join(path.dirname(coreEntry), "crypto.js");
const original = fs.readFileSync(cryptoPath, "utf8");
const pattern = /const keyType =\s*key instanceof crypto\.KeyObject\s*\?\s*key\.asymmetricKeyType\s*:\s*crypto\.createPublicKey\(key\)\.asymmetricKeyType;/s;
const replacement = "const keyType = key !== null && typeof key === 'object' && typeof key.asymmetricKeyType === 'string' ? key.asymmetricKeyType : crypto.createPublicKey(key).asymmetricKeyType;";
if (!pattern.test(original)) {
  throw new Error("Pinned @sigstore/core crypto helper did not match the expected 4.0.1 implementation; refusing to apply diagnostic patch");
}
const patched = original.replace(pattern, replacement);
if (patched === original) throw new Error("Diagnostic patch made no change");
fs.writeFileSync(cryptoPath, patched);
process.stdout.write("Applied diagnostic-only KeyObject algorithm-inference patch to pinned @sigstore/core\n");
