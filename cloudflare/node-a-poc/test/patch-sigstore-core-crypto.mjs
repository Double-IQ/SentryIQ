import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const coreEntry = fileURLToPath(import.meta.resolve("@sigstore/core"));
const cryptoPath = path.join(path.dirname(coreEntry), "crypto.js");
const original = fs.readFileSync(cryptoPath, "utf8");
const target = "return crypto_1.default.verify(algorithm, data, key, signature);";
const replacement = [
  "let verificationAlgorithm = algorithm;",
  "if (verificationAlgorithm === undefined) {",
  "  const keyType = key !== null && typeof key === 'object' && typeof key.asymmetricKeyType === 'string'",
  "    ? key.asymmetricKeyType",
  "    : crypto_1.default.createPublicKey(key).asymmetricKeyType;",
  "  if (keyType === 'ec' || keyType === 'rsa') {",
  "    verificationAlgorithm = 'sha256';",
  "  }",
  "}",
  "return crypto_1.default.verify(verificationAlgorithm, data, key, signature);"
].join("\n");
const occurrences = original.split(target).length - 1;
if (occurrences !== 1) {
  throw new Error("Expected exactly one published verify call in @sigstore/core 4.0.1; found " + occurrences);
}
const patched = original.replace(target, replacement);
if (patched === original) throw new Error("Diagnostic patch made no change");
fs.writeFileSync(cryptoPath, patched);
process.stdout.write("Applied diagnostic-only SHA-256 inference patch to @sigstore/core 4.0.1\n");
