import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packagePath = fileURLToPath(import.meta.resolve("@sigstore/core/package.json"));
const packageInfo = JSON.parse(fs.readFileSync(packagePath, "utf8"));
if (packageInfo.version !== "4.0.1") {
  throw new Error("SentryIQ compatibility patch is pinned to @sigstore/core 4.0.1; found " + packageInfo.version);
}

const coreEntry = fileURLToPath(import.meta.resolve("@sigstore/core"));
const cryptoPath = path.join(path.dirname(coreEntry), "crypto.js");
const original = fs.readFileSync(cryptoPath, "utf8");
const marker = "SENTRYIQ_CORE_EC_RSA_SHA256_INFERENCE_PATCH";
if (original.includes(marker)) {
  process.stdout.write("SentryIQ @sigstore/core compatibility patch already applied\n");
  process.exit(0);
}

const target = "return crypto_1.default.verify(algorithm, data, key, signature);";
const replacement = [
  "/* " + marker + " */",
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
  throw new Error("Expected one known @sigstore/core 4.0.1 verification call; found " + occurrences + "; refusing to patch an unknown build");
}
fs.writeFileSync(cryptoPath, original.replace(target, replacement));
process.stdout.write("Applied SentryIQ @sigstore/core 4.0.1 EC/RSA SHA-256 compatibility patch\n");
