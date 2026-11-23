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
} else {
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
}

const modelsPackagePath = fileURLToPath(import.meta.resolve("@tufjs/models/package.json"));
const modelsPackageInfo = JSON.parse(fs.readFileSync(modelsPackagePath, "utf8"));
if (modelsPackageInfo.version !== "5.0.3") {
  throw new Error("SentryIQ Workerd key compatibility patch is pinned to @tufjs/models 5.0.3; found " + modelsPackageInfo.version);
}
const modelsEntry = fileURLToPath(import.meta.resolve("@tufjs/models"));
const modelsKeyPath = path.join(path.dirname(modelsEntry), "utils", "key.js");
let modelsKeySource = fs.readFileSync(modelsKeyPath, "utf8");
const keyTypeMarker = "SENTRYIQ_TUF_MODELS_WORKER_EC_KEY_TYPE_PATCH";
if (modelsKeySource.includes(keyTypeMarker)) {
  process.stdout.write("SentryIQ @tufjs/models Workerd key-type compatibility patch already applied\\n");
} else {
  const keyTypeTarget = "key.asymmetricKeyType !== 'ec'";
  const keyTypeReplacement = "/* " + keyTypeMarker + " */ (key.asymmetricKeyType !== undefined && key.asymmetricKeyType !== 'ec')";
  const keyTypeOccurrences = modelsKeySource.split(keyTypeTarget).length - 1;
  if (keyTypeOccurrences !== 1) {
    throw new Error("Expected one known @tufjs/models 5.0.3 EC key-type check; found " + keyTypeOccurrences + "; refusing to patch an unknown build");
  }
  modelsKeySource = modelsKeySource.replace(keyTypeTarget, keyTypeReplacement);
  fs.writeFileSync(modelsKeyPath, modelsKeySource);
  process.stdout.write("Applied SentryIQ @tufjs/models Workerd EC key-type compatibility patch\\n");
}

const modelsMarker = "SENTRYIQ_TUF_MODELS_WORKER_EC_KEY_DETAILS_PATCH";
if (modelsKeySource.includes(modelsMarker)) {
  process.stdout.write("SentryIQ @tufjs/models Workerd key compatibility patch already applied\n");
} else {
  const modelsTarget = "key.asymmetricKeyDetails?.namedCurve !== namedCurve";
  const modelsReplacement = [
    "/* " + modelsMarker + " */",
    "(key.asymmetricKeyDetails?.namedCurve !== undefined && key.asymmetricKeyDetails.namedCurve !== namedCurve)"
  ].join("\n");
  const modelsOccurrences = modelsKeySource.split(modelsTarget).length - 1;
  if (modelsOccurrences !== 1) {
    throw new Error("Expected one known @tufjs/models 5.0.3 EC curve check; found " + modelsOccurrences + "; refusing to patch an unknown build");
  }
  fs.writeFileSync(modelsKeyPath, modelsKeySource.replace(modelsTarget, modelsReplacement));
  process.stdout.write("Applied SentryIQ @tufjs/models Workerd EC key-detail compatibility patch\n");
}
