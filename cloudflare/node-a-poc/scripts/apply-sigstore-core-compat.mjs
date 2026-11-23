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
  process.stdout.write("SentryIQ @tufjs/models Workerd key-type compatibility patch already applied\n");
} else {
  const keyTypeTarget = "key.asymmetricKeyType !== 'ec'";
  const keyTypeReplacement = "/* " + keyTypeMarker + " */ (key.asymmetricKeyType !== undefined && key.asymmetricKeyType !== 'ec')";
  const keyTypeOccurrences = modelsKeySource.split(keyTypeTarget).length - 1;
  if (keyTypeOccurrences !== 1) {
    throw new Error("Expected one known @tufjs/models 5.0.3 EC key-type check; found " + keyTypeOccurrences + "; refusing to patch an unknown build");
  }
  modelsKeySource = modelsKeySource.replace(keyTypeTarget, keyTypeReplacement);
  fs.writeFileSync(modelsKeyPath, modelsKeySource);
  process.stdout.write("Applied SentryIQ @tufjs/models Workerd EC key-type compatibility patch\n");
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

const modelsVerifyPath = path.join(path.dirname(modelsEntry), "utils", "verify.js");
let modelsVerifySource = fs.readFileSync(modelsVerifyPath, "utf8");
const verifyMarker = "SENTRYIQ_TUF_MODELS_WORKER_NAMED_CRYPTO_VERIFY_PATCH";
if (modelsVerifySource.includes(verifyMarker)) {
  process.stdout.write("SentryIQ @tufjs/models named crypto verify patch already applied\n");
} else {
  const esmImport = "import crypto from 'crypto';";
  const esmCall = "return crypto.verify(";
  const cjsImport = 'const crypto_1 = __importDefault(require("crypto"));';
  const cjsCall = "return crypto_1.default.verify(";
  if (modelsVerifySource.includes(esmImport) && modelsVerifySource.includes(esmCall)) {
    modelsVerifySource = modelsVerifySource.replace(esmImport, "import { verify as nodeCryptoVerify } from 'node:crypto';").replace(esmCall, "return nodeCryptoVerify(");
  } else if (modelsVerifySource.includes('import crypto from "crypto";') && modelsVerifySource.includes(esmCall)) {
    modelsVerifySource = modelsVerifySource.replace('import crypto from "crypto";', 'import { verify as nodeCryptoVerify } from "node:crypto";').replace(esmCall, "return nodeCryptoVerify(");
  } else if (modelsVerifySource.includes(cjsImport) && modelsVerifySource.includes(cjsCall)) {
    modelsVerifySource = modelsVerifySource.replace(cjsImport, 'const nodeCryptoVerify = require("node:crypto").verify;').replace(cjsCall, "return nodeCryptoVerify(");
  } else {
    throw new Error("Could not identify the pinned @tufjs/models 5.0.3 crypto.verify import/call; refusing an unknown build");
  }
  modelsVerifySource = "/* " + verifyMarker + " */\n" + modelsVerifySource;
  fs.writeFileSync(modelsVerifyPath, modelsVerifySource);
  process.stdout.write("Applied SentryIQ @tufjs/models named node:crypto.verify compatibility patch\n");
}

const modelsKeyMarker = "SENTRYIQ_TUF_MODELS_WORKER_NAMED_CRYPTO_KEY_PATCH";
let modelsKeyRuntimeSource = fs.readFileSync(modelsKeyPath, "utf8");
if (modelsKeyRuntimeSource.includes(modelsKeyMarker)) {
  process.stdout.write("SentryIQ @tufjs/models named crypto key patch already applied\\n");
} else {
  const esmKeyImport = "import crypto from 'crypto';";
  const cjsKeyImport = 'const crypto_1 = __importDefault(require("crypto"));';
  if (modelsKeyRuntimeSource.includes(esmKeyImport)) {
    modelsKeyRuntimeSource = modelsKeyRuntimeSource.replace(esmKeyImport, "import { constants, createPublicKey } from 'node:crypto';");
    const calls = modelsKeyRuntimeSource.split("crypto.createPublicKey(").length - 1;
    if (calls !== 5) throw new Error("Expected five pinned @tufjs/models createPublicKey calls; found " + calls);
    modelsKeyRuntimeSource = modelsKeyRuntimeSource.replaceAll("crypto.createPublicKey(", "createPublicKey(");
    modelsKeyRuntimeSource = modelsKeyRuntimeSource.replace("crypto.constants.RSA_PKCS1_PSS_PADDING", "constants.RSA_PKCS1_PSS_PADDING");
  } else if (modelsKeyRuntimeSource.includes(cjsKeyImport)) {
    modelsKeyRuntimeSource = modelsKeyRuntimeSource.replace(cjsKeyImport, 'const { constants, createPublicKey } = require("node:crypto");');
    const calls = modelsKeyRuntimeSource.split("crypto_1.default.createPublicKey(").length - 1;
    if (calls !== 5) throw new Error("Expected five pinned @tufjs/models createPublicKey calls; found " + calls);
    modelsKeyRuntimeSource = modelsKeyRuntimeSource.replaceAll("crypto_1.default.createPublicKey(", "createPublicKey(");
    modelsKeyRuntimeSource = modelsKeyRuntimeSource.replace("crypto_1.default.constants.RSA_PKCS1_PSS_PADDING", "constants.RSA_PKCS1_PSS_PADDING");
  } else {
    throw new Error("Could not identify the pinned @tufjs/models 5.0.3 crypto key import; refusing an unknown build");
  }
  modelsKeyRuntimeSource = "/* " + modelsKeyMarker + " */\\n" + modelsKeyRuntimeSource;
  fs.writeFileSync(modelsKeyPath, modelsKeyRuntimeSource);
  process.stdout.write("Applied SentryIQ @tufjs/models named node:crypto key patch\\n");
}
