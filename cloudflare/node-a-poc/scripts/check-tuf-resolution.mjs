import fs from "node:fs";
import path from "node:path";

const expected = new Map([
  ["tuf-js", "6.0.3"],
  ["@tufjs/models", "5.0.3"],
  ["@sigstore/core", "4.0.1"]
]);

for (const [name, version] of expected) {
  const manifestPath = path.join("node_modules", name, "package.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Required pinned package is missing: ${name}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.name !== name || manifest.version !== version) {
    throw new Error(
      `Unexpected ${name} package resolution: expected ${version}, got ${manifest.version ?? "unknown"}`
    );
  }
  process.stdout.write(`Verified ${name}@${version}\n`);
}

const workerEntry = fs.readFileSync(path.join("src", "index.ts"), "utf8");
const forbiddenWorkerImports = [
  /from ["']@sigstore\/tuf["']/,
  /from ["']node:fs(?:\/promises)?["']/,
  /from ["']node:path["']/,
  /from ["']\\.\/tuf-fs(?:-promises|-context)?["']/
];
for (const pattern of forbiddenWorkerImports) {
  if (pattern.test(workerEntry)) {
    throw new Error("Production Worker entry contains a forbidden path-based TUF/filesystem import: " + pattern);
  }
}
process.stdout.write("Verified production Worker entry has no path-based TUF/filesystem imports\\n");
