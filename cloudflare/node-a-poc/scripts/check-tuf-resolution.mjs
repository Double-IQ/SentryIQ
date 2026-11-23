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
