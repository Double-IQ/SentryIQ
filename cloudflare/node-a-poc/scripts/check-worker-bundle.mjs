import fs from "node:fs";
import path from "node:path";

const outDir = process.argv[2];
if (!outDir || !fs.existsSync(outDir)) {
  throw new Error("Usage: node scripts/check-worker-bundle.mjs <wrangler-outdir>");
}

function collectJavaScript(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...collectJavaScript(fullPath));
    else if (entry.isFile() && /\.(?:m?js|cjs)$/.test(entry.name)) files.push(fullPath);
  }
  return files;
}

const files = collectJavaScript(outDir);
if (files.length === 0) throw new Error("Wrangler produced no JavaScript bundle to inspect");

const forbidden = [
  /@sigstore\/tuf/,
  /\binitTUF\b/,
  /tuf-fs(?:-promises|-context)?/,
  /node:fs(?:\/promises)?/,
  /node:path/,
  /createReadStream/,
  /copyFileSync/
];
const violations = [];
for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  for (const pattern of forbidden) {
    if (pattern.test(source)) violations.push(path.relative(outDir, file) + ": " + pattern);
  }
}
if (violations.length) {
  throw new Error("Worker bundle contains forbidden filesystem TUF code:\n" + violations.join("\n"));
}
process.stdout.write("Verified " + files.length + " Worker JavaScript bundle(s) contain no path-based TUF/filesystem fallback\n");
