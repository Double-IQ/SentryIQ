import { createHash } from "node:crypto";

const MAX_MANIFEST_BYTES = 5_000_000;
const MAX_DEPTH = 64;
const MAX_FILES = 100_000;
const STATIC_EXTENSIONS = new Set([
  "css", "js", "mjs", "json", "webmanifest", "svg", "png", "jpg", "jpeg",
  "gif", "webp", "avif", "ico", "woff", "woff2", "ttf", "otf", "eot",
  "txt", "xml", "pdf", "wasm", "map", "html"
]);

export interface ReleaseManifestFile {
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
}

export interface VerifiedReleaseManifest {
  readonly format: 2;
  readonly repository: "Double-IQ/SentryIQ";
  readonly repository_id: "1345956206";
  readonly version: string;
  readonly commit: string;
  readonly workflow_path: ".github/workflows/release.yml";
  readonly public_files: readonly string[];
  readonly runtime_files: readonly string[];
  readonly files: readonly ReleaseManifestFile[];
  readonly publicHttpFiles: readonly ReleaseManifestFile[];
  readonly sha256: string;
}

export function parseAndValidateReleaseManifest(
  bytes: Uint8Array,
  expectedVersion: string,
  expectedCommit: string
): VerifiedReleaseManifest {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 2 || bytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new Error("release manifest is empty or exceeds the 5 MB limit");
  }
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(expectedVersion) ||
      !/^[a-f0-9]{40}$/.test(expectedCommit)) {
    throw new Error("expected release identity is not canonical");
  }

  const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  assertNoDuplicateJsonKeys(source);
  const parsed: unknown = JSON.parse(source);
  if (!isRecord(parsed) || parsed.format !== 2 ||
      parsed.repository !== "Double-IQ/SentryIQ" ||
      parsed.repository_id !== "1345956206" ||
      parsed.version !== expectedVersion ||
      parsed.commit !== expectedCommit ||
      parsed.workflow_path !== ".github/workflows/release.yml" ||
      !Array.isArray(parsed.files) || !Array.isArray(parsed.public_files) ||
      !Array.isArray(parsed.runtime_files)) {
    throw new Error("release manifest identity or schema does not match the approved release");
  }
  if (parsed.files.length < 1 || parsed.files.length > MAX_FILES) {
    throw new Error("release manifest file inventory is empty or exceeds its limit");
  }

  const entries = new Map<string, ReleaseManifestFile>();
  for (const raw of parsed.files) {
    if (!isRecord(raw) || typeof raw.path !== "string" ||
        !Number.isSafeInteger(raw.size) || (raw.size as number) < 0 ||
        typeof raw.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(raw.sha256)) {
      throw new Error("release manifest contains a malformed file entry");
    }
    const path = raw.path;
    if (!isSafeManifestPath(path) || entries.has(path)) {
      throw new Error("release manifest contains an unsafe or duplicate path");
    }
    entries.set(path, { path, size: raw.size as number, sha256: raw.sha256 });
  }

  const publicFiles = validatePathList(parsed.public_files, "public");
  const runtimeFiles = validatePathList(parsed.runtime_files, "runtime");
  const publicSet = new Set(publicFiles);
  const runtimeSet = new Set(runtimeFiles.map((path) => "runtime/" + path));
  if (publicSet.size !== publicFiles.length || runtimeSet.size !== runtimeFiles.length) {
    throw new Error("release manifest contains duplicate inventory paths");
  }
  for (const path of publicFiles) {
    if (path.startsWith("runtime/") || !entries.has(path)) {
      throw new Error("public inventory references an absent or private runtime file");
    }
  }
  for (const path of runtimeSet) {
    if (!entries.has(path)) throw new Error("runtime inventory references an absent file");
  }
  if (entries.size !== publicSet.size + runtimeSet.size) {
    throw new Error("release manifest inventories do not cover the complete file set");
  }
  for (const path of entries.keys()) {
    if (!publicSet.has(path) && !runtimeSet.has(path)) {
      throw new Error("release manifest file is not assigned to a public or runtime inventory");
    }
  }

  const publicHttpFiles = publicFiles
    .filter((path) => isStaticPublicAsset(path))
    .map((path) => entries.get(path)!);
  if (publicHttpFiles.length === 0 || publicHttpFiles.length > 98) {
    throw new Error("release manifest has no bounded byte-verifiable public static assets");
  }

  return {
    format: 2,
    repository: "Double-IQ/SentryIQ",
    repository_id: "1345956206",
    version: expectedVersion,
    commit: expectedCommit,
    workflow_path: ".github/workflows/release.yml",
    public_files: publicFiles,
    runtime_files: runtimeFiles,
    files: [...entries.values()],
    publicHttpFiles,
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

function validatePathList(value: unknown[], label: string): string[] {
  if (value.length > MAX_FILES) throw new Error(label + " inventory exceeds its limit");
  return value.map((path) => {
    if (typeof path !== "string" || !isSafeManifestPath(path)) {
      throw new Error(label + " inventory contains an unsafe path");
    }
    return path;
  });
}

function isStaticPublicAsset(path: string): boolean {
  if (path === "VERSION") return true;
  const extension = path.includes(".") ? path.split(".").pop()!.toLowerCase() : "";
  return STATIC_EXTENSIONS.has(extension);
}

function isSafeManifestPath(path: string): boolean {
  return path.length > 0 && path.length <= 512 && !path.startsWith("/") &&
    !path.includes("\\") && !path.includes("//") && !/[\u0000-\u001f\u007f%?#]/.test(path) &&
    !path.split("/").some((part) => part === "" || part === "." || part === "..");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Reject duplicate object keys before JSON.parse can silently keep the last value. */
export function assertNoDuplicateJsonKeys(source: string): void {
  let index = 0;
  const whitespace = () => { while (/\s/.test(source[index] ?? "")) index++; };
  const stringToken = (): string => {
    const start = index;
    if (source[index++] !== '"') throw new Error("invalid JSON string");
    while (index < source.length) {
      const char = source[index++]!;
      if (char === '"') return JSON.parse(source.slice(start, index)) as string;
      if (char === "\\") {
        if (index >= source.length) throw new Error("truncated JSON escape");
        index++;
      } else if (char.charCodeAt(0) < 0x20) {
        throw new Error("invalid control character in JSON string");
      }
    }
    throw new Error("unterminated JSON string");
  };
  const value = (depth: number): void => {
    if (depth > MAX_DEPTH) throw new Error("release manifest JSON nesting exceeds its limit");
    whitespace();
    const char = source[index];
    if (char === "{") {
      index++;
      whitespace();
      const keys = new Set<string>();
      if (source[index] === "}") { index++; return; }
      while (true) {
        whitespace();
        if (source[index] !== '"') throw new Error("invalid JSON object key");
        const key = stringToken();
        if (keys.has(key)) throw new Error("release manifest contains duplicate JSON object keys");
        keys.add(key);
        whitespace();
        if (source[index++] !== ":") throw new Error("invalid JSON object separator");
        value(depth + 1);
        whitespace();
        const delimiter = source[index++];
        if (delimiter === "}") return;
        if (delimiter !== ",") throw new Error("invalid JSON object delimiter");
      }
    }
    if (char === "[") {
      index++;
      whitespace();
      if (source[index] === "]") { index++; return; }
      while (true) {
        value(depth + 1);
        whitespace();
        const delimiter = source[index++];
        if (delimiter === "]") return;
        if (delimiter !== ",") throw new Error("invalid JSON array delimiter");
      }
    }
    if (char === '"') { stringToken(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(index));
    if (!match) throw new Error("invalid JSON value");
    index += match[0].length;
  };
  value(0);
  whitespace();
  if (index !== source.length) throw new Error("trailing data after release manifest JSON");
}
