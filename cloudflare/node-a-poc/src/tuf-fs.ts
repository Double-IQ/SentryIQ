import { Readable, Writable } from "node:stream";
import { currentTufFsContext } from "./tuf-fs-context";

function persistentRead(path: string): Buffer {
  const context = currentTufFsContext();
  const row = context.sql.exec<{ data: ArrayBuffer | Uint8Array }>(
    "SELECT data FROM tuf_files WHERE path = ?", path
  ).toArray()[0];
  if (!row) throw Object.assign(new Error("ENOENT: no such file or directory"), { code: "ENOENT" });
  return Buffer.from(row.data);
}

export function readFileSync(path: string, options?: string | { encoding?: BufferEncoding }): Buffer | string {
  const context = currentTufFsContext();
  const data = context.temporaryFiles.has(path) ? context.temporaryFiles.get(path)! : persistentRead(path);
  const encoding = typeof options === "string" ? options : options?.encoding;
  return encoding ? data.toString(encoding) : Buffer.from(data);
}

export function writeFileSync(path: string, data: string | ArrayBufferView): void {
  const context = currentTufFsContext();
  const bytes = typeof data === "string" ? Buffer.from(data) : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (path.startsWith("/tmp/")) {
    context.temporaryFiles.set(path, Buffer.from(bytes));
    return;
  }
  context.sql.exec(
    "INSERT INTO tuf_files (path, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
    path, bytes, Date.now()
  );
}

export function existsSync(path: string): boolean {
  const context = currentTufFsContext();
  if (context.temporaryFiles.has(path) || context.directories.has(path)) return true;
  return context.sql.exec<{ present: number }>(
    "SELECT 1 AS present FROM tuf_files WHERE path = ?", path
  ).toArray().length > 0;
}

export function mkdirSync(path: string, _options?: { recursive?: boolean }): void {
  currentTufFsContext().directories.add(path);
}

export function copyFileSync(source: string, destination: string): void {
  writeFileSync(destination, readFileSync(source) as Buffer);
}

export function createReadStream(path: string): Readable {
  return Readable.from([readFileSync(path) as Buffer]);
}

class TufWriteStream extends Writable {
  private chunks: Buffer[] = [];
  constructor(private readonly path: string) {
    super();
  }
  override _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk));
    callback();
  }
  override _final(callback: (error?: Error | null) => void): void {
    try {
      writeFileSync(this.path, Buffer.concat(this.chunks));
      this.chunks = [];
      callback();
    } catch (error) {
      callback(error instanceof Error ? error : new Error(String(error)));
    }
  }
  close(callback?: (error?: Error | null) => void): this {
    this.end(callback);
    return this;
  }
}

export function createWriteStream(path: string): TufWriteStream {
  return new TufWriteStream(path);
}

export function __removeTemporaryPath(path: string): void {
  const context = currentTufFsContext();
  for (const key of context.temporaryFiles.keys()) {
    if (key === path || key.startsWith(path + "/")) context.temporaryFiles.delete(key);
  }
  context.directories.delete(path);
}
