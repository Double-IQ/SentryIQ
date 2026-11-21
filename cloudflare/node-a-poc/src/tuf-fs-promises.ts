import { randomUUID } from "node:crypto";
import { __removeTemporaryPath, writeFileSync } from "./tuf-fs";
import { currentTufFsContext } from "./tuf-fs-context";

export async function realpath(path: string): Promise<string> {
  return path;
}

export async function mkdtemp(prefix: string): Promise<string> {
  const path = prefix + randomUUID();
  currentTufFsContext().directories.add(path);
  return path;
}

export async function open(path: string, _flags: string): Promise<{ close(): Promise<void> }> {
  writeFileSync(path, Buffer.alloc(0));
  return { async close() {} };
}

export async function rm(path: string, _options?: { force?: boolean; recursive?: boolean; maxRetries?: number }): Promise<void> {
  __removeTemporaryPath(path);
}
