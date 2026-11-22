import { AsyncLocalStorage } from "node:async_hooks";

export interface SqlCursor<T> {
  toArray(): T[];
}

export interface SqlStore {
  exec<T = unknown>(query: string, ...bindings: unknown[]): SqlCursor<T>;
}

export interface TufFsContext {
  sql: SqlStore;
  persistFile?: (path: string, data: Buffer) => void;
  temporaryFiles: Map<string, Buffer>;
  stagedFiles: Map<string, Buffer>;
  directories: Set<string>;
}

const contextStorage = new AsyncLocalStorage<TufFsContext>();

export function currentTufFsContext(): TufFsContext {
  const context = contextStorage.getStore();
  if (!context) throw new Error("TUF filesystem used outside a Durable Object storage context");
  return context;
}

export function createTufFsContext(sql: SqlStore, persistFile?: (path: string, data: Buffer) => void): TufFsContext {
  return { sql, persistFile, temporaryFiles: new Map(), stagedFiles: new Map(), directories: new Set(["/tmp"]) };
}

export function runWithTufFsContext<T>(context: TufFsContext, callback: () => T): T {
  return contextStorage.run(context, callback);
}

export function commitTufFsContext(context: TufFsContext): void {
  for (const [path, data] of context.stagedFiles) {
    context.sql.exec(
      "INSERT INTO tuf_files (path, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(path) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
      path, data, Date.now()
    );
  }
  context.stagedFiles.clear();
}

export function discardTufFsContext(context: TufFsContext): void {
  context.stagedFiles.clear();
  context.temporaryFiles.clear();
}
