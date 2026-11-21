import { AsyncLocalStorage } from "node:async_hooks";

export interface SqlCursor<T> {
  toArray(): T[];
}

export interface SqlStore {
  exec<T = unknown>(query: string, ...bindings: unknown[]): SqlCursor<T>;
}

export interface TufFsContext {
  sql: SqlStore;
  temporaryFiles: Map<string, Buffer>;
  directories: Set<string>;
}

const contextStorage = new AsyncLocalStorage<TufFsContext>();

export function currentTufFsContext(): TufFsContext {
  const context = contextStorage.getStore();
  if (!context) throw new Error("TUF filesystem used outside a Durable Object storage context");
  return context;
}

export function createTufFsContext(sql: SqlStore): TufFsContext {
  return { sql, temporaryFiles: new Map(), directories: new Set(["/tmp"]) };
}

export function runWithTufFsContext<T>(context: TufFsContext, callback: () => T): T {
  return contextStorage.run(context, callback);
}
