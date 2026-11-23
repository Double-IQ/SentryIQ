const CANONICAL_APPLICATION_HOST = "sentryiq.bichet.co.za";
const MAX_ALERT_BODY_BYTES = 8_192;
const MAX_ALERT_RESPONSE_BYTES = 4_096;

/**
 * Generic owner-controlled HTTPS webhook transport. The endpoint and exact
 * hostname allowlist must be supplied by the operator; the webhook provider
 * must be independent of the SentryIQ application host and Node 4.
 */
export class NodeAOwnerAlertWebhook {
  private readonly endpoint: string;

  constructor(
    endpoint: string,
    allowedHost: string,
    private readonly bearerToken: string,
    private readonly request: typeof fetch = fetch,
    private readonly clock: () => number = () => Math.floor(Date.now() / 1000)
  ) {
    let url: URL;
    try { url = new URL(endpoint); }
    catch { throw new Error("owner-alert webhook endpoint is invalid"); }
    const host = allowedHost.toLowerCase();
    if (url.protocol !== "https:" || url.hostname.toLowerCase() !== host ||
        host === "" || host === CANONICAL_APPLICATION_HOST ||
        host.endsWith(".bichet.co.za") || isLocalOrLiteralAddress(host) ||
        (url.port !== "" && url.port !== "443") || url.username !== "" ||
        url.password !== "" || url.search !== "" || url.hash !== "" ||
        url.pathname === "/" || !/^[A-Za-z0-9_-]{40,128}$/.test(bearerToken)) {
      throw new Error("owner-alert webhook must use an exact independent HTTPS host and strong credential");
    }
    this.endpoint = url.toString();
  }

  async send(reason: string, context: Record<string, unknown>): Promise<void> {
    if (!/^[a-z0-9_]{1,80}$/.test(reason) || !isSafeAlertContext(context)) {
      throw new Error("owner-alert event identity or context is invalid or contains non-alert data");
    }
    const issuedAt = this.clock();
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 1) {
      throw new Error("owner-alert clock returned an invalid timestamp");
    }
    const body = JSON.stringify({
      schema_version: 1,
      node_id: "integrity-a",
      event: reason,
      issued_at: issuedAt,
      context
    });
    if (new TextEncoder().encode(body).byteLength > MAX_ALERT_BODY_BYTES) {
      throw new Error("owner-alert webhook payload exceeds the 8 KB limit");
    }
    const response = await this.request(this.endpoint, {
      method: "POST",
      redirect: "error",
      headers: {
        Authorization: "Bearer " + this.bearerToken,
        "Content-Type": "application/json",
        Accept: "application/json",
        "Cache-Control": "no-store"
      },
      body
    });
    if (![200, 202, 204].includes(response.status)) {
      if (response.body) await response.body.cancel();
      throw new Error("independent owner-alert webhook did not acknowledge delivery");
    }
    if (response.body) {
      const reader = response.body.getReader();
      let length = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          length += value.byteLength;
          if (length > MAX_ALERT_RESPONSE_BYTES) {
            throw new Error("owner-alert webhook response exceeds its 4 KB limit");
          }
        }
      } catch (error) {
        try { await reader.cancel(error); } catch { /* preserve original error */ }
        throw error;
      } finally {
        reader.releaseLock();
      }
    }
  }
}

function isLocalOrLiteralAddress(host: string): boolean {
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
      host.startsWith("[") || /^[0-9.]+$/.test(host)) return true;
  return false;
}

function isSafeAlertContext(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const context = value as Record<string, unknown>;
  const allowed = new Set(["node_id", "phase", "release_version", "commit", "mismatch_count", "exception"]);
  if (Object.keys(context).some((key) => !allowed.has(key)) || context.node_id !== "integrity-a") return false;
  if (context.phase !== undefined && (typeof context.phase !== "string" || !/^[a-z0-9_]{1,80}$/.test(context.phase))) return false;
  if (context.release_version !== undefined && (typeof context.release_version !== "string" || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(context.release_version))) return false;
  if (context.commit !== undefined && (typeof context.commit !== "string" || !/^[a-f0-9]{40}$/.test(context.commit))) return false;
  if (context.mismatch_count !== undefined && (!Number.isSafeInteger(context.mismatch_count) || (context.mismatch_count as number) < 0 || (context.mismatch_count as number) > 100)) return false;
  if (context.exception !== undefined && (typeof context.exception !== "string" || !/^[A-Za-z][A-Za-z0-9]{0,79}$/.test(context.exception))) return false;
  return true;
}

