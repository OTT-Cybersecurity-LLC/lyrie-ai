/**
 * dashboard/server.ts — minimal public HTTP server for the Agentic-Attack-
 * Compression live radar feed (Feature 3).
 *
 * Endpoints (node:http only — zero new deps):
 *   GET /                       → self-contained HTML radar page
 *   GET /api/compression/feed   → JSON FeedSnapshot (anonymized/aggregated)
 *   GET /healthz                → { ok: true }
 *
 * The server ONLY ever reads from a `CompressionSignalStore`, which by
 * construction holds anonymized aggregates — no raw signal, host, or
 * operator data is reachable from any endpoint.
 *
 * The request handler (`compressionFeedHandler`) is exported separately so
 * tests can exercise it without binding a real socket.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";

import { CompressionSignalStore } from "./store";
import { renderRadarHtml } from "./ui";

export interface DashboardServerOptions {
  store: CompressionSignalStore;
  /** Max signals returned inline in the feed. Default 200. */
  feedLimit?: number;
  /** Injectable clock for deterministic tests. */
  now?: () => number;
}

/**
 * Pure request handler — resolves a `{ status, contentType, body }` for a
 * given method+path. No socket, fully unit-testable.
 */
export function handleDashboardRequest(
  method: string | undefined,
  url: string | undefined,
  opts: DashboardServerOptions,
): { status: number; contentType: string; body: string } {
  const now = opts.now ?? Date.now;
  const path = (url ?? "/").split("?")[0];

  if (method && method !== "GET") {
    return { status: 405, contentType: "application/json", body: JSON.stringify({ error: "method-not-allowed" }) };
  }

  if (path === "/healthz") {
    return { status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) };
  }

  if (path === "/api/compression/feed") {
    const snapshot = opts.store.snapshot(now(), opts.feedLimit ?? 200);
    return { status: 200, contentType: "application/json", body: JSON.stringify(snapshot) };
  }

  if (path === "/" || path === "/index.html") {
    return { status: 200, contentType: "text/html; charset=utf-8", body: renderRadarHtml() };
  }

  return { status: 404, contentType: "application/json", body: JSON.stringify({ error: "not-found" }) };
}

/** Build (but do not start) a node:http server bound to the given store. */
export function createDashboardServer(opts: DashboardServerOptions): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const { status, contentType, body } = handleDashboardRequest(req.method, req.url, opts);
    res.writeHead(status, {
      "Content-Type": contentType,
      // Public, read-only, cross-origin-safe feed.
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    });
    res.end(body);
  });
}

/** Convenience: build + listen. Resolves with the bound port. */
export function startDashboardServer(
  opts: DashboardServerOptions & { port?: number; host?: string },
): Promise<{ server: Server; port: number }> {
  const server = createDashboardServer(opts);
  return new Promise((resolve) => {
    server.listen(opts.port ?? 0, opts.host ?? "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : (opts.port ?? 0);
      resolve({ server, port });
    });
  });
}
