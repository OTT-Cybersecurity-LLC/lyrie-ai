/**
 * MCP Client — connects to an MCP server over stdio or HTTP/SSE,
 * negotiates protocol version, lists tools, and calls them.
 *
 * Spec: https://modelcontextprotocol.io/specification (2025-06-18 baseline,
 * forward-compatible with the 2026 draft).
 *
 * Phase 1 deliberately ships the surface every Lyrie skill needs: initialize,
 * tools/list, tools/call, resources/list, plus shutdown. Anything the spec
 * adds later can be appended without breaking callers.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";

import type {
  CallToolParams,
  CallToolResult,
  InitializeParams,
  InitializeResult,
  JsonRpcRequest,
  JsonRpcResponse,
  ListResourcesResult,
  ListToolsResult,
  Resource,
  ServerCapabilities,
  Tool,
  Transport,
} from "./types";

const PROTOCOL_VERSION = "2025-06-18";
const CLIENT_INFO = { name: "lyrie-agent", version: "0.1.1" };

// ─── Transport abstraction ───────────────────────────────────────────────────

interface TransportConn {
  send(line: string): void;
  close(): void;
  /** Resolve when the transport is fully shut down. */
  wait(): Promise<void>;
}

class StdioConn implements TransportConn {
  private child: ChildProcessWithoutNullStreams;
  private buffer = "";

  constructor(
    transport: Extract<Transport, { type: "stdio" }>,
    onLine: (line: string) => void,
  ) {
    this.child = spawn(transport.command, transport.args ?? [], {
      env: { ...process.env, ...(transport.env ?? {}) } as NodeJS.ProcessEnv,
      cwd: transport.cwd,
      stdio: ["pipe", "pipe", "pipe"],
    });

    this.child.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf8");
      let nl: number;
      // eslint-disable-next-line no-cond-assign
      while ((nl = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, nl).trim();
        this.buffer = this.buffer.slice(nl + 1);
        if (line) onLine(line);
      }
    });

    this.child.stderr.on("data", (chunk: Buffer) => {
      // MCP stdio servers commonly log to stderr; surface as debug.
      process.stderr.write(`[mcp:${transport.command}] ${chunk}`);
    });
  }

  send(line: string) {
    this.child.stdin.write(line + "\n");
  }

  close() {
    try {
      this.child.stdin.end();
      this.child.kill();
    } catch {
      // already gone
    }
  }

  async wait(): Promise<void> {
    if (this.child.exitCode !== null) return;
    await new Promise<void>((resolve) => this.child.once("exit", () => resolve()));
  }
}

class HttpConn implements TransportConn {
  private base: string;
  private headers: Record<string, string>;
  private onLine: (line: string) => void;
  private streamCtl: AbortController | null = null;

  constructor(
    transport: Extract<Transport, { type: "http" | "sse" }>,
    onLine: (line: string) => void,
  ) {
    this.base = transport.url.replace(/\/$/, "");
    this.headers = {
      "Content-Type": "application/json",
      Accept: transport.type === "sse" ? "text/event-stream" : "application/json",
      ...(transport.headers ?? {}),
    };
    this.onLine = onLine;
    if (transport.type === "sse") void this.openSse();
  }

  private async openSse() {
    this.streamCtl = new AbortController();
    try {
      const res = await fetch(this.base + "/sse", {
        headers: this.headers,
        signal: this.streamCtl.signal,
      });
      if (!res.body) return;
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let idx: number;
        // eslint-disable-next-line no-cond-assign
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const evt = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          for (const line of evt.split("\n")) {
            if (line.startsWith("data: ")) this.onLine(line.slice(6));
          }
        }
      }
    } catch {
      // stream closed
    }
  }

  async send(line: string) {
    const res = await fetch(this.base, {
      method: "POST",
      headers: this.headers,
      body: line,
    });
    if (res.headers.get("content-type")?.includes("application/json")) {
      const body = await res.text();
      if (body) this.onLine(body);
    }
  }

  close() {
    this.streamCtl?.abort();
  }

  async wait(): Promise<void> {
    /* nothing to wait on */
  }
}

// ─── Client ──────────────────────────────────────────────────────────────────

export interface McpClientOptions {
  /** Human name used to namespace tools when surfaced to the agent */
  name: string;
  transport: Transport;
  /** Optional default request timeout in ms (default: 30s) */
  requestTimeoutMs?: number;
}

export class McpClient {
  readonly name: string;
  private conn: TransportConn | null = null;
  private inflight = new Map<
    string | number,
    { resolve: (v: unknown) => void; reject: (e: unknown) => void; timer?: NodeJS.Timeout }
  >();
  private serverCapabilities: ServerCapabilities | null = null;
  private serverInfo: InitializeResult["serverInfo"] | null = null;
  private timeoutMs: number;
  private opts: McpClientOptions;

  constructor(opts: McpClientOptions) {
    this.name = opts.name;
    this.timeoutMs = opts.requestTimeoutMs ?? 30_000;
    this.opts = opts;
  }

  // ── lifecycle ────────────────────────────────────────────────────────────

  async connect(): Promise<InitializeResult> {
    if (this.conn) throw new Error("already connected");
    const onLine = (line: string) => this.onMessage(line);
    if (this.opts.transport.type === "stdio") {
      this.conn = new StdioConn(this.opts.transport, onLine);
    } else {
      this.conn = new HttpConn(this.opts.transport, onLine);
    }

    const init = await this.request<InitializeResult>("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { roots: { listChanged: false } },
      clientInfo: CLIENT_INFO,
    } satisfies InitializeParams);

    this.serverCapabilities = init.capabilities;
    this.serverInfo = init.serverInfo;

    // notifications/initialized — fire-and-forget
    this.notify("notifications/initialized", {});

    return init;
  }

  async disconnect(): Promise<void> {
    if (!this.conn) return;
    try {
      this.notify("notifications/cancelled", {});
    } catch {
      /* noop */
    }
    this.conn.close();
    await this.conn.wait();
    this.conn = null;
  }

  capabilities(): ServerCapabilities | null {
    return this.serverCapabilities;
  }

  info(): InitializeResult["serverInfo"] | null {
    return this.serverInfo;
  }

  // ── high-level methods ───────────────────────────────────────────────────

  async listTools(): Promise<Tool[]> {
    if (!this.serverCapabilities?.tools) return [];
    const r = await this.request<ListToolsResult>("tools/list", {});
    return r.tools;
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<CallToolResult> {
    return await this.request<CallToolResult>("tools/call", {
      name,
      arguments: args,
    } satisfies CallToolParams);
  }

  async listResources(): Promise<Resource[]> {
    if (!this.serverCapabilities?.resources) return [];
    const r = await this.request<ListResourcesResult>("resources/list", {});
    return r.resources;
  }

  // ── JSON-RPC plumbing ────────────────────────────────────────────────────

  private request<R>(method: string, params: unknown): Promise<R> {
    if (!this.conn) return Promise.reject(new Error("not connected"));
    const id = randomUUID();
    const req: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
    return new Promise<R>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inflight.delete(id);
        reject(new Error(`MCP request timeout: ${method}`));
      }, this.timeoutMs);
      this.inflight.set(id, {
        resolve: (v) => resolve(v as R),
        reject,
        timer,
      });
      this.conn!.send(JSON.stringify(req));
    });
  }

  private notify(method: string, params: unknown) {
    if (!this.conn) return;
    this.conn.send(JSON.stringify({ jsonrpc: "2.0", method, params }));
  }

  private onMessage(line: string) {
    let msg: JsonRpcResponse;
    try {
      msg = JSON.parse(line);
    } catch {
      return; // ignore garbled lines (some servers print banners)
    }
    if (msg.id == null) return; // notification or stray
    const pending = this.inflight.get(msg.id);
    if (!pending) return;
    this.inflight.delete(msg.id);
    if (pending.timer) clearTimeout(pending.timer);
    if (msg.error) {
      pending.reject(new Error(`[mcp ${msg.error.code}] ${msg.error.message}`));
    } else {
      pending.resolve(msg.result);
    }
  }
}
