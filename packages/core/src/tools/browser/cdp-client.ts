/**
 * cdp-client.ts — Pure CDP WebSocket client for Lyrie Browser Tool
 *
 * Zero external dependencies. Uses Node 22 native WebSocket.
 * Reliable CDP client with:
 *   - Configurable timeouts (default 10s per operation)
 *   - Auto-retry on attach failure (3x exponential backoff)
 *   - Proper event-based architecture with cleanup
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CDPTarget {
  id: string;
  type: string;
  title: string;
  url: string;
  webSocketDebuggerUrl: string;
}

export interface CDPSendOptions {
  timeoutMs?: number;
}

export interface CDPClientOptions {
  /** Default timeout per CDP command (ms). Default: 10000 */
  defaultTimeoutMs?: number;
  /** Max retries for connection attempts. Default: 3 */
  maxRetries?: number;
  /** Base backoff for retries (ms). Default: 500 */
  retryBaseMs?: number;
  /** CDP host. Default: http://127.0.0.1:9223 */
  host?: string;
}

export interface CDPMessage {
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: { message: string; code?: number };
}

type EventHandler = (params: Record<string, unknown>) => void;

// ─── CDPSession ───────────────────────────────────────────────────────────────

/**
 * Represents an active WebSocket connection to a single Chrome DevTools target.
 * Created by CDPClient — do not instantiate directly.
 */
export class CDPSession {
  private ws: WebSocket;
  private pending = new Map<
    number,
    { resolve: (r: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }
  >();
  private listeners: Array<{ method: string; handler: EventHandler }> = [];
  private _nextId = 1;
  private _defaultTimeoutMs: number;
  private _closed = false;

  constructor(ws: WebSocket, defaultTimeoutMs: number) {
    this.ws = ws;
    this._defaultTimeoutMs = defaultTimeoutMs;

    ws.addEventListener("message", (evt: MessageEvent) => {
      try {
        const msg: CDPMessage = JSON.parse(evt.data as string);
        if (msg.id != null) {
          const pending = this.pending.get(msg.id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pending.delete(msg.id);
            if (msg.error) {
              pending.reject(new Error(msg.error.message));
            } else {
              pending.resolve(msg.result ?? null);
            }
          }
        } else if (msg.method) {
          for (const listener of this.listeners) {
            if (listener.method === msg.method) {
              listener.handler((msg.params ?? {}) as Record<string, unknown>);
            }
          }
        }
      } catch {
        // Malformed message — ignore
      }
    });

    ws.addEventListener("close", () => {
      this._closed = true;
      // Reject all pending commands
      for (const [, pending] of this.pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("CDP session closed unexpectedly"));
      }
      this.pending.clear();
    });
  }

  get isClosed(): boolean {
    return this._closed;
  }

  /** Send a CDP command and await the result */
  async send<T = unknown>(
    method: string,
    params: Record<string, unknown> = {},
    options: CDPSendOptions = {}
  ): Promise<T> {
    if (this._closed) throw new Error(`CDPSession closed — cannot send ${method}`);

    const id = this._nextId++;
    const timeoutMs = options.timeoutMs ?? this._defaultTimeoutMs;

    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP command "${method}" timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);

      this.pending.set(id, {
        resolve: resolve as (r: unknown) => void,
        reject,
        timer,
      });

      try {
        this.ws.send(JSON.stringify({ id, method, params }));
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err as Error);
      }
    });
  }

  /** Subscribe to a CDP event */
  on(method: string, handler: EventHandler): () => void {
    const entry = { method, handler };
    this.listeners.push(entry);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== entry);
    };
  }

  /** Wait for a CDP event with a timeout */
  waitForEvent(
    method: string,
    timeoutMs: number
  ): Promise<Record<string, unknown> | null> {
    return new Promise((resolve) => {
      let unsubscribe: (() => void) | null = null;
      const timer = setTimeout(() => {
        unsubscribe?.();
        resolve(null); // Timeout is non-fatal for events (SPAs may not fire load)
      }, timeoutMs);

      unsubscribe = this.on(method, (params) => {
        clearTimeout(timer);
        unsubscribe!();
        resolve(params);
      });
    });
  }

  /** Close this session's WebSocket */
  close(): void {
    if (!this._closed) {
      this._closed = true;
      try { this.ws.close(); } catch { /* ignore */ }
    }
  }
}

// ─── CDPClient ────────────────────────────────────────────────────────────────

/**
 * High-level CDP client. Manages target listing, tab creation, and
 * session attachment with retry logic.
 *
 * LyrieBrowser CDPClient design:
 *   - No hardcoded timeouts — all fully configurable; default 10s per operation
 *   - Connection retries with exponential backoff (3x by default)
 *   - All sessions are tracked for safe cleanup
 */
export class CDPClient {
  readonly host: string;
  private defaultTimeoutMs: number;
  private maxRetries: number;
  private retryBaseMs: number;
  private sessions: Set<CDPSession> = new Set();

  constructor(options: CDPClientOptions = {}) {
    this.host = options.host ?? "http://127.0.0.1:9223";
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 10_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.retryBaseMs = options.retryBaseMs ?? 500;
  }

  /** Check if the CDP endpoint is reachable */
  async isAvailable(): Promise<boolean> {
    try {
      const r = await fetch(`${this.host}/json/version`, {
        signal: AbortSignal.timeout(3_000),
      });
      return r.ok;
    } catch {
      return false;
    }
  }

  /** List all page-type targets */
  async listTargets(): Promise<CDPTarget[]> {
    const r = await fetch(`${this.host}/json/list`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!r.ok) throw new Error(`CDP list failed: ${r.status}`);
    const targets: CDPTarget[] = await r.json();
    return targets.filter((t) => t.type === "page");
  }

  /** Open a brand-new tab. Never touches existing tabs. */
  async newTarget(url = "about:blank"): Promise<CDPTarget> {
    const r = await fetch(
      `${this.host}/json/new?${encodeURIComponent(url)}`,
      { method: "PUT", signal: AbortSignal.timeout(5_000) }
    );
    if (!r.ok) throw new Error(`CDP new tab failed: ${r.status}`);
    return r.json();
  }

  /** Close a target by id */
  async closeTarget(targetId: string): Promise<void> {
    await fetch(`${this.host}/json/close/${targetId}`, {
      signal: AbortSignal.timeout(5_000),
    }).catch(() => {});
  }

  /** Activate (focus) a target */
  async activateTarget(targetId: string): Promise<void> {
    await fetch(`${this.host}/json/activate/${targetId}`, {
      signal: AbortSignal.timeout(3_000),
    }).catch(() => {});
  }

  /**
   * Attach a CDPSession to a target's WebSocket debugger URL.
   * Retries up to maxRetries times with exponential backoff.
   *
   * Retries with exponential backoff instead of failing on first timeout.
   */
  async attachSession(wsUrl: string): Promise<CDPSession> {
    let lastError: Error = new Error("CDPClient.attachSession: no attempts made");

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 500ms, 1000ms, 2000ms, …
        const backoffMs = this.retryBaseMs * Math.pow(2, attempt - 1);
        await sleep(backoffMs);
      }

      try {
        const session = await this._connectWS(wsUrl);
        this.sessions.add(session);
        return session;
      } catch (err) {
        lastError = err as Error;
        // Continue to next retry
      }
    }

    throw new Error(
      `CDPClient: failed to attach after ${this.maxRetries} attempts. Last error: ${lastError.message}`
    );
  }

  /** Close all tracked sessions */
  closeAll(): void {
    for (const session of this.sessions) {
      session.close();
    }
    this.sessions.clear();
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private _connectWS(wsUrl: string): Promise<CDPSession> {
    return new Promise((resolve, reject) => {
      // Use a configurable connection timeout
      const connectTimeoutMs = this.defaultTimeoutMs;
      const timer = setTimeout(() => {
        reject(new Error(`CDP WebSocket connect timed out after ${connectTimeoutMs}ms: ${wsUrl}`));
      }, connectTimeoutMs);

      const ws = new WebSocket(wsUrl);

      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve(new CDPSession(ws, this.defaultTimeoutMs));
      });

      ws.addEventListener("error", (evt) => {
        clearTimeout(timer);
        reject(new Error(`CDP WebSocket error connecting to ${wsUrl}: ${(evt as ErrorEvent).message ?? "unknown"}`));
      });
    });
  }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
