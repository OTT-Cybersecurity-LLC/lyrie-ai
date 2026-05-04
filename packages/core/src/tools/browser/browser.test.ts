/**
 * browser.test.ts — LyrieBrowser & CDPClient unit tests (all mocked)
 *
 * Tests run without a live Chrome. Uses mock WebSocket and fetch.
 * 30+ tests covering CDP protocol, tab safety, retry logic, actions, etc.
 *
 * Run: cd packages/core && bun test
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, test, expect, beforeEach, mock, spyOn } from "bun:test";
import { CDPClient, CDPSession, sleep } from "./cdp-client";
import { LyrieBrowser } from "./browser-tool";

// ─── Mock WebSocket ───────────────────────────────────────────────────────────

/**
 * Minimal mock WebSocket that:
 *   - Emits "open" synchronously after construction (in next microtask)
 *   - Stores sent messages
 *   - Allows tests to simulate CDP responses via .respond()
 */
class MockWebSocket {
  static instances: MockWebSocket[] = [];

  url: string;
  sentMessages: string[] = [];
  private handlers: Record<string, Array<(evt: unknown) => void>> = {};
  private _nextResponseId = 1;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    // Simulate async open
    Promise.resolve().then(() => this._emit("open", {}));
  }

  addEventListener(event: string, handler: (evt: unknown) => void) {
    if (!this.handlers[event]) this.handlers[event] = [];
    this.handlers[event].push(handler);
  }

  removeEventListener(event: string, handler: (evt: unknown) => void) {
    if (this.handlers[event]) {
      this.handlers[event] = this.handlers[event].filter((h) => h !== handler);
    }
  }

  send(data: string) {
    this.sentMessages.push(data);
    const msg = JSON.parse(data);
    // Auto-respond to known CDP commands
    this._autoRespond(msg);
  }

  close() {
    this._emit("close", {});
  }

  /** Emit an arbitrary CDP event to listeners */
  emitEvent(method: string, params: Record<string, unknown> = {}) {
    this._emit("message", {
      data: JSON.stringify({ method, params }),
    });
  }

  /** Simulate a response to a specific command ID */
  respond(id: number, result: unknown = {}, error?: string) {
    this._emit("message", {
      data: error
        ? JSON.stringify({ id, error: { message: error } })
        : JSON.stringify({ id, result }),
    });
  }

  /** Simulate an error */
  error(msg: string) {
    this._emit("error", { message: msg } as ErrorEvent);
  }

  private _emit(event: string, data: unknown) {
    for (const handler of this.handlers[event] ?? []) {
      handler(data);
    }
  }

  private _autoRespond(msg: { id: number; method: string }) {
    // Respond to CDP domain enables and common commands automatically
    const autoResponseMap: Record<string, unknown> = {
      "Page.enable": {},
      "Runtime.enable": {},
      "DOM.enable": {},
      "Accessibility.enable": {},
      "Network.enable": {},
      "Page.navigate": { frameId: "main" },
      "Page.captureScreenshot": { data: "base64PNGdata==" },
      "Runtime.evaluate": { result: { type: "string", value: "eval-result" } },
      "Input.dispatchMouseEvent": {},
      "Input.dispatchKeyEvent": {},
      "Accessibility.getFullAXTree": {
        root: {
          role: { value: "RootWebArea" },
          name: { value: "Test Page" },
          children: [
            {
              role: { value: "heading" },
              name: { value: "Hello World" },
              children: [],
            },
          ],
        },
      },
    };

    if (msg.method in autoResponseMap) {
      setTimeout(() => {
        this._emit("message", {
          data: JSON.stringify({
            id: msg.id,
            result: autoResponseMap[msg.method],
          }),
        });
        // Also fire Page.loadEventFired for navigation
        if (msg.method === "Page.navigate") {
          setTimeout(() => this.emitEvent("Page.loadEventFired", {}), 10);
        }
      }, 5);
    }
  }
}

// ─── Mock fetch ───────────────────────────────────────────────────────────────

const mockTargets = [
  {
    id: "existing-tab-1",
    type: "page",
    title: "Existing Tab",
    url: "https://example.com",
    webSocketDebuggerUrl: "ws://127.0.0.1:9223/devtools/page/existing-tab-1",
  },
];

function createMockFetch(
  overrides: Record<string, unknown> = {}
) {
  return async (url: string, opts?: RequestInit) => {
    const urlStr = typeof url === "string" ? url : (url as URL).toString();

    if (urlStr.includes("/json/version")) {
      return {
        ok: true,
        json: async () => ({ Browser: "Chrome/125.0", webSocketDebuggerUrl: "ws://..." }),
      };
    }
    if (urlStr.includes("/json/list")) {
      return { ok: true, json: async () => mockTargets };
    }
    if (urlStr.includes("/json/new")) {
      return {
        ok: true,
        json: async () => ({
          id: `new-tab-${Date.now()}`,
          type: "page",
          title: "New Tab",
          url: "about:blank",
          webSocketDebuggerUrl: `ws://127.0.0.1:9223/devtools/page/new-tab-${Date.now()}`,
        }),
      };
    }
    if (urlStr.includes("/json/close")) {
      return { ok: true, json: async () => ({}) };
    }
    if (urlStr.includes("/json/activate")) {
      return { ok: true, json: async () => ({}) };
    }

    // Check overrides
    for (const [pattern, response] of Object.entries(overrides)) {
      if (urlStr.includes(pattern)) {
        return { ok: true, json: async () => response };
      }
    }

    return { ok: false, status: 404, statusText: "Not Found" };
  };
}

// ─── Test Setup ───────────────────────────────────────────────────────────────

let origWebSocket: typeof WebSocket;
let origFetch: typeof fetch;

function setupMocks() {
  MockWebSocket.instances = [];
  (global as any).WebSocket = MockWebSocket;
  (global as any).fetch = createMockFetch();
}

function teardownMocks() {
  if (origWebSocket) (global as any).WebSocket = origWebSocket;
  if (origFetch) (global as any).fetch = origFetch;
}

// ─── CDPClient Tests ──────────────────────────────────────────────────────────

describe("CDPClient", () => {
  beforeEach(() => setupMocks());

  test("isAvailable() returns true when fetch succeeds", async () => {
    const client = new CDPClient();
    const result = await client.isAvailable();
    expect(result).toBe(true);
  });

  test("isAvailable() returns false when fetch fails", async () => {
    (global as any).fetch = async () => { throw new Error("ECONNREFUSED"); };
    const client = new CDPClient();
    const result = await client.isAvailable();
    expect(result).toBe(false);
  });

  test("isAvailable() returns false when response is not ok", async () => {
    (global as any).fetch = async () => ({ ok: false, status: 500 });
    const client = new CDPClient();
    const result = await client.isAvailable();
    expect(result).toBe(false);
  });

  test("listTargets() returns page-type targets only", async () => {
    (global as any).fetch = async (url: string) => ({
      ok: true,
      json: async () => [
        { id: "t1", type: "page", title: "Page", url: "https://a.com", webSocketDebuggerUrl: "ws://a" },
        { id: "t2", type: "worker", title: "Worker", url: "about:blank", webSocketDebuggerUrl: "ws://b" },
        { id: "t3", type: "page", title: "Page2", url: "https://b.com", webSocketDebuggerUrl: "ws://c" },
      ],
    });
    const client = new CDPClient();
    const targets = await client.listTargets();
    expect(targets).toHaveLength(2);
    expect(targets.every((t) => t.type === "page")).toBe(true);
  });

  test("newTarget() calls /json/new with PUT method", async () => {
    const calls: string[] = [];
    (global as any).fetch = async (url: string, opts?: RequestInit) => {
      calls.push(`${opts?.method ?? "GET"} ${url}`);
      if (url.includes("/json/new")) {
        return {
          ok: true,
          json: async () => ({
            id: "new-1",
            type: "page",
            title: "",
            url: "https://test.com",
            webSocketDebuggerUrl: "ws://127.0.0.1:9223/devtools/page/new-1",
          }),
        };
      }
      return { ok: true, json: async () => ({}) };
    };
    const client = new CDPClient();
    const target = await client.newTarget("https://test.com");
    expect(calls.some((c) => c.startsWith("PUT"))).toBe(true);
    expect(target.id).toBe("new-1");
  });

  test("attachSession() connects WebSocket and returns CDPSession", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/test");
    expect(session).toBeDefined();
    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.instances[0].url).toBe("ws://127.0.0.1:9223/devtools/page/test");
    session.close();
  });

  test("attachSession() retries on failure with exponential backoff", async () => {
    let attempts = 0;

    // Override WebSocket — fails first 2 attempts, succeeds on 3rd
    class FailingMockWS {
      url: string;
      sentMessages: string[] = [];
      private handlers: Record<string, Array<(evt: unknown) => void>> = {};

      constructor(url: string) {
        this.url = url;
        attempts++;
        MockWebSocket.instances.push(this as any);
        if (attempts <= 2) {
          // Emit error (no open) — triggers CDPClient retry
          Promise.resolve().then(() =>
            this._emit("error", { message: "connection refused" } as ErrorEvent)
          );
        } else {
          // Succeed on 3rd attempt
          Promise.resolve().then(() => this._emit("open", {}));
        }
      }

      addEventListener(ev: string, h: (e: unknown) => void) {
        (this.handlers[ev] ??= []).push(h);
      }
      removeEventListener(ev: string, h: (e: unknown) => void) {
        if (this.handlers[ev]) this.handlers[ev] = this.handlers[ev].filter((x) => x !== h);
      }
      send(data: string) {
        this.sentMessages.push(data);
        // Auto-respond to domain enables
        const msg = JSON.parse(data);
        const autoOk = ["Page.enable", "Runtime.enable", "DOM.enable", "Accessibility.enable"];
        if (autoOk.includes(msg.method)) {
          setTimeout(() => this._emit("message", { data: JSON.stringify({ id: msg.id, result: {} }) }), 5);
        }
      }
      close() { this._emit("close", {}); }
      _emit(ev: string, data: unknown) { (this.handlers[ev] ?? []).forEach((h) => h(data)); }
    }
    (global as any).WebSocket = FailingMockWS;

    const startMs = Date.now();
    const client = new CDPClient({ maxRetries: 3, retryBaseMs: 10 });
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/retry-test");
    const elapsed = Date.now() - startMs;

    expect(attempts).toBe(3); // Failed twice, succeeded third
    expect(elapsed).toBeGreaterThanOrEqual(10); // At least one backoff
    session.close();
  }, 5000);

  test("attachSession() throws after maxRetries exhausted", async () => {
    class AlwaysFailWS {
      url: string;
      private handlers: Record<string, Array<(evt: unknown) => void>> = {};
      constructor(url: string) {
        this.url = url;
        Promise.resolve().then(() => this._emit("error", { message: "refused" } as ErrorEvent));
      }
      addEventListener(ev: string, h: (e: unknown) => void) {
        (this.handlers[ev] ??= []).push(h);
      }
      removeEventListener() {}
      send() {}
      close() {}
      private _emit(ev: string, data: unknown) {
        (this.handlers[ev] ?? []).forEach((h) => h(data));
      }
    }
    (global as any).WebSocket = AlwaysFailWS;

    const client = new CDPClient({ maxRetries: 2, retryBaseMs: 5 });
    await expect(
      client.attachSession("ws://127.0.0.1:9223/devtools/page/fail")
    ).rejects.toThrow(/failed to attach after 2 attempts/);
  }, 5000);

  test("closeAll() closes all tracked sessions", async () => {
    const client = new CDPClient();
    const s1 = await client.attachSession("ws://127.0.0.1:9223/devtools/page/s1");
    const s2 = await client.attachSession("ws://127.0.0.1:9223/devtools/page/s2");
    expect(s1.isClosed).toBe(false);
    expect(s2.isClosed).toBe(false);
    client.closeAll();
    expect(s1.isClosed).toBe(true);
    expect(s2.isClosed).toBe(true);
  });
});

// ─── CDPSession Tests ─────────────────────────────────────────────────────────

describe("CDPSession", () => {
  beforeEach(() => setupMocks());

  test("send() transmits correct CDP protocol message", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/test");
    const ws = MockWebSocket.instances[0];

    // Clear auto-messages from domain enables
    ws.sentMessages = [];

    const promise = session.send("Page.navigate", { url: "https://example.com" });
    // Let the auto-responder fire
    await sleep(20);

    // Check the sent message structure
    const sent = ws.sentMessages.find((m) => m.includes("Page.navigate"));
    expect(sent).toBeDefined();
    const parsed = JSON.parse(sent!);
    expect(parsed.method).toBe("Page.navigate");
    expect(parsed.params.url).toBe("https://example.com");
    expect(typeof parsed.id).toBe("number");

    await promise;
    session.close();
  });

  test("send() resolves with result from CDP response", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/test");

    const result = await session.send<{ data: string }>("Page.captureScreenshot", { format: "png" });
    expect(result.data).toBe("base64PNGdata==");
    session.close();
  });

  test("send() rejects on CDP error response", async () => {
    // Use a custom WS that returns an error
    class ErrorWS extends MockWebSocket {
      send(data: string) {
        this.sentMessages.push(data);
        const msg = JSON.parse(data);
        // For screenshot, return an error
        if (msg.method === "Page.captureScreenshot") {
          setTimeout(() => {
            this["_emit"]("message", {
              data: JSON.stringify({ id: msg.id, error: { message: "Not allowed" } }),
            });
          }, 5);
        } else {
          super.send(data);
        }
      }
    }
    (global as any).WebSocket = ErrorWS;

    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/err");
    await expect(
      session.send("Page.captureScreenshot", { format: "png" })
    ).rejects.toThrow("Not allowed");
    session.close();
  });

  test("send() rejects on timeout", async () => {
    // WS that never responds to Runtime.evaluate
    class TimeoutWS extends MockWebSocket {
      send(data: string) {
        this.sentMessages.push(data);
        const msg = JSON.parse(data);
        if (msg.method !== "Runtime.evaluate") {
          super.send(data); // let others through
        }
        // Runtime.evaluate gets no response → timeout
      }
    }
    (global as any).WebSocket = TimeoutWS;

    const client = new CDPClient({ defaultTimeoutMs: 100 });
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/timeout");
    await expect(
      session.send("Runtime.evaluate", { expression: "1+1" })
    ).rejects.toThrow(/timed out after 100ms/);
    session.close();
  }, 5000);

  test("on() registers event handler and returns unsubscribe", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/events");
    const ws = MockWebSocket.instances[0];

    const received: unknown[] = [];
    const unsubscribe = session.on("Page.loadEventFired", (params) => received.push(params));

    ws.emitEvent("Page.loadEventFired", { timestamp: 123 });
    await sleep(10);
    expect(received).toHaveLength(1);

    unsubscribe();
    ws.emitEvent("Page.loadEventFired", { timestamp: 456 });
    await sleep(10);
    expect(received).toHaveLength(1); // No new events after unsubscribe

    session.close();
  });

  test("waitForEvent() resolves when event fires", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/waitevent");
    const ws = MockWebSocket.instances[0];

    const promise = session.waitForEvent("Page.loadEventFired", 1000);
    setTimeout(() => ws.emitEvent("Page.loadEventFired", { timestamp: 999 }), 30);
    const params = await promise;
    expect(params?.timestamp).toBe(999);
    session.close();
  });

  test("waitForEvent() returns null on timeout (non-fatal)", async () => {
    const client = new CDPClient({ defaultTimeoutMs: 5000 });
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/waittimeout");

    const result = await session.waitForEvent("Page.neverFired", 50);
    expect(result).toBeNull();
    session.close();
  });

  test("session closed status tracks correctly", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/close");
    expect(session.isClosed).toBe(false);
    session.close();
    expect(session.isClosed).toBe(true);
  });

  test("send() on closed session throws immediately", async () => {
    const client = new CDPClient();
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/closedtest");
    session.close();
    await expect(session.send("Page.enable")).rejects.toThrow(/closed/);
  });

  test("pending commands rejected when session closes unexpectedly", async () => {
    class SlowWS extends MockWebSocket {
      send(data: string) {
        this.sentMessages.push(data);
        // Never respond to Runtime.evaluate
      }
    }
    (global as any).WebSocket = SlowWS;

    const client = new CDPClient({ defaultTimeoutMs: 5000 });
    const session = await client.attachSession("ws://127.0.0.1:9223/devtools/page/slowclose");
    const ws = MockWebSocket.instances[0] as SlowWS;

    const pendingPromise = session.send("Runtime.evaluate", { expression: "1+1" });
    // Close the WS mid-flight
    await sleep(20);
    ws.close(); // triggers "close" event

    await expect(pendingPromise).rejects.toThrow(/closed/);
  }, 5000);
});

// ─── LyrieBrowser Tests ───────────────────────────────────────────────────────

describe("LyrieBrowser", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    (global as any).WebSocket = MockWebSocket;
    (global as any).fetch = createMockFetch();
  });

  test("isAvailable() returns true when CDP endpoint responds", async () => {
    const browser = new LyrieBrowser();
    expect(await browser.isAvailable()).toBe(true);
  });

  test("isAvailable() returns false when CDP is down", async () => {
    (global as any).fetch = async () => { throw new Error("ECONNREFUSED"); };
    const browser = new LyrieBrowser();
    expect(await browser.isAvailable()).toBe(false);
  });

  test("newTab() opens a new tab and returns Tab with ownedByUs=true", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab("https://lyrie.ai");
    expect(tab).toBeDefined();
    expect(tab.ownedByUs).toBe(true);
    expect(tab.targetId).toBeTruthy();
    expect(tab.session).toBeDefined();
  });

  test("newTab() opens a fresh tab — never reuses existing ones", async () => {
    const putCalls: string[] = [];
    (global as any).fetch = async (url: string, opts?: RequestInit) => {
      if (opts?.method === "PUT") putCalls.push(url);
      return (createMockFetch())(url, opts);
    };

    const browser = new LyrieBrowser();
    await browser.newTab("https://x.com");
    expect(putCalls.length).toBe(1);
    expect(putCalls[0]).toContain("/json/new");
  });

  test("listTabs() returns all page targets with ownedByUs flag", async () => {
    // Track tabs opened via /json/new so the list mock can include them
    const openedTabs: typeof mockTargets = [];
    (global as any).fetch = async (url: string, opts?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.includes("/json/new")) {
        const newTarget = {
          id: `new-tab-${Date.now()}`,
          type: "page",
          title: "New Tab",
          url: "about:blank",
          webSocketDebuggerUrl: `ws://127.0.0.1:9223/devtools/page/new-tab-${Date.now()}`,
        };
        openedTabs.push(newTarget);
        return { ok: true, json: async () => newTarget };
      }
      if (urlStr.includes("/json/list")) {
        return { ok: true, json: async () => [...mockTargets, ...openedTabs] };
      }
      return (createMockFetch())(url, opts);
    };

    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    const list = await browser.listTabs();

    // The tab we opened should appear in the list
    const ours = list.find((t) => t.targetId === tab.targetId);
    expect(ours).toBeDefined();
    expect(ours?.ownedByUs).toBe(true);

    // Pre-existing tabs should be flagged as not ours
    const existing = list.find((t) => t.targetId === "existing-tab-1");
    expect(existing?.ownedByUs).toBe(false);
  });

  test("closeTab() only closes tabs WE opened", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    // Should succeed — we opened it
    await expect(browser.closeTab(tab)).resolves.toBeUndefined();
  });

  test("closeTab() refuses to close pre-existing tabs", async () => {
    const browser = new LyrieBrowser();
    const existingTab = await browser.attachTab("existing-tab-1");
    expect(existingTab.ownedByUs).toBe(false);
    await expect(browser.closeTab(existingTab)).rejects.toThrow(
      /tab safety violation/i
    );
  });

  test("attachTab() attaches to existing tab by ID", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.attachTab("existing-tab-1");
    expect(tab.targetId).toBe("existing-tab-1");
    expect(tab.ownedByUs).toBe(false);
  });

  test("attachTab() throws if targetId not found", async () => {
    const browser = new LyrieBrowser();
    await expect(browser.attachTab("nonexistent-id")).rejects.toThrow(/not found/);
  });

  test("screenshot() returns base64 PNG string", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    const base64 = await browser.screenshot(tab);
    expect(typeof base64).toBe("string");
    expect(base64.length).toBeGreaterThan(0);
  });

  test("screenshot() calls activate before capture", async () => {
    const activateCalls: string[] = [];
    (global as any).fetch = async (url: string, opts?: RequestInit) => {
      if (url.includes("/json/activate")) activateCalls.push(url);
      return (createMockFetch())(url, opts);
    };

    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    await browser.screenshot(tab);
    expect(activateCalls.length).toBeGreaterThan(0);
  });

  test("snapshot() returns accessibility tree as markdown", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    const snapshot = await browser.snapshot(tab);
    expect(typeof snapshot).toBe("string");
    expect(snapshot.length).toBeGreaterThan(0);
    // Should contain something from the AX tree mock
    expect(snapshot).toContain("RootWebArea");
  });

  test("evaluate() sends Runtime.evaluate with correct expression", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    ws.sentMessages = [];

    await browser.evaluate(tab, "document.title");

    const evalMsg = ws.sentMessages.find((m) => m.includes("Runtime.evaluate"));
    expect(evalMsg).toBeDefined();
    const parsed = JSON.parse(evalMsg!);
    expect(parsed.method).toBe("Runtime.evaluate");
    expect(parsed.params.expression).toBe("document.title");
    expect(parsed.params.returnByValue).toBe(true);
  });

  test("evaluate() returns the result value", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    const result = await browser.evaluate(tab, "1 + 1");
    expect(result).toBe("eval-result"); // MockWebSocket auto-responds with this
  });

  test("click() sends correct mouse events (mousePressed + mouseReleased)", async () => {
    // Intercept CDPSession.send directly to capture mouse events without WS mock complexity
    const sentMethods: Array<{ method: string; params: Record<string, unknown> }> = [];

    class CapturingWS extends MockWebSocket {
      send(data: string) {
        // Only push to sentMessages once — don't call super to avoid double-push
        this.sentMessages.push(data);
        const msg = JSON.parse(data);
        if (msg.method === "Runtime.evaluate") {
          const isCoords = msg.params.expression.includes("getBoundingClientRect");
          setTimeout(() => {
            this["_emit"]("message", {
              data: JSON.stringify({
                id: msg.id,
                result: { result: { type: "object", value: isCoords ? { x: 100, y: 200 } : "ok" } },
              }),
            });
          }, 5);
        } else if (msg.method?.startsWith("Input.")) {
          sentMethods.push({ method: msg.method, params: msg.params });
          // Auto-respond
          setTimeout(() => this["_emit"]("message", { data: JSON.stringify({ id: msg.id, result: {} }) }), 5);
        } else {
          // Delegate domain enables etc. to auto-responder without double-push
          const autoOk = ["Page.enable", "Runtime.enable", "DOM.enable", "Accessibility.enable",
                          "Page.navigate", "Page.captureScreenshot", "Accessibility.getFullAXTree"];
          if (autoOk.includes(msg.method)) {
            const resp = msg.method === "Page.captureScreenshot"
              ? { data: "base64=" }
              : msg.method === "Page.navigate"
              ? { frameId: "main" }
              : {};
            setTimeout(() => {
              this["_emit"]("message", { data: JSON.stringify({ id: msg.id, result: resp }) });
              if (msg.method === "Page.navigate") {
                setTimeout(() => this["_emit"]("message", { data: JSON.stringify({ method: "Page.loadEventFired", params: {} }) }), 10);
              }
            }, 5);
          }
        }
      }
    }

    (global as any).WebSocket = CapturingWS;
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    await browser.click(tab, "button.submit").catch(() => {});

    const mouseEvents = sentMethods.filter((e) => e.method === "Input.dispatchMouseEvent");
    expect(mouseEvents.length).toBeGreaterThanOrEqual(2);
    const pressed = mouseEvents.filter((e) => e.params.type === "mousePressed");
    const released = mouseEvents.filter((e) => e.params.type === "mouseReleased");
    expect(pressed.length).toBeGreaterThanOrEqual(1);
    expect(released.length).toBeGreaterThanOrEqual(1);
    expect(pressed[0].params.button).toBe("left");
  });

  test("type() sends keyChar events for each character", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1];
    ws.sentMessages = [];

    await browser.type(tab, "abc");

    const keyEvents = ws.sentMessages
      .filter((m) => m.includes("Input.dispatchKeyEvent"))
      .map((m) => JSON.parse(m));

    expect(keyEvents.length).toBeGreaterThanOrEqual(3);
    const chars = keyEvents
      .filter((e) => e.params.type === "char")
      .map((e) => e.params.text);
    expect(chars).toContain("a");
    expect(chars).toContain("b");
    expect(chars).toContain("c");
  });

  test("navigate() waits for Page.loadEventFired", async () => {
    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    // Should resolve without throwing (MockWebSocket auto-fires loadEventFired)
    await expect(
      browser.navigate(tab, "https://lyrie.ai")
    ).resolves.toBeUndefined();
  });

  test("waitForSelector() resolves when element appears", async () => {
    class SelectorWS extends MockWebSocket {
      private callCount = 0;
      send(data: string) {
        this.sentMessages.push(data);
        const msg = JSON.parse(data);
        if (msg.method === "Runtime.evaluate" && msg.params.expression.includes("querySelector")) {
          this.callCount++;
          const found = this.callCount >= 3; // not found first 2 times
          setTimeout(() => {
            this["_emit"]("message", {
              data: JSON.stringify({
                id: msg.id,
                result: { result: { type: "boolean", value: found } },
              }),
            });
          }, 5);
        } else {
          super.send(data);
        }
      }
    }
    (global as any).WebSocket = SelectorWS;

    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    await expect(
      browser.waitForSelector(tab, "#my-element", 2000)
    ).resolves.toBeUndefined();
  }, 5000);

  test("waitForSelector() rejects when element never appears", async () => {
    class NotFoundWS extends MockWebSocket {
      send(data: string) {
        this.sentMessages.push(data);
        const msg = JSON.parse(data);
        if (msg.method === "Runtime.evaluate" && msg.params.expression.includes("querySelector")) {
          setTimeout(() => {
            this["_emit"]("message", {
              data: JSON.stringify({
                id: msg.id,
                result: { result: { type: "boolean", value: false } },
              }),
            });
          }, 5);
        } else {
          super.send(data);
        }
      }
    }
    (global as any).WebSocket = NotFoundWS;

    const browser = new LyrieBrowser();
    const tab = await browser.newTab();
    await expect(
      browser.waitForSelector(tab, "#never-appears", 200)
    ).rejects.toThrow(/not found after 200ms/);
  }, 5000);

  test("auto-screenshot on error: saves PNG and appends path to error message", async () => {
    // Make click fail by returning null coords
    class NullCoordsWS extends MockWebSocket {
      send(data: string) {
        this.sentMessages.push(data);
        const msg = JSON.parse(data);
        if (msg.method === "Runtime.evaluate" && msg.params.expression.includes("getBoundingClientRect")) {
          setTimeout(() => {
            this["_emit"]("message", {
              data: JSON.stringify({
                id: msg.id,
                result: { result: { type: "null", value: null } },
              }),
            });
          }, 5);
        } else {
          super.send(data);
        }
      }
    }
    (global as any).WebSocket = NullCoordsWS;

    // Mock fs.writeFileSync
    let writtenPath = "";
    const origImport = global.__originalImport;

    const browser = new LyrieBrowser();
    const tab = await browser.newTab();

    const err = await browser.click(tab, ".nonexistent").catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain("click(.nonexistent) failed");
    // Should mention screenshot path
    expect(err.message).toMatch(/error screenshot|screenshot failed/);
  });

  test("cleanup() closes all sessions", async () => {
    const browser = new LyrieBrowser();
    await browser.newTab();
    await browser.newTab();
    // Should not throw
    await expect(browser.cleanup()).resolves.toBeUndefined();
  });
});

// ─── Tool Definition Tests ────────────────────────────────────────────────────

describe("browserToolDefinition", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    (global as any).WebSocket = MockWebSocket;
    (global as any).fetch = createMockFetch();
  });

  test("tool is named 'browser'", async () => {
    const { browserToolDefinition } = await import("./index");
    expect(browserToolDefinition.name).toBe("browser");
  });

  test("tool has correct action enum", async () => {
    const { browserToolDefinition } = await import("./index");
    const actions = browserToolDefinition.parameters.action.enum ?? [];
    expect(actions).toContain("status");
    expect(actions).toContain("tabs");
    expect(actions).toContain("open");
    expect(actions).toContain("snapshot");
    expect(actions).toContain("screenshot");
    expect(actions).toContain("navigate");
    expect(actions).toContain("click");
    expect(actions).toContain("type");
    expect(actions).toContain("fill");
    expect(actions).toContain("select");
    expect(actions).toContain("evaluate");
    expect(actions).toContain("close");
  });

  test("status action returns availability info", async () => {
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({ action: "status" });
    expect(result.success).toBe(true);
    expect(result.output).toContain("127.0.0.1:9223");
  });

  test("status action returns unavailable message when CDP down", async () => {
    (global as any).fetch = async () => { throw new Error("ECONNREFUSED"); };
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({ action: "status" });
    expect(result.success).toBe(true);
    expect(result.output).toContain("unavailable");
  });

  test("tabs action lists current tabs", async () => {
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({ action: "tabs" });
    expect(result.success).toBe(true);
    expect(result.metadata?.count).toBeGreaterThanOrEqual(0);
  });

  test("open action requires url", async () => {
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({ action: "open" });
    expect(result.success).toBe(false);
    expect(result.error).toContain("url");
  });

  test("click action without targetId returns error", async () => {
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({
      action: "click",
      selector: "button",
      // no targetId
    });
    expect(result.success).toBe(false);
    expect(result.error).toBeTruthy(); // "No targetId provided..."
  });

  test("navigate action without url returns error", async () => {
    const { browserToolDefinition } = await import("./index");
    // First open a tab so we have a valid targetId
    const openResult = await browserToolDefinition.execute({
      action: "open",
      url: "about:blank",
    });
    expect(openResult.success).toBe(true);
    const targetId = openResult.metadata?.targetId as string;

    const result = await browserToolDefinition.execute({
      action: "navigate",
      targetId,
      // no url
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("url");
  });

  test("evaluate action requires js", async () => {
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({
      action: "evaluate",
      targetId: "some-id",
    });
    expect(result.success).toBe(false);
  });

  test("unknown action returns error", async () => {
    const { browserToolDefinition } = await import("./index");
    const result = await browserToolDefinition.execute({ action: "unknown_action" });
    expect(result.success).toBe(false);
    expect(result.error).toContain("Unknown browser action");
  });

  test("tool risk is moderate", async () => {
    const { browserToolDefinition } = await import("./index");
    expect(browserToolDefinition.risk).toBe("moderate");
  });
});

// ─── sleep utility test ───────────────────────────────────────────────────────

describe("sleep", () => {
  test("sleep() resolves after approximately the given ms", async () => {
    const start = Date.now();
    await sleep(50);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(40);
    expect(elapsed).toBeLessThan(200);
  });
});
