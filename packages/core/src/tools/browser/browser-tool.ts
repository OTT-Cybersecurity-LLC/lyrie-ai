/**
 * browser-tool.ts — LyrieBrowser: the main browser automation class
 *
 * LyrieBrowser capabilities:
 *   1. No hardcoded timeouts — fully configurable CDP attach
 *   2. Auto-retry on attach failure (3x exponential backoff)
 *   3. Auto-screenshot on error (attach path/screenshot saved for debugging)
 *   4. Smart element detection (CSS → text content → aria-label fallback)
 *   5. Tab safety — NEVER closes tabs we didn't open
 *
 * Connects to 127.0.0.1:9223 (lyrie-automation Chrome Dev profile).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { CDPClient, CDPSession, CDPTarget, sleep } from "./cdp-client";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Tab {
  /** Chrome DevTools target ID */
  targetId: string;
  /** Active CDPSession for this tab */
  session: CDPSession;
  /** Whether this tab was opened by us (safe to close) */
  ownedByUs: boolean;
}

export interface LyrieBrowserOptions {
  /** CDP host. Default: http://127.0.0.1:9223 */
  cdpUrl?: string;
  /** Default per-operation timeout (ms). Default: 10000 */
  defaultTimeoutMs?: number;
  /** Retry attempts for CDP connection. Default: 3 */
  maxRetries?: number;
}

export type WaitCondition = "load" | "networkidle";

// ─── LyrieBrowser ─────────────────────────────────────────────────────────────

export class LyrieBrowser {
  private client: CDPClient;
  private openedTabIds = new Set<string>();
  private defaultTimeoutMs: number;

  constructor(options: LyrieBrowserOptions = {}) {
    const cdpUrl = options.cdpUrl ?? "http://127.0.0.1:9223";
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 10_000;
    this.client = new CDPClient({
      host: cdpUrl,
      defaultTimeoutMs: this.defaultTimeoutMs,
      maxRetries: options.maxRetries ?? 3,
      retryBaseMs: 500,
    });
  }

  // ─── Tab Management ────────────────────────────────────────────────────────

  /**
   * Open a new tab. NEVER touches existing tabs.
   * Tab safety rule: all tabs opened here are tracked.
   */
  async newTab(url?: string): Promise<Tab> {
    const target = await this.client.newTarget(url ?? "about:blank");
    this.openedTabIds.add(target.id);

    const session = await this.client.attachSession(target.webSocketDebuggerUrl);
    await this._enableDomains(session);

    if (url && url !== "about:blank") {
      await this._navigate(session, target.id, url, "load");
    }

    return { targetId: target.id, session, ownedByUs: true };
  }

  /** List all page tabs currently open in the browser */
  async listTabs(): Promise<Array<{ targetId: string; title: string; url: string; ownedByUs: boolean }>> {
    const targets = await this.client.listTargets();
    return targets.map((t) => ({
      targetId: t.id,
      title: t.title,
      url: t.url,
      ownedByUs: this.openedTabIds.has(t.id),
    }));
  }

  /**
   * Attach to an EXISTING tab by targetId (does not open or close anything).
   * This is how you re-attach to a tab opened in a previous session.
   */
  async attachTab(tabId: string): Promise<Tab> {
    const targets = await this.client.listTargets();
    const target = targets.find((t) => t.id === tabId);
    if (!target) throw new Error(`Tab ${tabId} not found`);

    const session = await this.client.attachSession(target.webSocketDebuggerUrl);
    await this._enableDomains(session);

    return { targetId: tabId, session, ownedByUs: this.openedTabIds.has(tabId) };
  }

  /**
   * Close a tab. Only closes tabs WE opened — refuses to touch pre-existing tabs.
   * Tab safety rule: this is non-negotiable per AGENTS.md.
   */
  async closeTab(tab: Tab): Promise<void> {
    if (!tab.ownedByUs) {
      throw new Error(
        `Tab safety violation: refusing to close tab ${tab.targetId} — it was not opened by LyrieBrowser`
      );
    }
    tab.session.close();
    await this.client.closeTarget(tab.targetId);
    this.openedTabIds.delete(tab.targetId);
  }

  // ─── Navigation ────────────────────────────────────────────────────────────

  /** Navigate tab to a URL */
  async navigate(
    tab: Tab,
    url: string,
    waitFor: WaitCondition = "load"
  ): Promise<void> {
    await this._navigate(tab.session, tab.targetId, url, waitFor);
  }

  // ─── Snapshots ─────────────────────────────────────────────────────────────

  /**
   * Returns the page's accessibility tree as markdown-like text.
   * Returns the accessibility tree as structured markdown text.
   */
  async snapshot(tab: Tab): Promise<string> {
    try {
      const result = await tab.session.send<{ root: unknown }>(
        "Accessibility.getFullAXTree",
        {},
        { timeoutMs: this.defaultTimeoutMs }
      );
      return this._axTreeToMarkdown(result.root as AXNode);
    } catch {
      // Fallback: use DOM innerText
      const text = await this.evaluate<string>(tab, "document.body?.innerText ?? ''");
      return text ?? "(empty page)";
    }
  }

  /**
   * Take a screenshot. Returns base64 PNG string.
   * If the tab is not visible (background), activates it first.
   */
  async screenshot(tab: Tab): Promise<string> {
    // Activate ensures Chrome renders background tabs
    await this.client.activateTarget(tab.targetId);
    await sleep(300);

    const result = await tab.session.send<{ data: string }>(
      "Page.captureScreenshot",
      { format: "png", quality: 90 },
      { timeoutMs: this.defaultTimeoutMs }
    );
    return result.data;
  }

  // ─── Actions ──────────────────────────────────────────────────────────────

  /**
   * Click an element. Smart element detection:
   *   1. CSS selector
   *   2. Text content match
   *   3. aria-label match
   */
  async click(tab: Tab, selector: string): Promise<void> {
    await this._withErrorScreenshot(tab, `click(${selector})`, async () => {
      const coords = await this._resolveElement(tab, selector);
      if (!coords) throw new Error(`Element not found: ${selector}`);

      await tab.session.send("Input.dispatchMouseEvent", {
        type: "mousePressed",
        x: coords.x,
        y: coords.y,
        button: "left",
        clickCount: 1,
      });
      await sleep(50);
      await tab.session.send("Input.dispatchMouseEvent", {
        type: "mouseReleased",
        x: coords.x,
        y: coords.y,
        button: "left",
        clickCount: 1,
      });
    });
  }

  /** Type text into the focused element, or into a specific selector */
  async type(tab: Tab, text: string, selector?: string): Promise<void> {
    await this._withErrorScreenshot(tab, `type("${text.slice(0, 20)}...")`, async () => {
      if (selector) {
        await this.click(tab, selector);
        await sleep(150);
      }
      for (const char of text) {
        await tab.session.send("Input.dispatchKeyEvent", { type: "char", text: char });
        await sleep(20);
      }
    });
  }

  /** Fill an input field (faster than type — sets value directly) */
  async fill(tab: Tab, selector: string, value: string): Promise<void> {
    await this._withErrorScreenshot(tab, `fill(${selector})`, async () => {
      await this.click(tab, selector);
      await sleep(100);
      // Select all + replace
      await tab.session.send("Input.dispatchKeyEvent", {
        type: "keyDown",
        modifiers: 2, // Ctrl/Cmd
        key: "a",
        windowsVirtualKeyCode: 65,
      });
      await tab.session.send("Input.dispatchKeyEvent", {
        type: "keyUp",
        modifiers: 2,
        key: "a",
        windowsVirtualKeyCode: 65,
      });
      for (const char of value) {
        await tab.session.send("Input.dispatchKeyEvent", { type: "char", text: char });
        await sleep(10);
      }
    });
  }

  /** Select a value from a <select> element */
  async select(tab: Tab, selector: string, value: string): Promise<void> {
    await this._withErrorScreenshot(tab, `select(${selector})`, async () => {
      await this.evaluate(tab, `
        (() => {
          const el = document.querySelector(${JSON.stringify(selector)});
          if (!el) throw new Error('select element not found: ${selector.replace(/'/g, "\\'")}');
          el.value = ${JSON.stringify(value)};
          el.dispatchEvent(new Event('change', { bubbles: true }));
        })()
      `);
    });
  }

  /** Evaluate JavaScript in the tab's context */
  async evaluate<T = unknown>(tab: Tab, js: string): Promise<T> {
    const result = await tab.session.send<{
      result: { value?: unknown; type: string };
      exceptionDetails?: { text: string };
    }>(
      "Runtime.evaluate",
      { expression: js, returnByValue: true, awaitPromise: true },
      { timeoutMs: this.defaultTimeoutMs }
    );

    if (result.exceptionDetails) {
      throw new Error(`JS exception: ${result.exceptionDetails.text}`);
    }
    return result.result?.value as T;
  }

  /** Wait until a CSS selector appears in the DOM */
  async waitForSelector(tab: Tab, selector: string, timeoutMs?: number): Promise<void> {
    const deadline = Date.now() + (timeoutMs ?? this.defaultTimeoutMs);
    const interval = 200;

    while (Date.now() < deadline) {
      const found = await this.evaluate<boolean>(
        tab,
        `!!document.querySelector(${JSON.stringify(selector)})`
      );
      if (found) return;
      await sleep(interval);
    }

    throw new Error(
      `waitForSelector: "${selector}" not found after ${timeoutMs ?? this.defaultTimeoutMs}ms`
    );
  }

  /** Wait for a navigation to complete */
  async waitForNavigation(tab: Tab, timeoutMs?: number): Promise<void> {
    await tab.session.waitForEvent(
      "Page.loadEventFired",
      timeoutMs ?? this.defaultTimeoutMs
    );
    await sleep(500); // SPA settle time
  }

  /** Scroll an element into view */
  async scrollIntoView(tab: Tab, selector: string): Promise<void> {
    await this.evaluate(
      tab,
      `(() => { const el = document.querySelector(${JSON.stringify(selector)}); el?.scrollIntoView({ block: 'center', behavior: 'instant' }); })()`
    );
  }

  // ─── Status ───────────────────────────────────────────────────────────────

  /** Returns true if the CDP endpoint at 127.0.0.1:9223 is reachable */
  async isAvailable(): Promise<boolean> {
    return this.client.isAvailable();
  }

  /** Clean up all sessions opened by this instance */
  async cleanup(): Promise<void> {
    this.client.closeAll();
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private async _enableDomains(session: CDPSession): Promise<void> {
    await Promise.all([
      session.send("Page.enable"),
      session.send("Runtime.enable"),
      session.send("DOM.enable"),
      session.send("Accessibility.enable"),
    ]);
  }

  private async _navigate(
    session: CDPSession,
    targetId: string,
    url: string,
    waitFor: WaitCondition
  ): Promise<void> {
    // Start listening BEFORE sending navigate to avoid race condition
    const loadPromise = session.waitForEvent(
      "Page.loadEventFired",
      this.defaultTimeoutMs * 3 // navigation can take longer
    );

    await session.send(
      "Page.navigate",
      { url },
      { timeoutMs: this.defaultTimeoutMs }
    );

    await loadPromise;

    if (waitFor === "networkidle") {
      // Wait for network quiet: no requests for 500ms
      await this._waitNetworkIdle(session, 500, this.defaultTimeoutMs * 2);
    }

    await sleep(600); // SPA settle
  }

  private async _waitNetworkIdle(
    session: CDPSession,
    idleMs: number,
    timeoutMs: number
  ): Promise<void> {
    let inFlight = 0;
    let lastActivity = Date.now();

    const unsubRequest = session.on("Network.requestWillBeSent", () => {
      inFlight++;
      lastActivity = Date.now();
    });
    const unsubResponse = session.on("Network.loadingFinished", () => {
      inFlight = Math.max(0, inFlight - 1);
      lastActivity = Date.now();
    });
    const unsubFailed = session.on("Network.loadingFailed", () => {
      inFlight = Math.max(0, inFlight - 1);
      lastActivity = Date.now();
    });

    await session.send("Network.enable");

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await sleep(100);
      if (inFlight === 0 && Date.now() - lastActivity >= idleMs) break;
    }

    unsubRequest();
    unsubResponse();
    unsubFailed();
  }

  /**
   * Smart element resolution:
   * 1. CSS selector
   * 2. Visible text match (links, buttons)
   * 3. aria-label match
   */
  private async _resolveElement(
    tab: Tab,
    selector: string
  ): Promise<{ x: number; y: number } | null> {
    return this.evaluate<{ x: number; y: number } | null>(
      tab,
      `(() => {
        function coords(el) {
          if (!el) return null;
          el.scrollIntoView({ block: 'center', behavior: 'instant' });
          const r = el.getBoundingClientRect();
          if (r.width === 0 && r.height === 0) return null;
          return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) };
        }
        // 1. CSS selector
        let el = document.querySelector(${JSON.stringify(selector)});
        if (el) return coords(el);
        // 2. Text content match (for buttons, links, labels)
        const text = ${JSON.stringify(selector)};
        el = Array.from(document.querySelectorAll('a,button,label,[role="button"],[role="link"]'))
          .find(e => e.textContent?.trim() === text || e.innerText?.trim() === text) || null;
        if (el) return coords(el);
        // 3. aria-label match
        el = document.querySelector('[aria-label=${JSON.stringify(selector).slice(1, -1)}]');
        if (el) return coords(el);
        return null;
      })()`
    );
  }

  /**
   * Wrap an action with auto-screenshot on failure.
   * If the action throws, we capture a screenshot to /tmp/lyrie-error-*.png
   * and re-throw with the path appended to the error message.
   */
  private async _withErrorScreenshot(
    tab: Tab,
    actionName: string,
    fn: () => Promise<void>
  ): Promise<void> {
    try {
      await fn();
    } catch (err) {
      let screenshotInfo = "";
      try {
        const base64 = await this.screenshot(tab);
        const path = `/tmp/lyrie-error-${Date.now()}.png`;
        const { writeFileSync } = await import("fs");
        writeFileSync(path, Buffer.from(base64, "base64"));
        screenshotInfo = ` [error screenshot: ${path}]`;
      } catch {
        screenshotInfo = " [screenshot failed]";
      }
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`${actionName} failed: ${msg}${screenshotInfo}`);
    }
  }

  /** Convert AX tree to simplified markdown */
  private _axTreeToMarkdown(node: AXNode, depth = 0): string {
    if (!node) return "";
    const indent = "  ".repeat(depth);
    const role = node.role?.value ?? "";
    const name = node.name?.value ?? "";

    let line = "";
    if (role && name) {
      line = `${indent}[${role}] ${name}`;
    } else if (name) {
      line = `${indent}${name}`;
    } else if (role) {
      line = `${indent}[${role}]`;
    }

    const children = (node.children ?? [])
      .map((c) => this._axTreeToMarkdown(c, depth + 1))
      .filter(Boolean)
      .join("\n");

    return [line, children].filter(Boolean).join("\n");
  }
}

// ─── Internal AX tree types ───────────────────────────────────────────────────

interface AXNode {
  role?: { value: string };
  name?: { value: string };
  children?: AXNode[];
}
