/**
 * browser/index.ts — LyrieBrowser tool exports + ToolExecutor registration helper
 *
 * Usage in ToolExecutor:
 *   import { browserToolDefinition } from "./browser";
 *   this.register(browserToolDefinition);
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export { LyrieBrowser } from "./browser-tool";
export type { Tab, LyrieBrowserOptions, WaitCondition } from "./browser-tool";
export { CDPClient, CDPSession, sleep } from "./cdp-client";
export type { CDPClientOptions, CDPTarget } from "./cdp-client";

import type { Tool, ToolResult } from "../tool-executor";
import { LyrieBrowser } from "./browser-tool";

// ─── Singleton browser instance ───────────────────────────────────────────────

let _browser: LyrieBrowser | null = null;

function getBrowser(): LyrieBrowser {
  if (!_browser) {
    _browser = new LyrieBrowser();
  }
  return _browser;
}

// ─── Tool definition ──────────────────────────────────────────────────────────

/**
 * The `browser` built-in tool definition for ToolExecutor.
 * Register with: this.register(browserToolDefinition)
 */
export const browserToolDefinition: Tool = {
  name: "browser",
  description:
    "Control a web browser. Navigate, click, type, take screenshots and snapshots. " +
    "Connects to the lyrie-automation Chrome profile at 127.0.0.1:9223 which has all " +
    "social logins (Twitter/X, LinkedIn, HackerNews, etc). " +
    "IMPORTANT: Never closes tabs that existed before this session — only tabs opened via 'open' action.",
  parameters: {
    action: {
      type: "string",
      description:
        "Action to perform: status | tabs | open | snapshot | screenshot | navigate | click | type | fill | select | evaluate | close",
      required: true,
      enum: [
        "status",
        "tabs",
        "open",
        "snapshot",
        "screenshot",
        "navigate",
        "click",
        "type",
        "fill",
        "select",
        "evaluate",
        "close",
      ],
    },
    url: {
      type: "string",
      description: "URL to open or navigate to (required for open/navigate actions)",
    },
    targetId: {
      type: "string",
      description: "Tab target ID (returned from open/tabs actions)",
    },
    selector: {
      type: "string",
      description: "CSS selector, visible text, or aria-label for click/fill/select actions",
    },
    text: {
      type: "string",
      description: "Text to type (for 'type' action) or value to fill/select",
    },
    js: {
      type: "string",
      description: "JavaScript expression to evaluate (for 'evaluate' action)",
    },
    timeoutMs: {
      type: "number",
      description: "Per-operation timeout in ms (default: 10000)",
      default: 10000,
    },
  },
  risk: "moderate",
  execute: async (args): Promise<ToolResult> => {
    const browser = getBrowser();
    const action = args.action as string;

    // Track opened tabs in this session (targetId → Tab)
    // We use a module-level map so tabs persist across calls
    const tab = args.targetId ? _openedTabs.get(args.targetId) : undefined;

    try {
      switch (action) {
        // ── status ──────────────────────────────────────────────────────────
        case "status": {
          const available = await browser.isAvailable();
          return {
            success: true,
            output: available
              ? "Browser available: 127.0.0.1:9223 (lyrie-automation profile)"
              : "Browser unavailable: CDP endpoint not responding at 127.0.0.1:9223",
            metadata: { available, cdpUrl: "http://127.0.0.1:9223" },
          };
        }

        // ── tabs ────────────────────────────────────────────────────────────
        case "tabs": {
          const tabs = await browser.listTabs();
          const lines = tabs.map(
            (t, i) =>
              `${i + 1}. [${t.ownedByUs ? "ours" : "existing"}] ${t.targetId}\n   ${t.title}\n   ${t.url}`
          );
          return {
            success: true,
            output: lines.join("\n\n") || "No tabs open",
            metadata: { count: tabs.length, tabs },
          };
        }

        // ── open ────────────────────────────────────────────────────────────
        case "open": {
          if (!args.url) return errorResult("open requires url");
          const newTab = await browser.newTab(args.url);
          _openedTabs.set(newTab.targetId, newTab);
          return {
            success: true,
            output: `Opened new tab: ${args.url}\ntargetId: ${newTab.targetId}`,
            metadata: { targetId: newTab.targetId, url: args.url },
          };
        }

        // ── snapshot ────────────────────────────────────────────────────────
        case "snapshot": {
          if (!tab) return tabNotFoundError(args.targetId);
          const tree = await browser.snapshot(tab);
          return { success: true, output: tree };
        }

        // ── screenshot ──────────────────────────────────────────────────────
        case "screenshot": {
          if (!tab) return tabNotFoundError(args.targetId);
          const base64 = await browser.screenshot(tab);
          return {
            success: true,
            output: `Screenshot captured (base64 PNG, ${base64.length} chars)`,
            metadata: { base64, format: "png" },
          };
        }

        // ── navigate ────────────────────────────────────────────────────────
        case "navigate": {
          if (!tab) return tabNotFoundError(args.targetId);
          if (!args.url) return errorResult("navigate requires url");
          await browser.navigate(tab, args.url);
          return { success: true, output: `Navigated to: ${args.url}` };
        }

        // ── click ────────────────────────────────────────────────────────────
        case "click": {
          if (!tab) return tabNotFoundError(args.targetId);
          if (!args.selector) return errorResult("click requires selector");
          await browser.click(tab, args.selector);
          return { success: true, output: `Clicked: ${args.selector}` };
        }

        // ── type ─────────────────────────────────────────────────────────────
        case "type": {
          if (!tab) return tabNotFoundError(args.targetId);
          if (!args.text) return errorResult("type requires text");
          await browser.type(tab, args.text, args.selector);
          return {
            success: true,
            output: `Typed "${args.text.slice(0, 30)}${args.text.length > 30 ? "…" : ""}"`,
          };
        }

        // ── fill ─────────────────────────────────────────────────────────────
        case "fill": {
          if (!tab) return tabNotFoundError(args.targetId);
          if (!args.selector) return errorResult("fill requires selector");
          if (args.text === undefined) return errorResult("fill requires text");
          await browser.fill(tab, args.selector, args.text);
          return { success: true, output: `Filled ${args.selector}` };
        }

        // ── select ───────────────────────────────────────────────────────────
        case "select": {
          if (!tab) return tabNotFoundError(args.targetId);
          if (!args.selector) return errorResult("select requires selector");
          if (!args.text) return errorResult("select requires text (the value)");
          await browser.select(tab, args.selector, args.text);
          return { success: true, output: `Selected "${args.text}" in ${args.selector}` };
        }

        // ── evaluate ─────────────────────────────────────────────────────────
        case "evaluate": {
          if (!tab) return tabNotFoundError(args.targetId);
          if (!args.js) return errorResult("evaluate requires js");
          const result = await browser.evaluate(tab, args.js);
          return {
            success: true,
            output: typeof result === "string" ? result : JSON.stringify(result, null, 2),
            metadata: { result },
          };
        }

        // ── close ────────────────────────────────────────────────────────────
        case "close": {
          if (!tab) return tabNotFoundError(args.targetId);
          await browser.closeTab(tab);
          _openedTabs.delete(args.targetId!);
          return { success: true, output: `Closed tab: ${args.targetId}` };
        }

        default:
          return errorResult(`Unknown browser action: ${action}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, output: "", error: msg };
    }
  },
};

// ─── Module-level tab registry ────────────────────────────────────────────────

// Tabs persist across tool calls within the same process lifetime
import type { Tab } from "./browser-tool";

const _openedTabs = new Map<string, Tab>();

// ─── Helpers ──────────────────────────────────────────────────────────────────

function errorResult(msg: string): ToolResult {
  return { success: false, output: "", error: msg };
}

function tabNotFoundError(targetId?: string): ToolResult {
  const msg = targetId
    ? `Tab ${targetId} not found. Open a tab first with action="open", or check action="tabs" for available targetIds.`
    : `No targetId provided. Use action="tabs" to list open tabs, or action="open" to open a new one.`;
  return { success: false, output: "", error: msg };
}
