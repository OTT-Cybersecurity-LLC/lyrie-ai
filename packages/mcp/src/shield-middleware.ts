/**
 * createShieldGuard — standalone, importable Shield middleware for MCP tool
 * calls/results.
 *
 * `McpRegistry` (registry.ts) already gates every tool result through Shield
 * filtering internally (`shieldFilter`, a private method) — but that path is
 * only reachable by adopting the full registry/daemon stack (mcp.json,
 * McpClient, connection lifecycle, ATP trust gate, etc). Any Node/Bun MCP
 * client that manages its own connections and just wants the Shield gate
 * had no standalone entry point. This module is that entry point.
 *
 * `createShieldGuard()` returns a small filtering function any MCP client
 * can wrap around its own tool-call handler in ~2 lines:
 *
 *   import { createShieldGuard } from "@lyrie/mcp";
 *   const guard = createShieldGuard();
 *   const result = await guard(rawResultFromMyOwnMcpClient, toolArgs);
 *   // result.content is now filtered — unsafe blocks are redacted or the
 *   // call is rejected, per `mode`.
 *
 * This does NOT duplicate detection logic — it re-exports the exact same
 * two-layer scan `McpRegistry.shieldFilter` runs (`ShieldGuard.scanRecalled`
 * JS heuristics + the Rust `AgenticThreatDetector` bridge), factored into a
 * shared, pure(ish) function that both the registry and this standalone
 * surface call. Behavior is identical between the two entry points by
 * construction — there is exactly one implementation.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { ShieldGuard, type ShieldGuardLike, AgenticThreatBridge } from "@lyrie/core";
import type { CallToolResult } from "./types";

export interface ShieldGuardOptions {
  /** Shield guard used to scan tool results before they reach the agent. Defaults to the built-in heuristic fallback. */
  shield?: ShieldGuardLike;
  /**
   * How the guard reacts to a critical verdict from the Rust agentic-threat
   * bridge (self-propagation write paths, base64/unicode-confusable prompt
   * injection) or a critical JS-heuristic ShieldGuard verdict:
   *   "redact" — replace the offending block with a Shield notice (default).
   *   "block"  — throw, rejecting the entire tool call.
   */
  mode?: "redact" | "block";
  /** Agentic-threat bridge instance (Rust detector via subprocess). Injectable for tests. Auto-constructed if omitted. */
  agenticBridge?: AgenticThreatBridge;
  /** Label used in Shield notice messages (e.g. "mcp:fs:read_file"). Defaults to "tool-call". */
  toolLabel?: string;
}

/**
 * A standalone Shield filter function. Call with a raw MCP `CallToolResult`
 * (and optionally the tool-call arguments, so argument-based checks like
 * self-propagation write-path detection can run too) and get back a
 * filtered result. Throws in `"block"` mode on a critical finding.
 */
export type ShieldGuardFn = (
  result: CallToolResult,
  args?: Record<string, unknown>,
) => Promise<CallToolResult>;

/**
 * Build a standalone Shield-filtering function for MCP tool calls/results.
 * Any Node/Bun MCP client — Lyrie-based or not — can import this and wrap
 * it around their own tool-call handler without adopting `McpRegistry`.
 *
 * @example
 *   // A non-Lyrie MCP client wrapping its own tool-call handler:
 *   import { createShieldGuard } from "@lyrie/mcp";
 *
 *   const guard = createShieldGuard({ mode: "redact" });
 *
 *   async function callTool(name: string, args: Record<string, unknown>) {
 *     const raw = await myOwnMcpClient.callTool(name, args);
 *     return guard(raw, args); // <- filtered before it reaches the agent/LLM
 *   }
 */
export function createShieldGuard(options: ShieldGuardOptions = {}): ShieldGuardFn {
  const shield: ShieldGuardLike = options.shield ?? ShieldGuard.fallback();
  const mode: "redact" | "block" = options.mode ?? "redact";
  const agenticBridge: AgenticThreatBridge = options.agenticBridge ?? new AgenticThreatBridge();
  const toolLabel = options.toolLabel ?? "tool-call";

  return async function shieldGuard(
    result: CallToolResult,
    args?: Record<string, unknown>,
  ): Promise<CallToolResult> {
    return runShieldFilter({ toolLabel, result, args, shield, mode, agenticBridge });
  };
}

// ─── Shared filter implementation ────────────────────────────────────────────
//
// This is the SAME logic `McpRegistry.shieldFilter` calls (see registry.ts).
// Both entry points route through this one function — there is no second
// copy of the detection logic to drift out of sync.

export interface RunShieldFilterInput {
  toolLabel: string;
  result: CallToolResult;
  args?: Record<string, unknown>;
  shield: ShieldGuardLike;
  mode: "redact" | "block";
  agenticBridge: AgenticThreatBridge;
}

export async function runShieldFilter(input: RunShieldFilterInput): Promise<CallToolResult> {
  const { toolLabel, result, args, shield, mode, agenticBridge } = input;

  // ── Tool-call argument scan: self-propagation / AI-sink write paths ──────
  if (args && agenticBridge.isAvailable()) {
    for (const [key, value] of Object.entries(args)) {
      if (typeof value !== "string" || value.length === 0) continue;
      const resp = await agenticBridge.run({ writePath: value, sensitiveRead: true });
      const finding = resp?.self_propagation ?? resp?.ai_sink_write;
      if (finding && finding.severity === "critical") {
        const msg = `⚠️ Lyrie Shield blocked ${toolLabel} — argument "${key}" is a self-propagation write path: ${finding.description}`;
        if (mode === "block") {
          throw new Error(msg);
        }
        return { content: [{ type: "text", text: msg }] };
      }
    }
  }

  if (!result?.content) return result;

  const filtered: CallToolResult["content"] = [];
  for (const block of result.content as any[]) {
    const text: string | undefined =
      block?.type === "text" && typeof block.text === "string"
        ? block.text
        : block?.type === "resource" && typeof block?.resource?.text === "string"
          ? block.resource.text
          : undefined;

    if (text === undefined) {
      filtered.push(block);
      continue;
    }

    // Layer 1: JS heuristic ShieldGuard (unchanged existing behavior).
    const verdict = shield.scanRecalled(text);
    if (verdict.blocked) {
      const msg = `⚠️ Lyrie Shield redacted ${toolLabel} ${block.type === "resource" ? "resource" : "output"}: ${verdict.reason ?? "unsafe content"}`;
      if (mode === "block" && verdict.severity === "critical") {
        throw new Error(msg);
      }
      filtered.push({ type: "text", text: msg });
      continue;
    }

    // Layer 2: Rust AgenticThreatDetector bridge — broader pattern set.
    if (agenticBridge.isAvailable()) {
      const finding = await agenticBridge.scanForPromptInjection(text);
      if (finding) {
        const msg = `⚠️ Lyrie Shield redacted ${toolLabel} ${block.type === "resource" ? "resource" : "output"}: ${finding.description}`;
        if (mode === "block" && finding.severity === "critical") {
          throw new Error(msg);
        }
        filtered.push({ type: "text", text: msg });
        continue;
      }
    }

    filtered.push(block);
  }

  return { ...result, content: filtered };
}
