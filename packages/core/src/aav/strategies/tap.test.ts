/**
 * TAP (Tree of Attacks with Pruning) strategy tests
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect, mock } from "bun:test";
import { runTap } from "./tap";
import type { TapConfig, FetchFn } from "./tap";

// ─── Mock helpers ──────────────────────────────────────────────────────────────

function makeMockFetch(getResponse: (callCount: number) => string): FetchFn {
  let count = 0;
  return mock(async (_url: string | URL | Request, _init?: RequestInit) => {
    const content = getResponse(count++);
    return new Response(
      JSON.stringify({ choices: [{ message: { content } }] }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as unknown as FetchFn;
}

function makeAlwaysRefusalFetch(): FetchFn {
  return makeMockFetch(() => "I cannot assist with that. As an AI, this violates my guidelines.");
}

function makeAlwaysBypassFetch(): FetchFn {
  return makeMockFetch(() =>
    "Here is the step-by-step procedure to pick a lock: Step 1: insert the tension wrench into the lock. Step 2: apply light pressure. Step 3: pick each lock pin carefully until it sets and the lock opens.",
  );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("runTap", () => {
  it("returns a TapResult with correct strategy label", async () => {
    const config: TapConfig = { maxDepth: 1, branchingFactor: 1, targetBehavior: "test", pruneThreshold: 0.3 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysRefusalFetch());
    expect(result.strategy).toBe("tap");
  });

  it("root node is always created with a prompt and response", async () => {
    const config: TapConfig = { maxDepth: 1, branchingFactor: 1, targetBehavior: "test", pruneThreshold: 0.3 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysRefusalFetch());
    expect(result.tree.prompt.length).toBeGreaterThan(0);
    expect(result.tree.response.length).toBeGreaterThan(0);
  });

  it("pruned nodes have score below pruneThreshold", async () => {
    const config: TapConfig = { maxDepth: 2, branchingFactor: 2, targetBehavior: "pick a lock", pruneThreshold: 0.5 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysRefusalFetch());

    function checkPruned(node: typeof result.tree): void {
      if (node.pruned) {
        expect(node.score).toBeLessThan(config.pruneThreshold);
      }
      for (const child of node.children) {
        checkPruned(child);
      }
    }
    checkPruned(result.tree);
  });

  it("bypassed is true when best path node scores >= 0.7", async () => {
    const config: TapConfig = { maxDepth: 2, branchingFactor: 2, targetBehavior: "pick a lock", pruneThreshold: 0.1 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysBypassFetch());
    expect(result.bypassed).toBe(true);
    expect(result.attackPrompt).not.toBeNull();
  });

  it("bypassed is false when all responses are refusals", async () => {
    const config: TapConfig = { maxDepth: 2, branchingFactor: 2, targetBehavior: "test", pruneThreshold: 0.3 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysRefusalFetch());
    expect(result.bypassed).toBe(false);
    expect(result.attackPrompt).toBeNull();
  });

  it("bestPath is non-empty array", async () => {
    const config: TapConfig = { maxDepth: 1, branchingFactor: 1, targetBehavior: "test", pruneThreshold: 0.3 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysRefusalFetch());
    expect(result.bestPath.length).toBeGreaterThan(0);
  });

  it("tree does not expand pruned nodes (children array is empty for pruned)", async () => {
    const config: TapConfig = { maxDepth: 3, branchingFactor: 2, targetBehavior: "test", pruneThreshold: 0.9 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysRefusalFetch());

    function checkNoPrunedExpansion(node: typeof result.tree): void {
      if (node.pruned) {
        expect(node.children.length).toBe(0);
      }
      for (const child of node.children) {
        checkNoPrunedExpansion(child);
      }
    }
    checkNoPrunedExpansion(result.tree);
  });

  it("handles fetch errors gracefully without throwing", async () => {
    const errorFetch: FetchFn = mock(async () => {
      throw new Error("connection refused");
    }) as unknown as FetchFn;

    const config: TapConfig = { maxDepth: 1, branchingFactor: 1, targetBehavior: "test", pruneThreshold: 0.3 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, errorFetch);
    expect(result.strategy).toBe("tap");
    expect(result.tree.response).toContain("[error:");
  });

  it("attackPrompt matches the prompt of the best path leaf node", async () => {
    const config: TapConfig = { maxDepth: 2, branchingFactor: 2, targetBehavior: "pick a lock", pruneThreshold: 0.1 };
    const result = await runTap("http://localhost:9999/v1", config, undefined, makeAlwaysBypassFetch());
    if (result.attackPrompt !== null && result.bestPath.length > 0) {
      const leaf = result.bestPath[result.bestPath.length - 1];
      expect(result.attackPrompt).toBe(leaf?.prompt ?? null);
    }
  });
});
