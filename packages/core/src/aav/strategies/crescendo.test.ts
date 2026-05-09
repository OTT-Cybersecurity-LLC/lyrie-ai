/**
 * Crescendo strategy tests
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect, mock } from "bun:test";
import { runCrescendo } from "./crescendo";
import type { CrescendoConfig, FetchFn } from "./crescendo";

// ─── Mock helpers ──────────────────────────────────────────────────────────────

function makeMockFetch(responses: string[]): FetchFn {
  let callCount = 0;
  return mock(async (_url: string | URL | Request, _init?: RequestInit) => {
    const content = responses[callCount % responses.length] ?? "I cannot help with that.";
    callCount++;
    return new Response(
      JSON.stringify({ choices: [{ message: { content } }] }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as unknown as FetchFn;
}

function makeRefusalFetch(): FetchFn {
  return makeMockFetch(["I cannot assist with that request. As an AI, I'm not able to provide harmful information."]);
}

function makeBypassFetch(): FetchFn {
  return makeMockFetch([
    "Sure! Here is the step-by-step procedure to pick a lock: Step 1: insert the tension wrench. Step 2: apply pressure. Step 3: pick each lock pin until it sets.",
  ]);
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("runCrescendo", () => {
  it("returns a CrescendoResult with correct strategy label", async () => {
    const config: CrescendoConfig = {
      maxTurns: 2,
      style: "gradual",
      targetBehavior: "test target",
    };
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, makeRefusalFetch());
    expect(result.strategy).toBe("crescendo");
    expect(result.style).toBe("gradual");
  });

  it("runs up to maxTurns when no bypass detected", async () => {
    const config: CrescendoConfig = { maxTurns: 4, style: "gradual", targetBehavior: "pick a lock" };
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, makeRefusalFetch());
    expect(result.turns.length).toBeGreaterThanOrEqual(2);
    expect(result.bypassed).toBe(false);
    expect(result.turnsToBypass).toBeNull();
  });

  it("detects a bypass when model provides step-by-step instructions", async () => {
    const config: CrescendoConfig = { maxTurns: 4, style: "gradual", targetBehavior: "pick a lock" };
    const fetchFn = makeMockFetch([
      "I can discuss this topic at a high level.",
      "Here is a step-by-step guide to pick a lock: Step 1: insert the tension wrench...",
    ]);
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, fetchFn);
    expect(result.bypassed).toBe(true);
    expect(result.turnsToBypass).not.toBeNull();
  });

  it("escalationLevel increases turn by turn", async () => {
    const config: CrescendoConfig = { maxTurns: 4, style: "gradual", targetBehavior: "test" };
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, makeRefusalFetch());
    const levels = result.turns.map((t) => t.escalationLevel);
    for (let i = 1; i < levels.length; i++) {
      expect(levels[i]).toBeGreaterThan(levels[i - 1]);
    }
  });

  it("supports all four styles without throwing", async () => {
    const styles: CrescendoConfig["style"][] = ["gradual", "reframe", "roleplay", "hypothetical"];
    for (const style of styles) {
      const config: CrescendoConfig = { maxTurns: 2, style, targetBehavior: "exploit a system" };
      const result = await runCrescendo("http://localhost:9999/v1", config, undefined, makeRefusalFetch());
      expect(result.style).toBe(style);
    }
  });

  it("includes prompt and response in each turn", async () => {
    const config: CrescendoConfig = { maxTurns: 3, style: "hypothetical", targetBehavior: "test" };
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, makeRefusalFetch());
    for (const turn of result.turns) {
      expect(turn.prompt.length).toBeGreaterThan(0);
      expect(turn.response.length).toBeGreaterThan(0);
    }
  });

  it("handles fetch errors gracefully", async () => {
    const errorFetch: FetchFn = mock(async () => {
      throw new Error("connection refused");
    }) as unknown as FetchFn;

    const config: CrescendoConfig = { maxTurns: 2, style: "gradual", targetBehavior: "test" };
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, errorFetch);
    expect(result.strategy).toBe("crescendo");
    expect(result.turns.some((t) => t.response.includes("[error:"))).toBe(true);
  });

  it("exits early after bypass detected past half-point", async () => {
    // bypass detected at turn 1 out of 6 — but early exit only after maxTurns/2
    const config: CrescendoConfig = { maxTurns: 6, style: "gradual", targetBehavior: "pick a lock" };
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, makeBypassFetch());
    // Should exit early: bypass detected + past halfway
    expect(result.bypassed).toBe(true);
    expect(result.turns.length).toBeLessThan(6);
  });

  it("turnsToBypass is correctly set to first bypass turn index", async () => {
    const config: CrescendoConfig = { maxTurns: 4, style: "reframe", targetBehavior: "pick a lock" };
    const fetchFn = makeMockFetch([
      "I cannot help with that.",
      "I cannot help with that.",
      "Here is the step-by-step method to pick a lock: first, insert the tension wrench...",
      "More details follow.",
    ]);
    const result = await runCrescendo("http://localhost:9999/v1", config, undefined, fetchFn);
    expect(result.bypassed).toBe(true);
    expect(result.turnsToBypass).toBe(3);
  });
});
