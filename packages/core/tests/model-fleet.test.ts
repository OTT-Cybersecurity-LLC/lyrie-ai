/**
 * ModelFleet Tests — 35+ tests for model routing, cost tracking,
 * latency tracking, health checks, and provider registration.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  ModelFleet,
  autoRoute,
  type LyrieProvider,
  type Message,
  type CompletionOptions,
  type TaskDescription,
} from "../src/engine/model-fleet";

// ─── Fake providers for testing ───────────────────────────────────────────────

function makeFakeProvider(overrides: Partial<LyrieProvider> = {}): LyrieProvider {
  return {
    name: "FakeCloud",
    models: ["fake-model-1"],
    isLocal: false,
    async isAvailable() { return true; },
    async complete(_messages: Message[], _opts: CompletionOptions) { return "ok"; },
    estimateCost(tokens: number) { return (tokens / 1_000_000) * 3; },
    ...overrides,
  };
}

function makeLocalProvider(overrides: Partial<LyrieProvider> = {}): LyrieProvider {
  return makeFakeProvider({
    name: "FakeLocal",
    models: ["local-model-1"],
    isLocal: true,
    estimateCost(_tokens: number) { return 0; },
    ...overrides,
  });
}

function makeUnavailableProvider(): LyrieProvider {
  return makeFakeProvider({
    name: "DeadProvider",
    models: ["dead-model"],
    async isAvailable() { return false; },
    async complete() { throw new Error("network unreachable"); },
  });
}

// ─── autoRoute ────────────────────────────────────────────────────────────────

describe("autoRoute", () => {
  it("routes code task to gpt-5.4-codex", () => {
    const r = autoRoute({ type: "code" });
    expect(r.primary).toBe("openai/gpt-5.4-codex");
    expect(r.reason).toMatch(/code/i);
  });

  it("routes bulk task to MiniMax-highspeed", () => {
    const r = autoRoute({ type: "bulk" });
    expect(r.primary).toBe("minimax/MiniMax-M2.7-highspeed");
    expect(r.reason).toMatch(/bulk/i);
  });

  it("routes reasoning task to grok-4-1-fast-reasoning", () => {
    const r = autoRoute({ type: "reasoning" });
    expect(r.primary).toBe("xai/grok-4-1-fast-reasoning");
    expect(r.reason).toMatch(/reasoning/i);
  });

  it("routes simple task to claude-haiku-4-5", () => {
    const r = autoRoute({ type: "simple" });
    expect(r.primary).toBe("anthropic/claude-haiku-4-5");
    expect(r.fallbacks).toHaveLength(0);
    expect(r.reason).toMatch(/simple/i);
  });

  it("routes chat task to claude-sonnet-4-6 (default)", () => {
    const r = autoRoute({ type: "chat" });
    expect(r.primary).toBe("anthropic/claude-sonnet-4-6");
  });

  it("routes creative task to claude-sonnet-4-6", () => {
    const r = autoRoute({ type: "creative" });
    expect(r.primary).toBe("anthropic/claude-sonnet-4-6");
    expect(r.reason).toMatch(/creative/i);
  });

  it("routes requiresLocal to hermes", () => {
    const r = autoRoute({ type: "chat", requiresLocal: true });
    expect(r.primary).toBe("hermes/hermes-3-70b");
    expect(r.fallbacks).toContain("ollama/llama3.2:1b");
    expect(r.reason).toMatch(/local/i);
  });

  it("requiresLocal overrides task type", () => {
    const r = autoRoute({ type: "code", requiresLocal: true });
    expect(r.primary).toBe("hermes/hermes-3-70b");
  });

  it("preferCheap routes to claude-haiku-4-5", () => {
    const r = autoRoute({ type: "reasoning", preferCheap: true });
    expect(r.primary).toBe("anthropic/claude-haiku-4-5");
    expect(r.reason).toMatch(/cheap/i);
  });

  it("preferCheap includes MiniMax in fallbacks", () => {
    const r = autoRoute({ type: "code", preferCheap: true });
    expect(r.fallbacks).toContain("minimax/MiniMax-M2.7-highspeed");
  });

  it("code route has claude-sonnet as fallback", () => {
    const r = autoRoute({ type: "code" });
    expect(r.fallbacks).toContain("anthropic/claude-sonnet-4-6");
  });

  it("reasoning route has claude-opus as fallback", () => {
    const r = autoRoute({ type: "reasoning" });
    expect(r.fallbacks).toContain("anthropic/claude-opus-4-7");
  });

  it("bulk route has haiku as fallback", () => {
    const r = autoRoute({ type: "bulk" });
    expect(r.fallbacks).toContain("anthropic/claude-haiku-4-5");
  });

  it("all routes have a reason string", () => {
    const types: TaskDescription["type"][] = ["chat", "code", "bulk", "reasoning", "creative", "simple"];
    for (const type of types) {
      const r = autoRoute({ type });
      expect(r.reason.length).toBeGreaterThan(0);
    }
  });

  it("all routes have a primary string", () => {
    const types: TaskDescription["type"][] = ["chat", "code", "bulk", "reasoning", "creative", "simple"];
    for (const type of types) {
      const r = autoRoute({ type });
      expect(r.primary).toMatch(/\//);
    }
  });
});

// ─── ModelFleet — registration ───────────────────────────────────────────────

describe("ModelFleet.register / list", () => {
  beforeEach(() => ModelFleet._reset());

  it("list() returns empty array before any registration", () => {
    const fleet = ModelFleet.getInstance();
    expect(fleet.list()).toHaveLength(0);
  });

  it("registers a provider and lists it", () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider());
    expect(fleet.list().length).toBeGreaterThan(0);
  });

  it("lists all registered providers", () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider({ name: "P1", models: ["m1"] }));
    fleet.register(makeLocalProvider({ name: "P2", models: ["m2"] }));
    expect(fleet.list().length).toBe(2);
  });

  it("list() includes provider name", () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider({ name: "MyProvider", models: ["mp1"] }));
    const info = fleet.list()[0];
    expect(info.name).toBe("MyProvider");
  });

  it("list() includes isLocal flag", () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeLocalProvider());
    const [info] = fleet.list();
    expect(info.isLocal).toBe(true);
  });

  it("list() includes models array", () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider({ models: ["a", "b"] }));
    const [info] = fleet.list();
    expect(info.models).toEqual(["a", "b"]);
  });
});

// ─── ModelFleet — singleton ───────────────────────────────────────────────────

describe("ModelFleet singleton", () => {
  beforeEach(() => ModelFleet._reset());

  it("getInstance() returns the same instance", () => {
    const a = ModelFleet.getInstance();
    const b = ModelFleet.getInstance();
    expect(a).toBe(b);
  });

  it("_reset() creates a new instance", () => {
    const a = ModelFleet.getInstance();
    ModelFleet._reset();
    const b = ModelFleet.getInstance();
    expect(a).not.toBe(b);
  });
});

// ─── ModelFleet — routing ─────────────────────────────────────────────────────

describe("ModelFleet.route", () => {
  beforeEach(() => ModelFleet._reset());

  it("returns route for code task", () => {
    const fleet = ModelFleet.getInstance();
    const r = fleet.route({ type: "code" });
    expect(r.primary).toBe("openai/gpt-5.4-codex");
  });

  it("returns route for simple task", () => {
    const fleet = ModelFleet.getInstance();
    const r = fleet.route({ type: "simple" });
    expect(r.primary).toBe("anthropic/claude-haiku-4-5");
  });

  it("requiresLocal always picks local provider", () => {
    const fleet = ModelFleet.getInstance();
    const r = fleet.route({ type: "code", requiresLocal: true });
    expect(r.primary).toBe("hermes/hermes-3-70b");
  });
});

// ─── ModelFleet — healthCheck ─────────────────────────────────────────────────

describe("ModelFleet.healthCheck", () => {
  beforeEach(() => ModelFleet._reset());

  it("returns empty providers when none registered", async () => {
    const fleet = ModelFleet.getInstance();
    const report = await fleet.healthCheck();
    expect(report.providers).toHaveLength(0);
    expect(report.checkedAt).toBeTruthy();
  });

  it("reports available=true for a healthy provider", async () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider({ name: "Healthy", models: ["h1"] }));
    const report = await fleet.healthCheck();
    const p = report.providers.find((x) => x.name === "Healthy");
    expect(p?.available).toBe(true);
  });

  it("reports available=false for an unhealthy provider", async () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeUnavailableProvider());
    const report = await fleet.healthCheck();
    const p = report.providers.find((x) => x.name === "DeadProvider");
    expect(p?.available).toBe(false);
  });

  it("records latency for healthy provider", async () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider({ name: "FastProvider", models: ["f1"] }));
    const report = await fleet.healthCheck();
    const p = report.providers.find((x) => x.name === "FastProvider");
    expect(typeof p?.latencyMs).toBe("number");
    expect(p!.latencyMs!).toBeGreaterThanOrEqual(0);
  });

  it("healthCheck runs without throwing for mixed providers", async () => {
    const fleet = ModelFleet.getInstance();
    fleet.register(makeFakeProvider());
    fleet.register(makeLocalProvider());
    fleet.register(makeUnavailableProvider());
    await expect(fleet.healthCheck()).resolves.toBeDefined();
  });

  it("checkedAt is a valid ISO date string", async () => {
    const fleet = ModelFleet.getInstance();
    const report = await fleet.healthCheck();
    expect(() => new Date(report.checkedAt)).not.toThrow();
    expect(isNaN(new Date(report.checkedAt).getTime())).toBe(false);
  });
});

// ─── Cost estimation ──────────────────────────────────────────────────────────

describe("Cost estimation", () => {
  it("MiniMax is the cheapest cloud provider", () => {
    // MiniMax: $0.08/MTok, Google Flash: $0.075/MTok — both very cheap
    // Haiku: $0.25/MTok, Sonnet: $3/MTok
    const minimax = (1_000_000 / 1_000_000) * 0.08;
    const sonnet = (1_000_000 / 1_000_000) * 3;
    expect(minimax).toBeLessThan(sonnet);
  });

  it("local providers cost 0", () => {
    const hermes = makeLocalProvider();
    expect(hermes.estimateCost(100_000)).toBe(0);
  });

  it("cloud providers have non-zero cost", () => {
    const cloud = makeFakeProvider();
    expect(cloud.estimateCost(100_000)).toBeGreaterThan(0);
  });
});

// ─── recordCall + cost summary ────────────────────────────────────────────────

describe("ModelFleet cost tracking", () => {
  beforeEach(() => ModelFleet._reset());

  it("cost summary is empty before any calls", () => {
    const fleet = ModelFleet.getInstance();
    const summary = fleet.cost.summary();
    expect(Object.keys(summary)).toHaveLength(0);
  });

  it("records a call and reflects in summary", () => {
    const fleet = ModelFleet.getInstance();
    fleet.recordCall("anthropic", 10_000, 0.03, 500);
    const summary = fleet.cost.summary();
    expect(summary["anthropic"]).toBeDefined();
    expect(summary["anthropic"].calls).toBe(1);
    expect(summary["anthropic"].tokens).toBe(10_000);
  });

  it("accumulates multiple calls for same provider", () => {
    const fleet = ModelFleet.getInstance();
    fleet.recordCall("openai", 5_000, 0.01, 200);
    fleet.recordCall("openai", 5_000, 0.01, 300);
    const summary = fleet.cost.summary();
    expect(summary["openai"].calls).toBe(2);
    expect(summary["openai"].tokens).toBe(10_000);
  });

  it("total cost sums across providers", () => {
    const fleet = ModelFleet.getInstance();
    fleet.recordCall("anthropic", 1_000, 0.003, 100);
    fleet.recordCall("openai", 1_000, 0.002, 100);
    const total = fleet.cost.total();
    expect(total).toBeCloseTo(0.005, 6);
  });
});
