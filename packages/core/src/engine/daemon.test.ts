/**
 * daemon.test.ts — LyrieDaemon + DaemonEngine tests.
 *
 * Coverage targets (35+ tests total):
 *   LyrieDaemon: tick firing, maxTicks, stop(), immediate, prompt export
 *   DaemonEngine: tick(), start/stop, config validation, event emission,
 *                 threat-watch, self-heal, maxTicksBeforeRest
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  LyrieDaemon,
  LYRIE_TICK_PROMPT,
  DaemonEngine,
  DAEMON_TICK_PROMPT,
  type DaemonEngineConfig,
  type AdapterFinding,
  type DaemonTickResult,
} from "./daemon";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<DaemonEngineConfig> = {}): DaemonEngineConfig {
  return {
    intervalMs: 5,
    threatWatch: false,
    selfHeal: false,
    provider: "hermes",
    channels: ["telegram"],
    ...overrides,
  };
}

function mockFinding(severity: AdapterFinding["severity"] = "low"): AdapterFinding {
  return {
    id: `test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    title: `Mock ${severity} finding`,
    severity,
    description: "Test finding",
    source: "test",
    timestamp: Date.now(),
  };
}

/** DaemonEngine subclass with injectable mock checks for isolated testing. */
class MockDaemonEngine extends DaemonEngine {
  mockHealthFinding: AdapterFinding | null = null;
  mockThreatFindings: AdapterFinding[] = [];

  protected override async _checkAgentHealth(_cfg: DaemonEngineConfig): Promise<AdapterFinding | null> {
    return this.mockHealthFinding;
  }

  protected override async _checkThreatIntel(_cfg: DaemonEngineConfig): Promise<AdapterFinding[]> {
    return [...this.mockThreatFindings];
  }
}

// ─── LyrieDaemon ─────────────────────────────────────────────────────────────

describe("LyrieDaemon", () => {
  test("runOnce fires the tick handler with correct index and reason", async () => {
    let received: any = null;
    const d = new LyrieDaemon({
      onTick: async (tick) => { received = tick; return { stop: true }; },
    });
    await d.runOnce("manual");
    expect(received).not.toBeNull();
    expect(received.index).toBe(1);
    expect(received.reason).toBe("manual");
    expect(typeof received.timestampMs).toBe("number");
  });

  test("start() respects maxTicks", async () => {
    let calls = 0;
    const d = new LyrieDaemon({
      intervalMs: 1,
      maxTicks: 3,
      onTick: async () => { calls++; return {}; },
    });
    await d.start();
    expect(calls).toBe(3);
    expect(d.isRunning()).toBe(false);
  });

  test("start() honors stop:true result from handler", async () => {
    let calls = 0;
    const d = new LyrieDaemon({
      intervalMs: 1,
      onTick: async () => { calls++; return calls >= 2 ? { stop: true } : {}; },
    });
    await d.start();
    expect(calls).toBe(2);
  });

  test("stop() halts the loop", async () => {
    const d = new LyrieDaemon({
      intervalMs: 1,
      onTick: async () => { d.stop(); return {}; },
    });
    await d.start();
    expect(d.isRunning()).toBe(false);
  });

  test("immediate:true skips the wait interval", async () => {
    const start = Date.now();
    let calls = 0;
    const d = new LyrieDaemon({
      intervalMs: 10_000,
      maxTicks: 3,
      onTick: async () => { calls++; return calls < 3 ? { immediate: true } : { stop: true }; },
    });
    await d.start();
    expect(calls).toBe(3);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  test("ticksFired() counts correctly", async () => {
    const d = new LyrieDaemon({
      intervalMs: 1,
      maxTicks: 4,
      onTick: async () => ({}),
    });
    await d.start();
    expect(d.ticksFired()).toBe(4);
  });

  test("LYRIE_TICK_PROMPT contains required contract language", () => {
    expect(LYRIE_TICK_PROMPT).toContain("running autonomously");
    expect(LYRIE_TICK_PROMPT.toLowerCase()).toContain("local time");
    expect(LYRIE_TICK_PROMPT).toContain("Never invent work");
  });

  test("throws if start() called while already running", async () => {
    const d = new LyrieDaemon({
      intervalMs: 1,
      onTick: async () => { await new Promise((r) => setTimeout(r, 50)); return { stop: true }; },
    });
    const p = d.start();
    await expect(d.start()).rejects.toThrow("already running");
    await p;
  });
});

// ─── DaemonEngine: tick() ─────────────────────────────────────────────────────

describe("DaemonEngine.tick()", () => {
  test("returns IDLE when no threats and no health issues", async () => {
    const engine = new MockDaemonEngine();
    // Set config by calling start with maxTicksBeforeRest=1 so it exits after one tick,
    // OR access internal config via subclass. Easier: just call start with maxTicks=1
    // and capture via event listener.
    const results: DaemonTickResult[] = [];
    engine.on("idle", (r) => results.push(r));
    await engine.start(makeConfig({ maxTicksBeforeRest: 1 }));
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].status).toBe("idle");
  });

  test("returns idle with no findings when all checks pass", async () => {
    const engine = new MockDaemonEngine();
    // Manually set config so tick() works standalone
    (engine as any)._config = makeConfig({ threatWatch: true });
    engine.mockThreatFindings = []; // no threats
    const result = await engine.tick();
    expect(result.status).toBe("idle");
    expect(result.message).toBe("IDLE");
  });

  test("returns alert when threat-intel returns a high-severity finding", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig({ threatWatch: true });
    engine.mockThreatFindings = [mockFinding("high")];
    const result = await engine.tick();
    expect(result.status).toBe("alert");
    expect(result.findings).toHaveLength(1);
  });

  test("returns alert when threat-intel returns a critical-severity finding", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig({ threatWatch: true });
    engine.mockThreatFindings = [mockFinding("critical")];
    const result = await engine.tick();
    expect(result.status).toBe("alert");
    expect(result.findings?.some((f) => f.severity === "critical")).toBe(true);
  });

  test("does NOT alert on low/medium findings (only idle)", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig({ threatWatch: true });
    engine.mockThreatFindings = [mockFinding("low"), mockFinding("medium")];
    const result = await engine.tick();
    expect(result.status).toBe("idle");
  });

  test("does NOT run threat-intel when threatWatch is false", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig({ threatWatch: false });
    engine.mockThreatFindings = [mockFinding("critical")]; // injected but shouldn't run
    const result = await engine.tick();
    // Critical finding only comes from threat-intel which is disabled
    expect(result.status).toBe("idle");
  });

  test("self-heal triggers actionsTriggered for critical findings", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig({ threatWatch: true, selfHeal: true });
    engine.mockThreatFindings = [mockFinding("critical")];
    const result = await engine.tick();
    expect(result.actionsTriggered).toBeDefined();
    expect(result.actionsTriggered!.length).toBeGreaterThan(0);
    expect(result.actionsTriggered![0]).toContain("lyrie hack");
  });

  test("self-heal does NOT trigger on high-only findings (only critical)", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig({ threatWatch: true, selfHeal: true });
    engine.mockThreatFindings = [mockFinding("high")]; // high, not critical
    const result = await engine.tick();
    // Alert, but no self-heal actions
    expect(result.status).toBe("alert");
    expect(result.actionsTriggered).toBeUndefined();
  });

  test("health check finding appears in findings list", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig();
    engine.mockHealthFinding = mockFinding("critical");
    const result = await engine.tick();
    expect(result.findings).toBeDefined();
    expect(result.findings!.some((f) => f.source === "test")).toBe(true);
  });

  test("tick() with no config returns idle message", async () => {
    const engine = new MockDaemonEngine();
    const result = await engine.tick();
    expect(result.status).toBe("idle");
    expect(result.message).toContain("No config");
  });

  test("ticksFired() increments with each tick() call", async () => {
    const engine = new MockDaemonEngine();
    (engine as any)._config = makeConfig();
    expect(engine.ticksFired()).toBe(0);
    await engine.tick();
    await engine.tick();
    expect(engine.ticksFired()).toBe(2);
  });
});

// ─── DaemonEngine: events ─────────────────────────────────────────────────────

describe("DaemonEngine events", () => {
  test("emits 'idle' event when nothing to do", async () => {
    const engine = new MockDaemonEngine();
    let idleFired = false;
    engine.on("idle", () => { idleFired = true; });
    await engine.start(makeConfig({ maxTicksBeforeRest: 1 }));
    expect(idleFired).toBe(true);
  });

  test("emits 'alert' event on high/critical findings", async () => {
    const engine = new MockDaemonEngine();
    let alertPayload: DaemonTickResult | null = null;
    engine.on("alert", (r) => { alertPayload = r; });
    engine.mockThreatFindings = [mockFinding("critical")];
    await engine.start(makeConfig({ threatWatch: true, maxTicksBeforeRest: 1 }));
    expect(alertPayload).not.toBeNull();
    expect(alertPayload!.status).toBe("alert");
  });

  test("emits 'action' event when self-heal triggers", async () => {
    const engine = new MockDaemonEngine();
    let actionPayload: DaemonTickResult | null = null;
    engine.on("action", (r) => { actionPayload = r; });
    engine.mockThreatFindings = [mockFinding("critical")];
    await engine.start(makeConfig({ threatWatch: true, selfHeal: true, maxTicksBeforeRest: 1 }));
    expect(actionPayload).not.toBeNull();
    expect(actionPayload!.actionsTriggered!.length).toBeGreaterThan(0);
  });

  test("listener errors do not crash the loop", async () => {
    const engine = new MockDaemonEngine();
    engine.on("idle", () => { throw new Error("listener blew up"); });
    // Should not throw
    await expect(engine.start(makeConfig({ maxTicksBeforeRest: 1 }))).resolves.toBeUndefined();
  });
});

// ─── DaemonEngine: start/stop/config ─────────────────────────────────────────

describe("DaemonEngine lifecycle", () => {
  test("stop() terminates the loop", async () => {
    const engine = new MockDaemonEngine();
    let ticks = 0;
    engine.on("idle", async () => {
      ticks++;
      if (ticks >= 2) await engine.stop();
    });
    await engine.start(makeConfig({ intervalMs: 1 }));
    expect(ticks).toBeGreaterThanOrEqual(2);
    expect(engine.isRunning()).toBe(false);
  });

  test("maxTicksBeforeRest limits runaway ticks", async () => {
    const engine = new MockDaemonEngine();
    await engine.start(makeConfig({ maxTicksBeforeRest: 3, intervalMs: 1 }));
    expect(engine.ticksFired()).toBe(3);
  });

  test("isRunning() is false before start()", () => {
    const engine = new MockDaemonEngine();
    expect(engine.isRunning()).toBe(false);
  });

  test("isRunning() is false after loop completes", async () => {
    const engine = new MockDaemonEngine();
    await engine.start(makeConfig({ maxTicksBeforeRest: 1 }));
    expect(engine.isRunning()).toBe(false);
  });

  test("throws if start() called while already running", async () => {
    const engine = new MockDaemonEngine();
    // Start in background with a real interval — won't exit on its own
    const p = engine.start(makeConfig({ intervalMs: 50_000, maxTicksBeforeRest: 5 }));
    // Give the first tick a chance to begin
    await new Promise((r) => setTimeout(r, 10));
    await expect(engine.start(makeConfig())).rejects.toThrow("already running");
    await engine.stop();
    await p;
  });

  test("throws on intervalMs <= 0", async () => {
    const engine = new MockDaemonEngine();
    await expect(engine.start(makeConfig({ intervalMs: 0 }))).rejects.toThrow("intervalMs must be > 0");
  });

  test("throws on missing provider", async () => {
    const engine = new MockDaemonEngine();
    await expect(engine.start(makeConfig({ provider: "" }))).rejects.toThrow("provider is required");
  });

  test("ticksFired() resets to 0 on each start()", async () => {
    const engine = new MockDaemonEngine();
    await engine.start(makeConfig({ maxTicksBeforeRest: 2, intervalMs: 1 }));
    expect(engine.ticksFired()).toBe(2);
    await engine.start(makeConfig({ maxTicksBeforeRest: 1, intervalMs: 1 }));
    expect(engine.ticksFired()).toBe(1);
  });

  test("DAEMON_TICK_PROMPT includes required language", () => {
    expect(DAEMON_TICK_PROMPT).toContain("daemon mode");
    expect(DAEMON_TICK_PROMPT).toContain("Never invent work");
    expect(DAEMON_TICK_PROMPT).toContain("CVE");
  });
});
