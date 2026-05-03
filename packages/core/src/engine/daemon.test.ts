/**
 * LyrieDaemon — tick-loop tests.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { LyrieDaemon, LYRIE_TICK_PROMPT } from "./daemon";

describe("LyrieDaemon", () => {
  test("runOnce fires the tick handler with index/timestamp", async () => {
    let received: any = null;
    const d = new LyrieDaemon({
      onTick: async (tick) => {
        received = tick;
        return { stop: true };
      },
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
      intervalMs: 5,
      maxTicks: 3,
      onTick: async () => {
        calls++;
        return {};
      },
    });
    await d.start();
    expect(calls).toBe(3);
    expect(d.isRunning()).toBe(false);
  });

  test("start() honors stop:true result", async () => {
    let calls = 0;
    const d = new LyrieDaemon({
      intervalMs: 5,
      onTick: async () => {
        calls++;
        return calls >= 2 ? { stop: true } : {};
      },
    });
    await d.start();
    expect(calls).toBe(2);
  });

  test("stop() halts the loop", async () => {
    const d = new LyrieDaemon({
      intervalMs: 5,
      onTick: async () => {
        d.stop();
        return {};
      },
    });
    await d.start();
    expect(d.isRunning()).toBe(false);
  });

  test("immediate:true skips the wait", async () => {
    const start = Date.now();
    let calls = 0;
    const d = new LyrieDaemon({
      intervalMs: 10_000, // would be very long if not immediate
      maxTicks: 3,
      onTick: async () => {
        calls++;
        return calls < 3 ? { immediate: true } : { stop: true };
      },
    });
    await d.start();
    const elapsed = Date.now() - start;
    expect(calls).toBe(3);
    expect(elapsed).toBeLessThan(1000); // not 30s
  });

  test("LYRIE_TICK_PROMPT mentions the autonomous-running contract", () => {
    expect(LYRIE_TICK_PROMPT).toContain("running autonomously");
    expect(LYRIE_TICK_PROMPT.toLowerCase()).toContain("local time");
    expect(LYRIE_TICK_PROMPT).toContain("Never invent work");
  });
});
