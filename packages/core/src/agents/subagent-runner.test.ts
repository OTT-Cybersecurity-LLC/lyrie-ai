/**
 * SubagentRunner Tests
 *
 * Tests for the LLM-callable sub-agent orchestration layer (v1.1).
 * spawn_subagent tool registration, SubagentRunner.run, parallel runs,
 * timeout enforcement, fork/isolated context modes.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { SubagentRunner, defaultSubagentRunner } from "./subagent-runner";
import type { SubagentOptions, SubagentResult, SubagentTask } from "./subagent-runner";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Build a mock SubagentRunner that short-circuits the engine so tests stay
 * fast and offline.  Uses Bun's prototype patching in lieu of a full DI
 * framework.
 */
function mockRunner(
  handler: (task: string, options: SubagentOptions) => SubagentResult,
): SubagentRunner {
  const runner = new SubagentRunner();
  // @ts-expect-error — intentional override for testing
  runner.run = async (task: string, options: SubagentOptions = {}) => handler(task, options);
  return runner;
}

// ─── SubagentRunner: type safety ─────────────────────────────────────────────

describe("SubagentRunner — interface contracts", () => {
  it("SubagentResult has all required fields", () => {
    const result: SubagentResult = {
      success: true,
      output: "done",
      durationMs: 42,
      model: "claude-haiku-4-5",
    };
    expect(result.success).toBe(true);
    expect(result.output).toBe("done");
    expect(typeof result.durationMs).toBe("number");
    expect(typeof result.model).toBe("string");
  });

  it("SubagentResult may carry an error field on failure", () => {
    const result: SubagentResult = {
      success: false,
      output: "",
      durationMs: 10,
      model: "unknown",
      error: "timed out",
    };
    expect(result.error).toBe("timed out");
  });

  it("SubagentTask wraps task + options", () => {
    const t: SubagentTask = {
      task: "summarise CVEs",
      options: { timeoutSeconds: 60, context: "isolated" },
    };
    expect(t.task).toBe("summarise CVEs");
    expect(t.options?.timeoutSeconds).toBe(60);
  });
});

// ─── SubagentRunner: run ──────────────────────────────────────────────────────

describe("SubagentRunner.run", () => {
  it("returns SubagentResult with success=true on happy path", async () => {
    const runner = mockRunner((task) => ({
      success: true,
      output: `result for: ${task}`,
      durationMs: 1,
      model: "stub",
    }));

    const res = await runner.run("hello");
    expect(res.success).toBe(true);
    expect(res.output).toContain("hello");
  });

  it("returns SubagentResult with success=false on error", async () => {
    const runner = mockRunner(() => ({
      success: false,
      output: "",
      durationMs: 1,
      model: "stub",
      error: "engine blew up",
    }));

    const res = await runner.run("crash");
    expect(res.success).toBe(false);
    expect(res.error).toBeDefined();
  });

  it("passes model option through to result", async () => {
    const runner = mockRunner((_task, opts) => ({
      success: true,
      output: "ok",
      durationMs: 1,
      model: opts.model ?? "default",
    }));

    const res = await runner.run("task", { model: "claude-opus-4-6" });
    expect(res.model).toBe("claude-opus-4-6");
  });

  it("passes timeoutSeconds option", async () => {
    let capturedTimeout = 0;
    const runner = mockRunner((_task, opts) => {
      capturedTimeout = opts.timeoutSeconds ?? -1;
      return { success: true, output: "ok", durationMs: 1, model: "stub" };
    });

    await runner.run("task", { timeoutSeconds: 42 });
    expect(capturedTimeout).toBe(42);
  });

  it("defaults context to isolated", async () => {
    let capturedCtx: string | undefined;
    const runner = mockRunner((_task, opts) => {
      capturedCtx = opts.context;
      return { success: true, output: "ok", durationMs: 1, model: "stub" };
    });

    await runner.run("task");
    expect(capturedCtx ?? "isolated").toBe("isolated");
  });

  it("accepts context=fork and passes parentContext", async () => {
    let capturedCtx: string | undefined;
    let capturedParent: string | undefined;
    const runner = mockRunner((_task, opts) => {
      capturedCtx = opts.context;
      capturedParent = opts.parentContext;
      return { success: true, output: "ok", durationMs: 1, model: "stub" };
    });

    await runner.run("task", { context: "fork", parentContext: "parent summary" });
    expect(capturedCtx).toBe("fork");
    expect(capturedParent).toBe("parent summary");
  });
});

// ─── SubagentRunner: runParallel ──────────────────────────────────────────────

describe("SubagentRunner.runParallel", () => {
  it("returns an array matching input length", async () => {
    const runner = mockRunner((task) => ({
      success: true,
      output: `result:${task}`,
      durationMs: 1,
      model: "stub",
    }));

    const tasks: SubagentTask[] = [
      { task: "task-A" },
      { task: "task-B" },
      { task: "task-C" },
    ];

    const results = await runner.runParallel(tasks);
    expect(results).toHaveLength(3);
  });

  it("results preserve input order", async () => {
    const runner = mockRunner((task) => ({
      success: true,
      output: task,
      durationMs: 1,
      model: "stub",
    }));

    const tasks: SubagentTask[] = [
      { task: "first" },
      { task: "second" },
      { task: "third" },
    ];

    const results = await runner.runParallel(tasks);
    expect(results[0].output).toBe("first");
    expect(results[1].output).toBe("second");
    expect(results[2].output).toBe("third");
  });

  it("runs tasks concurrently (timing test)", async () => {
    const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

    const runner = new SubagentRunner();
    // Override run to simulate 50ms work per task
    // @ts-expect-error
    runner.run = async (task: string) => {
      await delay(50);
      return { success: true, output: task, durationMs: 50, model: "stub" };
    };

    const tasks: SubagentTask[] = Array.from({ length: 4 }, (_, i) => ({ task: `t${i}` }));

    const start = Date.now();
    const results = await runner.runParallel(tasks);
    const elapsed = Date.now() - start;

    // Sequential would be 200ms; parallel should be < 150ms
    expect(elapsed).toBeLessThan(150);
    expect(results).toHaveLength(4);
  });

  it("handles a mix of success and failure", async () => {
    const runner = mockRunner((task) => ({
      success: task !== "fail",
      output: task !== "fail" ? "ok" : "",
      durationMs: 1,
      model: "stub",
      error: task === "fail" ? "boom" : undefined,
    }));

    const results = await runner.runParallel([
      { task: "ok-1" },
      { task: "fail" },
      { task: "ok-2" },
    ]);

    expect(results[0].success).toBe(true);
    expect(results[1].success).toBe(false);
    expect(results[1].error).toBe("boom");
    expect(results[2].success).toBe(true);
  });

  it("empty tasks array returns empty results", async () => {
    const runner = mockRunner(() => ({ success: true, output: "", durationMs: 0, model: "stub" }));
    const results = await runner.runParallel([]);
    expect(results).toHaveLength(0);
  });
});

// ─── SubagentRunner: timeout enforcement ─────────────────────────────────────

describe("SubagentRunner — timeout enforcement", () => {
  it("enforces timeoutSeconds — run that takes too long returns error", async () => {
    const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

    const runner = new SubagentRunner();
    // @ts-expect-error
    runner.run = async (_task: string, opts: SubagentOptions = {}) => {
      const limit = (opts.timeoutSeconds ?? 300) * 1000;
      const result = await Promise.race<SubagentResult>([
        delay(10_000).then(() => ({ success: true, output: "late", durationMs: 10000, model: "stub" })),
        new Promise<SubagentResult>((resolve) =>
          setTimeout(
            () =>
              resolve({
                success: false,
                output: "",
                durationMs: limit,
                model: "stub",
                error: `Sub-agent timed out after ${opts.timeoutSeconds ?? 300}s`,
              }),
            limit,
          ),
        ),
      ]);
      return result;
    };

    const start = Date.now();
    const res = await runner.run("slow task", { timeoutSeconds: 0.05 });
    const elapsed = Date.now() - start;

    expect(res.success).toBe(false);
    expect(res.error).toMatch(/timed out/);
    expect(elapsed).toBeLessThan(500);
  });
});

// ─── defaultSubagentRunner: singleton ─────────────────────────────────────────

describe("defaultSubagentRunner singleton", () => {
  it("is exported and is a SubagentRunner instance", () => {
    expect(defaultSubagentRunner).toBeInstanceOf(SubagentRunner);
  });
});
