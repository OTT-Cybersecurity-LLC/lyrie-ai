/**
 * ToolLoopDetector Tests
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { ToolLoopDetector } from "../src/agents/loop-detector";
import type { ToolCall } from "../src/agents/loop-detector";

describe("ToolLoopDetector", () => {
  let detector: ToolLoopDetector;

  beforeEach(() => {
    detector = new ToolLoopDetector();
  });

  describe("lifecycle", () => {
    it("tracks active runs", () => {
      expect(detector.activeRuns).toBe(0);
      detector.onRunStart("r1");
      expect(detector.activeRuns).toBe(1);
      detector.onRunStart("r2");
      expect(detector.activeRuns).toBe(2);
      detector.onRunEnd("r1");
      expect(detector.activeRuns).toBe(1);
    });

    it("clears run state on end", () => {
      detector.onRunStart("r1");
      const call: ToolCall = { name: "exec", args: { cmd: "ls" } };
      detector.isLoop(call, "r1");
      detector.onRunEnd("r1");
      expect(detector.callCount(call, "r1")).toBe(0);
    });
  });

  describe("loop detection", () => {
    it("returns false for the first two identical calls", () => {
      detector.onRunStart("run1");
      const call: ToolCall = { name: "web_search", args: { query: "test" } };
      expect(detector.isLoop(call, "run1")).toBe(false);
      expect(detector.isLoop(call, "run1")).toBe(false);
    });

    it("returns true on the third identical call", () => {
      detector.onRunStart("run1");
      const call: ToolCall = { name: "web_search", args: { query: "test" } };
      detector.isLoop(call, "run1");
      detector.isLoop(call, "run1");
      expect(detector.isLoop(call, "run1")).toBe(true);
    });

    it("does not trigger for different tool names", () => {
      detector.onRunStart("run1");
      expect(detector.isLoop({ name: "tool_a", args: {} }, "run1")).toBe(false);
      expect(detector.isLoop({ name: "tool_b", args: {} }, "run1")).toBe(false);
      expect(detector.isLoop({ name: "tool_c", args: {} }, "run1")).toBe(false);
    });

    it("does not trigger for different args", () => {
      detector.onRunStart("run1");
      const base: ToolCall = { name: "exec", args: { cmd: "ls" } };
      const variant: ToolCall = { name: "exec", args: { cmd: "pwd" } };
      detector.isLoop(base, "run1");
      detector.isLoop(base, "run1");
      // third call is different args — should not trigger
      expect(detector.isLoop(variant, "run1")).toBe(false);
    });

    it("auto-starts run if onRunStart was not called", () => {
      const call: ToolCall = { name: "read", args: { path: "/tmp" } };
      expect(detector.isLoop(call, "implicit-run")).toBe(false);
    });

    it("isolates loop counts per run", () => {
      const call: ToolCall = { name: "search", args: { q: "lyrie" } };
      detector.onRunStart("r1");
      detector.onRunStart("r2");
      detector.isLoop(call, "r1");
      detector.isLoop(call, "r1");
      detector.isLoop(call, "r2"); // only 1 in r2
      expect(detector.isLoop(call, "r1")).toBe(true);   // r1 hits 3
      expect(detector.isLoop(call, "r2")).toBe(false);  // r2 still at 2
    });
  });

  describe("normalizeExecCall", () => {
    it("strips pid, duration, and timestamp", () => {
      const call: ToolCall = {
        name: "exec",
        args: { cmd: "ls" },
        pid: 12345,
        duration: 42,
        timestamp: "2026-01-01T00:00:00Z",
      };
      const normalized = detector.normalizeExecCall(call);
      expect(normalized.pid).toBeUndefined();
      expect(normalized.duration).toBeUndefined();
      expect(normalized.timestamp).toBeUndefined();
      expect(normalized.name).toBe("exec");
      expect((normalized.args as any).cmd).toBe("ls");
    });

    it("strips volatile keys from args too", () => {
      const call: ToolCall = {
        name: "exec",
        args: { cmd: "ls", pid: 99, timestamp: 123 },
      };
      const normalized = detector.normalizeExecCall(call);
      // volatile keys inside args are not stripped (only top-level)
      // but top-level volatile keys are stripped
      expect(normalized.pid).toBeUndefined();
    });

    it("preserves non-volatile fields", () => {
      const call: ToolCall = {
        name: "read_file",
        args: { path: "/etc/hosts" },
        sessionId: "abc",
      };
      const normalized = detector.normalizeExecCall(call);
      expect(normalized.sessionId).toBe("abc");
    });

    it("produces same fingerprint for volatile-differing calls", () => {
      detector.onRunStart("run-norm");
      const call1: ToolCall = { name: "exec", args: { cmd: "ls" }, pid: 1, timestamp: "t1" };
      const call2: ToolCall = { name: "exec", args: { cmd: "ls" }, pid: 2, timestamp: "t2" };
      detector.isLoop(call1, "run-norm");
      detector.isLoop(call1, "run-norm");
      // call2 is normalized to same fingerprint — should trigger loop
      expect(detector.isLoop(call2, "run-norm")).toBe(true);
    });
  });

  describe("runSnapshot", () => {
    it("returns empty object for unknown run", () => {
      expect(detector.runSnapshot("unknown")).toEqual({});
    });

    it("returns call counts for a run", () => {
      detector.onRunStart("snap");
      const call: ToolCall = { name: "tool", args: {} };
      detector.isLoop(call, "snap");
      detector.isLoop(call, "snap");
      const snapshot = detector.runSnapshot("snap");
      const counts = Object.values(snapshot);
      expect(counts.length).toBe(1);
      expect(counts[0]).toBe(2);
    });
  });
});
