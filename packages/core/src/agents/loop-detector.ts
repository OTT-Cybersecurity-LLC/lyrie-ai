/**
 * ToolLoopDetector — Run-scoped detection of repeated tool calls.
 *
 * Problem: agents can get stuck calling the same tool with the same arguments
 * in a loop when a model receives an empty/ambiguous response.
 *
 * Solution: within a single run, fingerprint each normalized tool call.
 * If the same fingerprint appears ≥ LOOP_THRESHOLD times, flag it as a loop.
 *
 * Normalization strips volatile fields (PID, duration, timestamp) so that
 * functionally-identical calls are detected even when metadata differs.
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

export interface ToolCall {
  name: string;
  args?: Record<string, unknown>;
  /** Optional metadata (stripped during normalization) */
  pid?: number;
  duration?: number;
  timestamp?: string | number;
  [key: string]: unknown;
}

const LOOP_THRESHOLD = 3;

/** Volatile keys that are stripped before fingerprinting. */
const VOLATILE_KEYS = new Set(["pid", "duration", "timestamp", "requestId", "traceId", "spanId"]);

export class ToolLoopDetector {
  /** runId → { fingerprint → count } */
  private readonly _runs = new Map<string, Map<string, number>>();

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  onRunStart(runId: string): void {
    this._runs.set(runId, new Map());
  }

  onRunEnd(runId: string): void {
    this._runs.delete(runId);
  }

  // ─── Detection ─────────────────────────────────────────────────────────────

  /**
   * Record a tool call for the given run and return true if it looks like a loop.
   */
  isLoop(call: ToolCall, runId: string): boolean {
    let counters = this._runs.get(runId);
    if (!counters) {
      // Auto-start if caller forgot onRunStart
      counters = new Map();
      this._runs.set(runId, counters);
    }

    const normalized = this.normalizeExecCall(call);
    const fp = fingerprint(normalized);
    const count = (counters.get(fp) ?? 0) + 1;
    counters.set(fp, count);

    return count >= LOOP_THRESHOLD;
  }

  /**
   * How many times the exact call has been seen in this run.
   */
  callCount(call: ToolCall, runId: string): number {
    const counters = this._runs.get(runId);
    if (!counters) return 0;
    return counters.get(fingerprint(this.normalizeExecCall(call))) ?? 0;
  }

  // ─── Normalization ─────────────────────────────────────────────────────────

  /**
   * Strip volatile fields (PID, duration, timestamp) from a ToolCall so that
   * functionally identical calls produce the same fingerprint.
   */
  normalizeExecCall(call: ToolCall): ToolCall {
    const normalized: ToolCall = { name: call.name };

    if (call.args) {
      const cleanArgs: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(call.args)) {
        if (!VOLATILE_KEYS.has(k)) {
          cleanArgs[k] = v;
        }
      }
      normalized.args = cleanArgs;
    }

    // Copy non-volatile top-level keys
    for (const [k, v] of Object.entries(call)) {
      if (k !== "name" && k !== "args" && !VOLATILE_KEYS.has(k)) {
        normalized[k] = v;
      }
    }

    return normalized;
  }

  // ─── Diagnostics ───────────────────────────────────────────────────────────

  /** Return all fingerprints and counts for a run (useful for debugging). */
  runSnapshot(runId: string): Record<string, number> {
    const counters = this._runs.get(runId);
    if (!counters) return {};
    return Object.fromEntries(counters);
  }

  /** Number of active runs being tracked. */
  get activeRuns(): number {
    return this._runs.size;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fingerprint(call: ToolCall): string {
  return JSON.stringify(call, sortedReplacer);
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}
