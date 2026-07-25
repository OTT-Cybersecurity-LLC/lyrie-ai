/**
 * AgenticThreatBridge — TS-side client for the Rust `AgenticThreatDetector`
 * (packages/shield/src/agentic_threat.rs), exposed via the `lyrie-shield
 * agentic-bridge` CLI subcommand (packages/shield/src/bridge.rs).
 *
 * Why a subprocess bridge and not NAPI?
 *   The `lyrie-shield` crate has no NAPI-RS dependency and Shield is
 *   already invoked from the TS/Python side as a CLI binary (see
 *   `package.json`'s `shield:build` / `shield:test` scripts and
 *   `packages/core/src/security/mcp-scanner.ts`'s references to
 *   `lyrie_shield`). A JSON-stdin/stdout subprocess call matches that
 *   existing low-risk pattern instead of introducing a new native-addon
 *   build/toolchain requirement.
 *
 * Statelessness:
 *   The Rust binary is invoked once per call and holds no state between
 *   invocations. This class owns the sliding-window event history
 *   (mirroring `AgenticThreatDetector`'s in-memory window) and resends it
 *   on every `detectCompression()` / `analyzeCommand()` call. Events older
 *   than `windowMs` are pruned locally before each call so the Rust-side
 *   window behaves identically to the in-process Rust detector.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync } from "node:fs";
import { join } from "node:path";

export type AttackPhase =
  | "Recon"
  | "InitialAccess"
  | "Execution"
  | "Persistence"
  | "LateralMovement"
  | "Exfiltration"
  | "PromptInjection"
  | "SelfPropagation";

export interface BehavioralEvent {
  timestamp_ms: number;
  phase: AttackPhase;
  /** 1=Automation, 2=Augmentation, 3=Autonomy */
  channel: 1 | 2 | 3;
  tool_fingerprint: string;
}

export interface AttackCompressionSignature {
  phases_observed: AttackPhase[];
  compression_ratio: number;
  channel: number;
  ttp_entropy: number;
  confidence: number;
  threat_level: "None" | "Low" | "Medium" | "High" | "Critical";
}

export interface AgenticFinding {
  severity: "none" | "low" | "medium" | "high" | "critical";
  threat_type: string;
  description: string;
}

export interface AgenticBridgeResponse {
  compression: AttackCompressionSignature;
  prompt_injection: AgenticFinding | null;
  self_propagation: AgenticFinding | null;
  ai_sink_write: AgenticFinding | null;
}

function defaultToolFingerprint(command: string): string {
  const trimmed = command.trim();
  const firstToken = trimmed.split(/\s+/)[0] ?? "unknown";
  return firstToken.length > 0 ? firstToken : "unknown";
}

export interface AgenticThreatBridgeOptions {
  /** Path to the lyrie-shield binary. Auto-detected if omitted. */
  binaryPath?: string;
  /** Sliding window duration in ms. Default: 5 minutes (matches Rust default). */
  windowMs?: number;
  /** Timeout for each subprocess call in ms. Default: 5000. */
  timeoutMs?: number;
}

function findDefaultBinary(): string | null {
  // Resolve relative to this file's package root: packages/core -> ../shield
  const candidates = [
    join(__dirname, "..", "..", "..", "shield", "target", "release", "lyrie-shield"),
    join(__dirname, "..", "..", "..", "shield", "target", "debug", "lyrie-shield"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

/**
 * TS client for the Rust agentic-threat-detection engine.
 *
 * Usage:
 * ```ts
 * const bridge = new AgenticThreatBridge();
 * bridge.ingestCommand("nmap -sV 10.0.0.0/24", "nmap");
 * const sig = await bridge.detectCompression();
 * if (sig && sig.threat_level !== "None") { ... }
 * ```
 */
export class AgenticThreatBridge {
  private events: BehavioralEvent[] = [];
  private readonly binaryPath: string | null;
  private readonly windowMs: number;
  private readonly timeoutMs: number;

  constructor(opts: AgenticThreatBridgeOptions = {}) {
    this.binaryPath = opts.binaryPath ?? findDefaultBinary();
    this.windowMs = opts.windowMs ?? 5 * 60_000;
    this.timeoutMs = opts.timeoutMs ?? 5_000;
  }

  /** True if the lyrie-shield binary was found and this bridge is usable. */
  isAvailable(): boolean {
    return this.binaryPath !== null;
  }

  /**
   * Record a pre-classified behavioral event into the local sliding window.
   * Phase classification lives solely in Rust (`classify_command()` in
   * `agentic_threat.rs`) to avoid two divergent implementations; callers
   * that only have a raw command string should classify it up front by
   * running it through `scanForPromptInjection`/`run()` with `scanText`,
   * or supply an already-known phase (e.g. from an MCP tool-call name
   * mapped by the caller's own routing table).
   */
  ingestEvent(event: BehavioralEvent): void {
    this.evictStale();
    this.events.push(event);
  }

  /**
   * Record a raw command/tool-call as an `Execution`-phase event tagged
   * with its tool fingerprint. This is a coarse default for callers that
   * don't have phase information (most daemon tool-call telemetry) — it
   * still contributes to TTP-entropy and velocity signals even without
   * precise phase classification. Channel is heuristically bumped to 3
   * once 2+ distinct phases have been observed in the local window.
   */
  ingestCommand(command: string, toolFingerprint?: string): void {
    this.evictStale();
    const channel: 1 | 3 = this.distinctPhaseCountHint() >= 2 ? 3 : 1;
    this.events.push({
      timestamp_ms: Date.now(),
      phase: "Execution",
      channel,
      tool_fingerprint: toolFingerprint ?? defaultToolFingerprint(command),
    });
  }

  /** Number of currently-held events within the sliding window. */
  eventCount(): number {
    this.evictStale();
    return this.events.length;
  }

  /** Clear all held events (e.g. after an alert has been actioned). */
  reset(): void {
    this.events = [];
  }

  private evictStale(): void {
    const cutoff = Date.now() - this.windowMs;
    this.events = this.events.filter((e) => e.timestamp_ms >= cutoff);
  }

  private distinctPhaseCountHint(): number {
    return new Set(this.events.map((e) => e.phase)).size;
  }

  /**
   * Run the full agentic-threat pipeline (compression + optional text/path
   * checks) against the current event window via the Rust bridge.
   * Returns `null` if the bridge binary is unavailable (fail-open — the
   * daemon must not crash if Shield hasn't been built on this host).
   */
  async run(opts: { scanText?: string; writePath?: string; sensitiveRead?: boolean } = {}): Promise<AgenticBridgeResponse | null> {
    if (!this.binaryPath) return null;
    this.evictStale();

    const request = {
      events: this.events,
      scan_text: opts.scanText,
      write_path: opts.writePath,
      sensitive_read: opts.sensitiveRead ?? false,
    };

    try {
      const proc = Bun.spawn([this.binaryPath, "agentic-bridge"], {
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      });
      proc.stdin.write(JSON.stringify(request));
      proc.stdin.end();

      const timeout = new Promise<null>((resolve) => {
        setTimeout(() => resolve(null), this.timeoutMs);
      });
      const exited = proc.exited.then(() => proc);
      const result = await Promise.race([exited, timeout]);
      if (result === null) {
        proc.kill();
        return null;
      }

      const stdout = await new Response(proc.stdout).text();
      const exitCode = await proc.exited;
      if (exitCode !== 0) return null;

      const parsed = JSON.parse(stdout.trim()) as AgenticBridgeResponse;
      return parsed;
    } catch {
      // Fail-open: bridge errors must never crash the daemon tick loop.
      return null;
    }
  }

  /** Convenience: run compression detection only (no text/path checks). */
  async detectCompression(): Promise<AttackCompressionSignature | null> {
    const resp = await this.run();
    return resp?.compression ?? null;
  }

  /** Convenience: scan arbitrary text for prompt-injection payloads. */
  async scanForPromptInjection(text: string): Promise<AgenticFinding | null> {
    const resp = await this.run({ scanText: text });
    return resp?.prompt_injection ?? null;
  }
}
