/**
 * RustShieldBridge — wires the compiled Lyrie Shield Rust binary into the
 * TypeScript engine via JSON-RPC over stdin/stdout.
 *
 * The Rust binary (`packages/shield/target/release/lyrie-shield`) exposes
 * three RPC methods:
 *   scan_malware(filePath)     → MalwareScanResult
 *   scan_behaviour(events[])  → BehaviourScanResult
 *   waf_check(url, headers)   → WAFResult
 *
 * Wire-up:
 *   const bridge = new RustShieldBridge();
 *   if (await bridge.start()) {
 *     const result = await bridge.scanMalware('/path/to/file');
 *   }
 *
 * Responsibility split (spec U2):
 *   Rust binary:  malware signature scan, behavioural analysis on file writes,
 *                 WAF on outbound web fetches.
 *   TS Shield:    prompt injection, exfil patterns, MCP filter (called per-message,
 *                 latency-critical — keep in TS).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MalwareScanResult {
  clean: boolean;
  /** Threat name if detected (e.g. "Trojan.Generic.123") */
  threat?: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  details?: string;
  latencyMs: number;
}

export interface BehaviourEvent {
  type: "file_write" | "file_delete" | "network_connect" | "process_spawn";
  target: string;
  metadata?: Record<string, unknown>;
}

export interface BehaviourScanResult {
  anomalous: boolean;
  signals: string[];
  severity: "none" | "low" | "medium" | "high" | "critical";
  latencyMs: number;
}

export interface WAFResult {
  blocked: boolean;
  rule?: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  latencyMs: number;
}

// ─── JSON-RPC types ───────────────────────────────────────────────────────────

interface RPCRequest {
  id: number;
  method: string;
  params: unknown;
}

interface RPCResponse {
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

type PendingCall = {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

// ─── RustShieldBridge ─────────────────────────────────────────────────────────

export class RustShieldBridge {
  private proc: ChildProcess | null = null;
  private pending = new Map<number, PendingCall>();
  private nextId = 1;
  private available = false;
  private readonly rpcTimeoutMs = 5000;

  /**
   * Default path to the compiled Rust binary.
   * Resolved relative to the monorepo root.
   */
  private readonly binaryPath: string;

  constructor(binaryPath?: string) {
    const repoRoot = resolve(__dirname, "../../../../..");
    this.binaryPath =
      binaryPath ??
      resolve(repoRoot, "packages/shield/target/release/lyrie-shield");
  }

  /**
   * Start the Rust shield process.
   * Returns true if the binary was found and started successfully.
   */
  async start(): Promise<boolean> {
    if (!existsSync(this.binaryPath)) {
      console.warn(
        `[rust-shield] Binary not found at ${this.binaryPath}. ` +
          "Run `bun run shield:build` to compile. Rust Shield disabled."
      );
      this.available = false;
      return false;
    }

    try {
      this.proc = spawn(this.binaryPath, ["--rpc"], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      this.proc.on("error", (err) => {
        console.error(`[rust-shield] Process error: ${err.message}`);
        this.available = false;
      });

      this.proc.on("exit", (code) => {
        if (code !== 0) {
          console.warn(`[rust-shield] Process exited with code ${code}`);
        }
        this.available = false;
        // Reject all pending calls
        for (const [, pending] of this.pending) {
          clearTimeout(pending.timer);
          pending.reject(new Error("Rust shield process exited"));
        }
        this.pending.clear();
      });

      // Set up stdout line reader for JSON-RPC responses
      const rl = createInterface({ input: this.proc.stdout! });
      rl.on("line", (line) => this.handleResponse(line));

      // Wait for the ready signal (the binary writes {"ready":true} on startup)
      await this.waitForReady();

      this.available = true;
      console.log(`[rust-shield] ✓ Lyrie Shield Rust binary ready at ${this.binaryPath}`);
      return true;
    } catch (err: any) {
      console.warn(`[rust-shield] Failed to start: ${err.message}. Rust Shield disabled.`);
      this.available = false;
      return false;
    }
  }

  /**
   * Stop the Rust shield process gracefully.
   */
  async stop(): Promise<void> {
    if (this.proc) {
      this.proc.kill("SIGTERM");
      this.proc = null;
      this.available = false;
    }
  }

  /** Whether the Rust binary is running and available. */
  isAvailable(): boolean {
    return this.available;
  }

  // ─── Public RPC methods ───────────────────────────────────────────────────

  /**
   * Scan a file for malware signatures using the Rust binary's YARA/ClamAV
   * signature engine. Falls back gracefully when unavailable.
   */
  async scanMalware(filePath: string): Promise<MalwareScanResult> {
    const start = performance.now();

    if (!this.available) {
      return {
        clean: true,
        severity: "none",
        details: "Rust Shield unavailable — compile with `bun run shield:build`",
        latencyMs: performance.now() - start,
      };
    }

    try {
      const result = await this.call<Omit<MalwareScanResult, "latencyMs">>(
        "scan_malware",
        { path: filePath }
      );
      return { ...result, latencyMs: performance.now() - start };
    } catch (err: any) {
      return {
        clean: true,
        severity: "low",
        details: `scan error: ${err.message}`,
        latencyMs: performance.now() - start,
      };
    }
  }

  /**
   * Analyse a sequence of behavioural events (file writes, network calls, etc.)
   * for anomaly signals.
   */
  async scanBehaviour(events: BehaviourEvent[]): Promise<BehaviourScanResult> {
    const start = performance.now();

    if (!this.available) {
      return {
        anomalous: false,
        signals: [],
        severity: "none",
        latencyMs: performance.now() - start,
      };
    }

    try {
      const result = await this.call<Omit<BehaviourScanResult, "latencyMs">>(
        "scan_behaviour",
        { events }
      );
      return { ...result, latencyMs: performance.now() - start };
    } catch (err: any) {
      return {
        anomalous: false,
        signals: [`scan error: ${err.message}`],
        severity: "low",
        latencyMs: performance.now() - start,
      };
    }
  }

  /**
   * Web Application Firewall check on an outbound URL + headers.
   * Detects SSRF, header injection, and known-bad URL patterns.
   */
  async wafCheck(url: string, headers?: Record<string, string>): Promise<WAFResult> {
    const start = performance.now();

    if (!this.available) {
      return {
        blocked: false,
        severity: "none",
        latencyMs: performance.now() - start,
      };
    }

    try {
      const result = await this.call<Omit<WAFResult, "latencyMs">>(
        "waf_check",
        { url, headers: headers ?? {} }
      );
      return { ...result, latencyMs: performance.now() - start };
    } catch (err: any) {
      return {
        blocked: false,
        severity: "low",
        latencyMs: performance.now() - start,
      };
    }
  }

  // ─── JSON-RPC internals ───────────────────────────────────────────────────

  private call<T>(method: string, params: unknown): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const id = this.nextId++;
      const request: RPCRequest = { id, method, params };

      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`RPC timeout after ${this.rpcTimeoutMs}ms for method "${method}"`));
      }, this.rpcTimeoutMs);

      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
      });

      const line = JSON.stringify(request) + "\n";
      this.proc!.stdin!.write(line);
    });
  }

  private handleResponse(line: string): void {
    let response: RPCResponse;
    try {
      response = JSON.parse(line) as RPCResponse;
    } catch {
      return; // ignore non-JSON lines (e.g. startup messages)
    }

    const pending = this.pending.get(response.id);
    if (!pending) return;

    clearTimeout(pending.timer);
    this.pending.delete(response.id);

    if (response.error) {
      pending.reject(
        new Error(`RPC error ${response.error.code}: ${response.error.message}`)
      );
    } else {
      pending.resolve(response.result);
    }
  }

  private waitForReady(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error("Rust Shield startup timeout")),
        3000
      );

      const rl = createInterface({ input: this.proc!.stdout! });
      rl.once("line", (line) => {
        clearTimeout(timeout);
        rl.close();
        try {
          const msg = JSON.parse(line);
          if (msg.ready) {
            resolve();
          } else {
            reject(new Error(`Unexpected startup message: ${line}`));
          }
        } catch {
          reject(new Error(`Non-JSON startup message: ${line}`));
        }
      });
    });
  }
}

// ─── Convenience singleton ────────────────────────────────────────────────────

let _instance: RustShieldBridge | undefined;

export async function getRustShieldBridge(
  binaryPath?: string
): Promise<RustShieldBridge> {
  if (!_instance) {
    _instance = new RustShieldBridge(binaryPath);
    await _instance.start();
  }
  return _instance;
}

export function resetRustShieldBridge(): void {
  _instance = undefined;
}
