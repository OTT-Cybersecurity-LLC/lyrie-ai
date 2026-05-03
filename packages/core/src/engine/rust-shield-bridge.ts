/**
 * RustShieldBridge — TypeScript ↔ Rust LyrieShield binary bridge.
 *
 * Spawns the compiled `lyrie-shield` binary and communicates via
 * newline-delimited JSON-RPC over stdin/stdout.
 *
 * Binary search order (first found wins):
 *   1. packages/shield/target/release/lyrie-shield   (dev build)
 *   2. ~/.lyrie/bin/lyrie-shield                      (installed)
 *   3. $PATH                                           (system install)
 *
 * Graceful degradation: if the binary is not found or fails to start,
 * isAvailable() returns false and all scan methods return clean/safe
 * results so the agent continues operating with the TypeScript-only shield.
 *
 * Protocol (newline-delimited JSON-RPC):
 *   Request:  {"id":1,"method":"scan_file","params":{"path":"...","content":"..."}}
 *   Response: {"id":1,"result":{"clean":true,"threats":[],"latency_ms":0.8}}
 *   Error:    {"id":1,"error":"message"}
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { type ChildProcess, spawn } from "child_process";
import { existsSync } from "fs";
import { resolve as resolvePath, join } from "path";
import { homedir } from "os";
import { createInterface } from "readline";

// ─── Public Types ─────────────────────────────────────────────────────────────

export interface ScanResult {
  clean: boolean;
  threats: string[];
  latencyMs: number;
}

export interface BehaviorReport {
  suspicious: boolean;
  threats: string[];
  latencyMs: number;
}

/** Minimal shape of a ToolCall for behavioral analysis */
export interface ToolCallRecord {
  tool: string;
  args?: Record<string, unknown>;
}

// ─── Internal ─────────────────────────────────────────────────────────────────

interface RpcRequest {
  id: number;
  method: string;
  params: Record<string, unknown>;
}

interface RpcResponse {
  id: number;
  result?: unknown;
  error?: string;
}

type PendingCallback = (response: RpcResponse) => void;

// ─── Bridge ───────────────────────────────────────────────────────────────────

export class RustShieldBridge {
  private proc: ChildProcess | null = null;
  private available = false;
  private nextId = 1;
  private pending: Map<number, PendingCallback> = new Map();
  private readonly callTimeoutMs: number;

  constructor(options?: { callTimeoutMs?: number }) {
    this.callTimeoutMs = options?.callTimeoutMs ?? 5000;
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  async init(): Promise<void> {
    const binaryPath = this.findBinary();
    if (!binaryPath) {
      console.debug(
        "[RustShieldBridge] lyrie-shield binary not found — running without Rust acceleration"
      );
      this.available = false;
      return;
    }

    try {
      await this.spawnProcess(binaryPath);
      this.available = true;
      console.log(`[RustShieldBridge] 🦀 Rust shield online (${binaryPath})`);
    } catch (err: any) {
      console.warn(`[RustShieldBridge] Failed to start binary: ${err.message}`);
      this.available = false;
    }
  }

  async shutdown(): Promise<void> {
    if (this.proc) {
      this.proc.stdin?.end();
      this.proc.kill("SIGTERM");
      this.proc = null;
    }
    this.available = false;
    // Reject all pending calls
    for (const [id, cb] of this.pending) {
      cb({ id, error: "Bridge shut down" });
    }
    this.pending.clear();
  }

  isAvailable(): boolean {
    return this.available;
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Scan a file write for malware signatures BEFORE it touches disk.
   */
  async scanFileWrite(path: string, content: string): Promise<ScanResult> {
    if (!this.available) return cleanResult();
    try {
      const raw = await this.call("scan_file", { path, content });
      return normalizeScanResult(raw);
    } catch (err: any) {
      console.debug(`[RustShieldBridge] scanFileWrite error: ${err.message}`);
      return cleanResult();
    }
  }

  /**
   * Behavioral analysis: is this sequence of tool calls suspicious?
   */
  async analyzeToolSequence(calls: ToolCallRecord[]): Promise<BehaviorReport> {
    if (!this.available) return cleanBehaviorReport();
    try {
      const raw = await this.call("analyze_tool_sequence", { calls });
      return normalizeBehaviorReport(raw);
    } catch (err: any) {
      console.debug(`[RustShieldBridge] analyzeToolSequence error: ${err.message}`);
      return cleanBehaviorReport();
    }
  }

  /**
   * WAF on outbound HTTP: scan request before it goes out.
   */
  async scanOutboundRequest(
    url: string,
    headers: Record<string, string>,
    body?: string
  ): Promise<ScanResult> {
    if (!this.available) return cleanResult();
    try {
      const raw = await this.call("scan_outbound_request", { url, headers, body: body ?? "" });
      return normalizeScanResult(raw);
    } catch (err: any) {
      console.debug(`[RustShieldBridge] scanOutboundRequest error: ${err.message}`);
      return cleanResult();
    }
  }

  // ─── Internal — Binary Discovery ───────────────────────────────────────────

  private findBinary(): string | null {
    const candidates = [
      // 1. Dev build inside the monorepo
      resolvePath(
        join(__dirname, "../../../../shield/target/release/lyrie-shield")
      ),
      // Also try relative to the packages dir (compiled from CWD)
      resolvePath(
        join(process.cwd(), "packages/shield/target/release/lyrie-shield")
      ),
      // 2. User-installed
      join(homedir(), ".lyrie", "bin", "lyrie-shield"),
      // 3. PATH (checked last; existsSync won't find it so we check separately)
    ];

    for (const p of candidates) {
      if (existsSync(p)) return p;
    }

    // 3. Try PATH via `which`/`command -v`
    try {
      const { execSync } = require("child_process");
      const found = execSync("command -v lyrie-shield 2>/dev/null", {
        encoding: "utf-8",
        timeout: 2000,
      }).trim();
      if (found) return found;
    } catch {
      // not in PATH
    }

    return null;
  }

  // ─── Internal — Process Management ─────────────────────────────────────────

  private async spawnProcess(binaryPath: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const proc = spawn(binaryPath, ["rpc"], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env },
      });

      proc.on("error", (err) => {
        this.available = false;
        reject(err);
      });

      proc.on("exit", (code) => {
        if (this.available) {
          console.warn(`[RustShieldBridge] process exited with code ${code}; disabling`);
          this.available = false;
          // Fail all pending
          for (const [id, cb] of this.pending) {
            cb({ id, error: `Process exited (code ${code})` });
          }
          this.pending.clear();
        }
      });

      // Read responses line-by-line
      const rl = createInterface({ input: proc.stdout! });
      rl.on("line", (line) => {
        line = line.trim();
        if (!line) return;
        try {
          const resp: RpcResponse = JSON.parse(line);
          const cb = this.pending.get(resp.id);
          if (cb) {
            this.pending.delete(resp.id);
            cb(resp);
          }
        } catch {
          console.debug(`[RustShieldBridge] bad JSON from binary: ${line}`);
        }
      });

      proc.stderr?.on("data", (chunk: Buffer) => {
        const msg = chunk.toString().trim();
        if (msg) console.debug(`[RustShieldBridge] stderr: ${msg}`);
      });

      this.proc = proc;

      // Verify the process is alive with a status call
      setTimeout(async () => {
        try {
          await this.call("status", {});
          resolve();
        } catch (err: any) {
          reject(err);
        }
      }, 100);
    });
  }

  // ─── Internal — RPC ────────────────────────────────────────────────────────

  private call(method: string, params: Record<string, unknown>): Promise<unknown> {
    return new Promise<unknown>((resolve, reject) => {
      if (!this.proc || !this.proc.stdin || this.proc.stdin.destroyed) {
        return reject(new Error("Process not running"));
      }

      const id = this.nextId++;
      const request: RpcRequest = { id, method, params };
      const line = JSON.stringify(request) + "\n";

      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`RPC timeout: ${method} (${this.callTimeoutMs}ms)`));
      }, this.callTimeoutMs);

      this.pending.set(id, (resp) => {
        clearTimeout(timer);
        if (resp.error) {
          reject(new Error(`RPC error: ${resp.error}`));
        } else {
          resolve(resp.result);
        }
      });

      this.proc.stdin.write(line, "utf-8", (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(new Error(`stdin write failed: ${err.message}`));
        }
      });
    });
  }
}

// ─── Normalizers & Defaults ───────────────────────────────────────────────────

function cleanResult(): ScanResult {
  return { clean: true, threats: [], latencyMs: 0 };
}

function cleanBehaviorReport(): BehaviorReport {
  return { suspicious: false, threats: [], latencyMs: 0 };
}

function normalizeScanResult(raw: unknown): ScanResult {
  if (!raw || typeof raw !== "object") return cleanResult();
  const r = raw as Record<string, unknown>;
  return {
    clean: r.clean === true,
    threats: Array.isArray(r.threats) ? (r.threats as string[]) : [],
    latencyMs: typeof r.latency_ms === "number" ? r.latency_ms : 0,
  };
}

function normalizeBehaviorReport(raw: unknown): BehaviorReport {
  if (!raw || typeof raw !== "object") return cleanBehaviorReport();
  const r = raw as Record<string, unknown>;
  return {
    suspicious: r.suspicious === true,
    threats: Array.isArray(r.threats) ? (r.threats as string[]) : [],
    latencyMs: typeof r.latency_ms === "number" ? r.latency_ms : 0,
  };
}
