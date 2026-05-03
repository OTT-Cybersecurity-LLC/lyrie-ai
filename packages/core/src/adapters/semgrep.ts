/**
 * Lyrie — Semgrep CE Adapter
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Wraps Semgrep Community Edition (free, no cloud, open-source).
 *
 * Key features:
 *   • Runs `semgrep --config auto --json <target>`
 *   • Parses Semgrep JSON output → AdapterFinding[]
 *   • Supports custom config strings (--config p/owasp-top-ten etc.)
 *   • Graceful degradation: isAvailable()=false if semgrep not installed
 *   • Accepts injected executor for testing (DI pattern)
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { AdapterFinding, AdapterOptions, AdapterResult, ScannerAdapter } from "./adapter-types";
import type { ShellExecutor } from "./nuclei";

const execFileAsync = promisify(execFile);

function defaultExecutor(
  cmd: string,
  args: string[],
  opts?: { timeout?: number; maxBuffer?: number },
): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(cmd, args, {
    timeout: opts?.timeout,
    maxBuffer: opts?.maxBuffer,
  }).catch((err: any) => ({
    stdout: err?.stdout ?? "",
    stderr: err?.stderr ?? "",
  }));
}

// ─── Semgrep JSON output shapes ───────────────────────────────────────────────

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: {
      cve?: string;
      cwe?: string | string[];
      fix?: string;
    };
    fix?: string;
  };
}

interface SemgrepJsonOutput {
  results?: SemgrepResult[];
  version?: string;
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, AdapterFinding["severity"]> = {
  critical: "critical",
  error: "high",
  warning: "medium",
  info: "info",
  low: "low",
};

function mapSeverity(raw?: string): AdapterFinding["severity"] {
  return SEVERITY_MAP[(raw ?? "").toLowerCase()] ?? "info";
}

function firstOf(val: string | string[] | undefined): string | undefined {
  if (!val) return undefined;
  return Array.isArray(val) ? val[0] : val;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

export interface SemgrepOptions extends AdapterOptions {
  /**
   * Semgrep config string. Defaults to "auto".
   * Examples: "auto", "p/owasp-top-ten", "p/secrets", "/path/to/rules/"
   */
  config?: string;
  /** Additional rule paths or config strings. */
  rules?: string[];
}

export class SemgrepAdapter implements ScannerAdapter {
  readonly name = "semgrep";
  readonly version = "ce";

  private readonly exec: ShellExecutor;

  constructor(executor?: ShellExecutor) {
    this.exec = executor ?? defaultExecutor;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { stdout } = await this.exec("semgrep", ["--version"], { timeout: 5_000 });
      return stdout.length > 0 || true; // any response = available
    } catch {
      return false;
    }
  }

  async scan(target: string, options: SemgrepOptions = {}): Promise<AdapterResult> {
    const start = Date.now();

    const config = options.config ?? "auto";
    const args: string[] = [
      "--config", config,
      "--json",
      "--quiet",
      target,
    ];

    for (const rule of options.rules ?? []) {
      args.push("--config", rule);
    }

    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    const { stdout: rawOutput, stderr } = await this.exec("semgrep", args, {
      timeout: options.timeoutMs ?? 180_000,
      maxBuffer: 100 * 1024 * 1024,
    });

    if (!rawOutput && stderr) {
      return {
        findings: [],
        scannerName: this.name,
        scannerVersion: this.version,
        durationMs: Date.now() - start,
        warnings: [`semgrep failed: ${stderr}`],
      };
    }

    const findings = parseSemgrepOutput(rawOutput);

    return {
      findings,
      scannerName: this.name,
      scannerVersion: this.version,
      durationMs: Date.now() - start,
      rawOutput,
    };
  }
}

// ─── Parse Semgrep JSON output ────────────────────────────────────────────────

export function parseSemgrepOutput(raw: string): AdapterFinding[] {
  const findings: AdapterFinding[] = [];

  let parsed: SemgrepJsonOutput;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return findings;
  }

  for (const r of parsed.results ?? []) {
    const extra = r.extra ?? {};
    const metadata = extra.metadata ?? {};

    const id = r.check_id ?? `semgrep-${findings.length + 1}`;
    const title = id.split(".").pop() ?? id;
    const severity = mapSeverity(extra.severity);
    const description = extra.message ?? `Semgrep rule ${id} matched.`;

    const cve = firstOf(metadata.cve);
    const cwe = firstOf(metadata.cwe);

    const location = r.path
      ? { file: r.path, line: r.start?.line }
      : undefined;

    const remediation = extra.fix ?? metadata.fix;

    findings.push({
      id,
      title,
      severity,
      description,
      location,
      cve,
      cwe,
      remediation,
    });
  }

  return findings;
}
