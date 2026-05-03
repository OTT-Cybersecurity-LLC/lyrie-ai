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
 *
 * Why this matters:
 *   Semgrep CE has 20k+ rules covering 30 languages. Lyrie wraps it with
 *   Stages A–F validation + auto-PoC, which is the story that walks straight
 *   at Semgrep's commercial AppSec Platform pitch.
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { AdapterFinding, AdapterOptions, AdapterResult, ScannerAdapter } from "./adapter-types";

const execFileAsync = promisify(execFile);

// ─── Semgrep JSON output shapes ───────────────────────────────────────────────

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: {
      cve?: string;
      cwe?: string | string[];
      owasp?: string | string[];
      references?: string[];
      fix?: string;
      technology?: string[];
    };
    fix?: string;
    lines?: string;
  };
}

interface SemgrepJsonOutput {
  results?: SemgrepResult[];
  errors?: Array<{ message?: string; level?: string }>;
  version?: string;
}

// ─── Severity mapping ─────────────────────────────────────────────────────────
//
// Semgrep uses: ERROR, WARNING, INFO (plus legacy CRITICAL from some rule sets)
//

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
   * Semgrep config string. Defaults to "auto" which uses all available
   * rules from the Semgrep registry.
   * Examples: "auto", "p/owasp-top-ten", "p/secrets", "/path/to/rules/"
   */
  config?: string;
  /** Additional rule paths or config strings. */
  rules?: string[];
}

export class SemgrepAdapter implements ScannerAdapter {
  readonly name = "semgrep";
  readonly version = "ce";

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync("semgrep", ["--version"], { timeout: 5_000 });
      return true;
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

    // Add any extra rule configs
    for (const rule of options.rules ?? []) {
      args.push("--config", rule);
    }

    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    let rawOutput = "";
    try {
      const { stdout } = await execFileAsync("semgrep", args, {
        timeout: options.timeoutMs ?? 180_000,
        maxBuffer: 100 * 1024 * 1024,
      });
      rawOutput = stdout;
    } catch (err: any) {
      // semgrep may exit 1 when findings exist; stdout still has JSON
      rawOutput = err?.stdout ?? "";
      if (!rawOutput) {
        return {
          findings: [],
          scannerName: this.name,
          scannerVersion: this.version,
          durationMs: Date.now() - start,
          warnings: [`semgrep failed: ${err.message}`],
        };
      }
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
