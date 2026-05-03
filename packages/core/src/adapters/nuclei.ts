/**
 * Lyrie — Nuclei Adapter
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Wraps the Nuclei scanner (projectdiscovery/nuclei).
 *
 * Key features:
 *   • Runs `nuclei -target <target> -json -silent -timeout 30`
 *   • Parses JSON-lines output → AdapterFinding[]
 *   • Graceful degradation: isAvailable()=false if nuclei not installed
 *   • Optional template list and severity filter
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import type { AdapterFinding, AdapterOptions, AdapterResult, ScannerAdapter } from "./adapter-types";

const execFileAsync = promisify(execFile);

// ─── Nuclei JSON output shapes ────────────────────────────────────────────────

interface NucleiJsonResult {
  "template-id"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    classification?: {
      "cve-id"?: string | string[];
      "cwe-id"?: string | string[];
    };
    remediation?: string;
  };
  host?: string;
  "matched-at"?: string;
  "extracted-results"?: string[];
  timestamp?: string;
  "curl-command"?: string;
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, AdapterFinding["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "info",
};

function mapSeverity(raw?: string): AdapterFinding["severity"] {
  return SEVERITY_MAP[(raw ?? "").toLowerCase()] ?? "info";
}

function firstOf(val: string | string[] | undefined): string | undefined {
  if (!val) return undefined;
  return Array.isArray(val) ? val[0] : val;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

export interface NucleiOptions extends AdapterOptions {
  /** Specific template ids or paths to run. */
  templates?: string[];
  /** Only report findings at these severities. Default: all. */
  severity?: string[];
}

export class NucleiAdapter implements ScannerAdapter {
  readonly name = "nuclei";
  readonly version = "3.x";

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync("nuclei", ["-version"], { timeout: 5_000 });
      return true;
    } catch {
      return false;
    }
  }

  async scan(target: string, options: NucleiOptions = {}): Promise<AdapterResult> {
    const start = Date.now();

    const args: string[] = [
      "-target", target,
      "-json",
      "-silent",
      "-timeout", "30",
    ];

    if (options.templates && options.templates.length > 0) {
      for (const t of options.templates) {
        args.push("-t", t);
      }
    }

    if (options.severity && options.severity.length > 0) {
      args.push("-severity", options.severity.join(","));
    }

    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    let rawOutput = "";
    try {
      const { stdout } = await execFileAsync("nuclei", args, {
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 50 * 1024 * 1024,
      });
      rawOutput = stdout;
    } catch (err: any) {
      // nuclei exits non-zero when it finds issues; stdout still has the JSON
      rawOutput = err?.stdout ?? "";
    }

    const findings = parseNucleiOutput(rawOutput);

    return {
      findings,
      scannerName: this.name,
      scannerVersion: this.version,
      durationMs: Date.now() - start,
      rawOutput,
    };
  }
}

// ─── Parse nuclei JSON-lines output ──────────────────────────────────────────

export function parseNucleiOutput(raw: string): AdapterFinding[] {
  const findings: AdapterFinding[] = [];

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith("{")) continue;

    let parsed: NucleiJsonResult;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }

    const info = parsed.info ?? {};
    const classification = info.classification ?? {};

    const id = parsed["template-id"] ?? `nuclei-${findings.length + 1}`;
    const title = info.name ?? id;
    const severity = mapSeverity(info.severity);
    const description = info.description ?? `Nuclei template ${id} matched target.`;

    const cve = firstOf(classification["cve-id"]);
    const cwe = firstOf(classification["cwe-id"]);

    const matchedAt = parsed["matched-at"] ?? parsed.host;
    const location = matchedAt
      ? { file: matchedAt }
      : undefined;

    findings.push({
      id,
      title,
      severity,
      description,
      location,
      cve,
      cwe,
      remediation: info.remediation,
    });
  }

  return findings;
}
