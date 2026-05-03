/**
 * Lyrie — TruffleHog Adapter
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Wraps TruffleHog v3 (trufflesecurity/trufflehog).
 *
 * Key features:
 *   • Runs `trufflehog filesystem <path> --json --no-update`
 *   • Parses TruffleHog DetectorResult JSON-lines → AdapterFinding[]
 *   • Maps every detected secret to an AdapterFinding with
 *     severity=critical for verified secrets, high for unverified
 *   • Adds Lyrie's AI-judgment hint in the finding description
 *     ("this key is in examples/ — likely a placeholder")
 *   • AGPL license: calls the binary only, no vendoring
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { basename, dirname } from "node:path";

import type { AdapterFinding, AdapterOptions, AdapterResult, ScannerAdapter } from "./adapter-types";

const execFileAsync = promisify(execFile);

// ─── TruffleHog JSON output shapes ───────────────────────────────────────────

interface TruffleHogResult {
  DetectorName?: string;
  DetectorType?: number;
  DecoderName?: string;
  Verified?: boolean;
  Raw?: string;
  RawV2?: string;
  Redacted?: string;
  ExtraData?: Record<string, string>;
  StructuredData?: unknown;
  SourceMetadata?: {
    Data?: {
      Filesystem?: {
        file?: string;
        line?: number;
      };
      Git?: {
        commit?: string;
        file?: string;
        line?: number;
        repository?: string;
        author?: string;
        date?: string;
      };
    };
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function extractLocation(r: TruffleHogResult): { file: string; line?: number } | undefined {
  const data = r.SourceMetadata?.Data;
  if (data?.Filesystem?.file) {
    return { file: data.Filesystem.file, line: data.Filesystem.line };
  }
  if (data?.Git?.file) {
    return { file: data.Git.file, line: data.Git.line };
  }
  return undefined;
}

/**
 * Lyrie verdict hint: detect whether a secret looks like a placeholder / example.
 * This is the "AI judgment layer" on top of TruffleHog's mechanical detection.
 */
function detectPlaceholderHint(location?: { file: string; line?: number }, raw?: string): string | undefined {
  if (!location?.file) return undefined;

  const file = location.file.toLowerCase();
  const dir = dirname(file);
  const base = basename(file);

  const isExamplePath =
    dir.includes("example") ||
    dir.includes("sample") ||
    dir.includes("fixture") ||
    dir.includes("test") ||
    dir.includes("mock") ||
    dir.includes("spec") ||
    base.includes(".example") ||
    base.includes(".sample");

  const isPlaceholderValue =
    raw !== undefined &&
    (raw.toLowerCase().includes("your_") ||
      raw.toLowerCase().includes("replace_") ||
      raw.toLowerCase().includes("placeholder") ||
      raw === "AKIAIOSFODNN7EXAMPLE" || // AWS example key
      /^[A-Z_]+$/.test(raw)); // all-caps env var style

  if (isExamplePath) {
    return `Secret is in ${file} — likely an example/fixture placeholder. Confirm before alerting.`;
  }
  if (isPlaceholderValue) {
    return `Secret value looks like a placeholder ("${raw?.slice(0, 20)}…"). Confirm it is live before alerting.`;
  }
  return undefined;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

export class TruffleHogAdapter implements ScannerAdapter {
  readonly name = "trufflehog";
  readonly version = "3.x";

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync("trufflehog", ["--version"], { timeout: 5_000 });
      return true;
    } catch {
      return false;
    }
  }

  async scan(target: string, options: AdapterOptions = {}): Promise<AdapterResult> {
    const start = Date.now();

    const args: string[] = [
      "filesystem",
      target,
      "--json",
      "--no-update",
    ];

    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    let rawOutput = "";
    try {
      const { stdout } = await execFileAsync("trufflehog", args, {
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 50 * 1024 * 1024,
      });
      rawOutput = stdout;
    } catch (err: any) {
      rawOutput = err?.stdout ?? "";
      if (!rawOutput) {
        return {
          findings: [],
          scannerName: this.name,
          scannerVersion: this.version,
          durationMs: Date.now() - start,
          warnings: [`trufflehog failed: ${err.message}`],
        };
      }
    }

    const findings = parseTruffleHogOutput(rawOutput);

    return {
      findings,
      scannerName: this.name,
      scannerVersion: this.version,
      durationMs: Date.now() - start,
      rawOutput,
    };
  }
}

// ─── Parse TruffleHog JSON-lines output ──────────────────────────────────────

export function parseTruffleHogOutput(raw: string): AdapterFinding[] {
  const findings: AdapterFinding[] = [];

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith("{")) continue;

    let parsed: TruffleHogResult;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }

    const detector = parsed.DetectorName ?? "Unknown";
    const verified = parsed.Verified ?? false;
    const raw_val = parsed.Redacted ?? parsed.Raw ?? "";

    const location = extractLocation(parsed);
    const placeholderHint = detectPlaceholderHint(location, raw_val);

    // Verified secrets = critical. Unverified = high.
    const severity: AdapterFinding["severity"] = verified ? "critical" : "high";

    const baseDescription = verified
      ? `Verified live ${detector} secret detected.`
      : `Potential ${detector} secret detected (unverified).`;

    const description = placeholderHint
      ? `${baseDescription} ⚠️ Lyrie note: ${placeholderHint}`
      : baseDescription;

    const id = `trufflehog-${detector.toLowerCase().replace(/[^a-z0-9]/g, "-")}-${findings.length + 1}`;

    findings.push({
      id,
      title: `${detector} secret${verified ? " (verified live)" : ""}`,
      severity,
      description,
      location,
      extra: {
        verified,
        detectorType: parsed.DetectorType,
        decoderName: parsed.DecoderName,
        extraData: parsed.ExtraData,
      },
    });
  }

  return findings;
}
