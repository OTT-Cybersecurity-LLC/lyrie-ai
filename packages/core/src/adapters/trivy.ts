/**
 * Lyrie — Trivy Adapter (post-supply-chain-incident edition)
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Wraps the Trivy vulnerability scanner (aquasecurity/trivy).
 *
 * Key features:
 *   • Supports three scan modes: fs | image | repo
 *   • Parses Trivy JSON output → AdapterFinding[]
 *   • Binary verification before trust: hashes the trivy binary and compares
 *     against known-good SHA-256 digests. If mismatch, sets binaryVerified=false
 *     in AdapterResult and emits a warning — but still runs (operator choice).
 *
 * The March 2026 Trivy supply-chain incident (two separate compromises within
 * the same month) demonstrated that even "trusted" scanner binaries must be
 * verified before trusting their output. This adapter is Lyrie's proof-of-
 * concept for "scanner-of-scanners" attestation — the Shield Doctrine applied
 * to third-party tooling.
 *
 * Known-good SHA-256 digests are stored in TRIVY_KNOWN_HASHES below. Add new
 * entries as Trivy ships new signed releases. The primary source is:
 *   https://github.com/aquasecurity/trivy/releases
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { createHash } from "node:crypto";
import { execFile, execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { promisify } from "node:util";

import type { AdapterFinding, AdapterOptions, AdapterResult, ScannerAdapter } from "./adapter-types";

const execFileAsync = promisify(execFile);

// ─── Known-good Trivy binary hashes (SHA-256) ─────────────────────────────────
//
// Populated with officially released Trivy versions as of 2026-05.
// Source: `sha256sum $(which trivy)` after a verified install.
// Add new entries when upgrading Trivy; remove entries only when a
// version is *confirmed* compromised.
//
// NOTE: These are illustrative placeholders. In production, populate from
// the verified Trivy GitHub release checksums file:
//   https://github.com/aquasecurity/trivy/releases/latest
//
export const TRIVY_KNOWN_HASHES: ReadonlySet<string> = new Set([
  // v0.51.x (pre-incident baseline — add real sha256 in production)
  "KNOWN_GOOD_PLACEHOLDER_0_51",
  // v0.52.x
  "KNOWN_GOOD_PLACEHOLDER_0_52",
  // v0.53.x (post-incident clean build)
  "KNOWN_GOOD_PLACEHOLDER_0_53",
]);

// ─── Trivy JSON output shapes ─────────────────────────────────────────────────

interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  FixedVersion?: string;
  PrimaryURL?: string;
  CweIDs?: string[];
  CVSS?: Record<string, unknown>;
}

interface TrivyResult {
  Target?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: Array<{
    ID?: string;
    Title?: string;
    Description?: string;
    Severity?: string;
    Resolution?: string;
    CauseMetadata?: { Provider?: string; StartLine?: number };
  }>;
  Secrets?: Array<{
    RuleID?: string;
    Title?: string;
    Severity?: string;
    StartLine?: number;
    Match?: string;
  }>;
}

interface TrivyJsonOutput {
  SchemaVersion?: number;
  ArtifactName?: string;
  ArtifactType?: string;
  Results?: TrivyResult[];
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, AdapterFinding["severity"]> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
  INFO: "info",
};

function mapSeverity(raw?: string): AdapterFinding["severity"] {
  return SEVERITY_MAP[(raw ?? "").toUpperCase()] ?? "info";
}

// ─── Binary verification ──────────────────────────────────────────────────────

export interface BinaryVerificationResult {
  verified: boolean;
  hash?: string;
  warning?: string;
}

export function hashBinary(binaryPath: string): string {
  const buf = readFileSync(binaryPath);
  return createHash("sha256").update(buf).digest("hex");
}

export function verifyBinaryHash(binaryPath: string): BinaryVerificationResult {
  if (!existsSync(binaryPath)) {
    return {
      verified: false,
      warning: `Trivy binary not found at: ${binaryPath}`,
    };
  }

  let hash: string;
  try {
    hash = hashBinary(binaryPath);
  } catch (err: any) {
    return {
      verified: false,
      warning: `Failed to hash Trivy binary: ${err.message}`,
    };
  }

  if (TRIVY_KNOWN_HASHES.size === 0) {
    // No known-good hashes registered → warn but don't block
    return {
      verified: false,
      hash,
      warning:
        "No known-good Trivy hashes registered. Populate TRIVY_KNOWN_HASHES " +
        "from the official Trivy release checksums to enable binary attestation.",
    };
  }

  if (TRIVY_KNOWN_HASHES.has(hash)) {
    return { verified: true, hash };
  }

  return {
    verified: false,
    hash,
    warning:
      `Trivy binary hash mismatch — possible supply-chain compromise. ` +
      `Observed: ${hash}. ` +
      `Known-good hashes: ${[...TRIVY_KNOWN_HASHES].slice(0, 3).join(", ")}... ` +
      `Proceeding at operator discretion. Verify the Trivy binary independently before trusting results.`,
  };
}

// ─── Resolve trivy binary path ────────────────────────────────────────────────

function resolveTrivy(): string | null {
  try {
    const out = execFileSync("which", ["trivy"], { encoding: "utf-8", timeout: 3_000 }).trim();
    return out || null;
  } catch {
    return null;
  }
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

export interface TrivyOptions extends AdapterOptions {
  /** Scan mode. Default: "fs". */
  mode?: "fs" | "image" | "repo";
  /** Severity levels to include. Default: all. */
  severity?: string[];
  /** Skip binary verification (not recommended). */
  skipVerification?: boolean;
}

export class TrivyAdapter implements ScannerAdapter {
  readonly name = "trivy";
  readonly version = "0.x";

  async isAvailable(): Promise<boolean> {
    return resolveTrivy() !== null;
  }

  /** Verify the Trivy binary hash before trusting it. */
  async verifyBinary(): Promise<BinaryVerificationResult> {
    const binaryPath = resolveTrivy();
    if (!binaryPath) {
      return { verified: false, warning: "trivy not found on PATH" };
    }
    return verifyBinaryHash(binaryPath);
  }

  async scan(target: string, options: TrivyOptions = {}): Promise<AdapterResult> {
    const start = Date.now();
    const mode = options.mode ?? "fs";
    const warnings: string[] = [];
    let binaryVerified: boolean | undefined;

    // ── Binary verification (the Lyrie differentiator) ─────────────────────
    if (!options.skipVerification) {
      const verifyResult = await this.verifyBinary();
      binaryVerified = verifyResult.verified;
      if (!verifyResult.verified && verifyResult.warning) {
        warnings.push(`[Trivy binary verification] ${verifyResult.warning}`);
      }
    }

    const args: string[] = [
      mode,          // fs | image | repo
      target,
      "--format", "json",
      "--quiet",
    ];

    if (options.severity && options.severity.length > 0) {
      args.push("--severity", options.severity.join(","));
    }

    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    let rawOutput = "";
    try {
      const { stdout } = await execFileAsync("trivy", args, {
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 100 * 1024 * 1024,
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
          binaryVerified,
          warnings: [...warnings, `trivy exited with error: ${err.message}`],
        };
      }
    }

    const findings = parseTrivyOutput(rawOutput);

    return {
      findings,
      scannerName: this.name,
      scannerVersion: this.version,
      durationMs: Date.now() - start,
      binaryVerified,
      rawOutput,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }
}

// ─── Parse Trivy JSON output ──────────────────────────────────────────────────

export function parseTrivyOutput(raw: string): AdapterFinding[] {
  const findings: AdapterFinding[] = [];

  let parsed: TrivyJsonOutput;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return findings;
  }

  for (const result of parsed.Results ?? []) {
    const target = result.Target ?? "";

    // Vulnerabilities
    for (const v of result.Vulnerabilities ?? []) {
      findings.push({
        id: v.VulnerabilityID ?? `trivy-vuln-${findings.length + 1}`,
        title: v.Title ?? `${v.PkgName ?? "unknown"} vulnerability`,
        severity: mapSeverity(v.Severity),
        description: v.Description ?? `Vulnerability in ${v.PkgName}.`,
        location: target ? { file: target } : undefined,
        cve: v.VulnerabilityID?.startsWith("CVE-") ? v.VulnerabilityID : undefined,
        cwe: v.CweIDs?.[0],
        remediation: v.FixedVersion ? `Upgrade to ${v.FixedVersion}` : undefined,
      });
    }

    // Misconfigurations
    for (const m of result.Misconfigurations ?? []) {
      const loc = m.CauseMetadata?.StartLine
        ? { file: target, line: m.CauseMetadata.StartLine }
        : target ? { file: target } : undefined;

      findings.push({
        id: m.ID ?? `trivy-misconfig-${findings.length + 1}`,
        title: m.Title ?? "Misconfiguration",
        severity: mapSeverity(m.Severity),
        description: m.Description ?? "Trivy detected a misconfiguration.",
        location: loc,
        remediation: m.Resolution,
      });
    }

    // Secrets
    for (const s of result.Secrets ?? []) {
      findings.push({
        id: s.RuleID ?? `trivy-secret-${findings.length + 1}`,
        title: s.Title ?? "Hardcoded secret",
        severity: mapSeverity(s.Severity),
        description: s.Match
          ? `Secret detected: ${s.Match}`
          : "Trivy detected a hardcoded secret.",
        location: s.StartLine !== undefined ? { file: target, line: s.StartLine } : target ? { file: target } : undefined,
      });
    }
  }

  return findings;
}
