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
 *   • Accepts injected executor + hasher for testing (DI pattern)
 *
 * The March 2026 Trivy supply-chain incident (two separate compromises within
 * the same month) demonstrated that even "trusted" scanner binaries must be
 * verified before trusting their output. This adapter is Lyrie's proof-of-
 * concept for "scanner-of-scanners" attestation — the Shield Doctrine applied
 * to third-party tooling.
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { createHash } from "node:crypto";
import { execFile, execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { promisify } from "node:util";

import type { AdapterFinding, AdapterOptions, AdapterResult, ScannerAdapter } from "./adapter-types";
import type { ShellExecutor } from "./nuclei";

const execFileAsync = promisify(execFile);

// ─── Known-good Trivy binary hashes (SHA-256) ─────────────────────────────────
//
// In production, populate from verified Trivy GitHub release checksums:
//   https://github.com/aquasecurity/trivy/releases/latest
//
// These placeholders must be replaced with real SHA-256 values before deploying.
// The adapter warns (never silently trusts) when no known-good hash matches.
//
export const TRIVY_KNOWN_HASHES: ReadonlySet<string> = new Set([
  // v0.51.x baseline — replace with real sha256 before production use
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
  CweIDs?: string[];
}

interface TrivyResult {
  Target?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: Array<{
    ID?: string;
    Title?: string;
    Description?: string;
    Severity?: string;
    Resolution?: string;
    CauseMetadata?: { StartLine?: number };
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

/** Injectable binary hasher for testing. */
export type BinaryHasher = (binaryPath: string) => string;

export function defaultHasher(binaryPath: string): string {
  const buf = readFileSync(binaryPath);
  return createHash("sha256").update(buf).digest("hex");
}

export function verifyBinaryHash(
  binaryPath: string,
  knownHashes: ReadonlySet<string> = TRIVY_KNOWN_HASHES,
  hasher: BinaryHasher = defaultHasher,
  existsCheck: (p: string) => boolean = existsSync,
): BinaryVerificationResult {
  if (!existsCheck(binaryPath)) {
    return {
      verified: false,
      warning: `Trivy binary not found at: ${binaryPath}`,
    };
  }

  let hash: string;
  try {
    hash = hasher(binaryPath);
  } catch (err: any) {
    return {
      verified: false,
      warning: `Failed to hash Trivy binary: ${err.message}`,
    };
  }

  if (knownHashes.size === 0 || [...knownHashes].every(h => h.startsWith("KNOWN_GOOD_PLACEHOLDER"))) {
    // Placeholder hashes registered — warn operator to populate real hashes
    return {
      verified: false,
      hash,
      warning:
        "TRIVY_KNOWN_HASHES contains only placeholder values. " +
        "Populate from the official Trivy release checksums to enable binary attestation: " +
        "https://github.com/aquasecurity/trivy/releases/latest",
    };
  }

  if (knownHashes.has(hash)) {
    return { verified: true, hash };
  }

  return {
    verified: false,
    hash,
    warning:
      `Trivy binary hash mismatch — possible supply-chain compromise. ` +
      `Observed: ${hash}. ` +
      `Verify the Trivy binary independently before trusting its results.`,
  };
}

// ─── Resolve trivy binary path ────────────────────────────────────────────────

export type WhichResolver = (binary: string) => string | null;

export function defaultWhichResolver(binary: string): string | null {
  try {
    const out = execFileSync("which", [binary], { encoding: "utf-8", timeout: 3_000 }).trim();
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

  private readonly exec: ShellExecutor;
  private readonly which: WhichResolver;
  private readonly hasher: BinaryHasher;
  private readonly knownHashes: ReadonlySet<string>;
  private readonly existsCheck: (p: string) => boolean;

  constructor(opts?: {
    executor?: ShellExecutor;
    whichResolver?: WhichResolver;
    hasher?: BinaryHasher;
    knownHashes?: ReadonlySet<string>;
    /** Override existsSync for testing. Default: real fs.existsSync */
    existsCheck?: (p: string) => boolean;
  }) {
    this.exec = opts?.executor ?? this._defaultExec.bind(this);
    this.which = opts?.whichResolver ?? defaultWhichResolver;
    this.hasher = opts?.hasher ?? defaultHasher;
    this.knownHashes = opts?.knownHashes ?? TRIVY_KNOWN_HASHES;
    this.existsCheck = opts?.existsCheck ?? existsSync;
  }

  private async _defaultExec(
    cmd: string,
    args: string[],
    execOpts?: { timeout?: number; maxBuffer?: number },
  ): Promise<{ stdout: string; stderr: string }> {
    return execFileAsync(cmd, args, {
      timeout: execOpts?.timeout,
      maxBuffer: execOpts?.maxBuffer,
    }).catch((err: any) => ({
      stdout: err?.stdout ?? "",
      stderr: err?.stderr ?? "",
    }));
  }

  async isAvailable(): Promise<boolean> {
    return this.which("trivy") !== null;
  }

  /** Verify the Trivy binary hash before trusting it. */
  async verifyBinary(): Promise<BinaryVerificationResult> {
    const binaryPath = this.which("trivy");
    if (!binaryPath) {
      return { verified: false, warning: "trivy not found on PATH" };
    }
    return verifyBinaryHash(binaryPath, this.knownHashes, this.hasher, this.existsCheck);
  }

  async scan(target: string, options: TrivyOptions = {}): Promise<AdapterResult> {
    const start = Date.now();
    const mode = options.mode ?? "fs";
    const warnings: string[] = [];
    let binaryVerified: boolean | undefined;

    // ── Binary verification (the Lyrie differentiator) ─────────────────────
    // Every invocation verifies the trivy binary hash before trusting output.
    // If the hash doesn't match a known-good value, we still run the scan
    // but set binaryVerified=false so the operator can decide how to act.
    // This was designed specifically in response to the March 2026 Trivy
    // supply-chain incident where the binary was compromised twice.
    if (!options.skipVerification) {
      const verifyResult = await this.verifyBinary();
      binaryVerified = verifyResult.verified;
      if (!verifyResult.verified && verifyResult.warning) {
        warnings.push(`[Trivy binary verification] ${verifyResult.warning}`);
      }
    }

    const args: string[] = [
      mode,
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

    const { stdout: rawOutput } = await this.exec("trivy", args, {
      timeout: options.timeoutMs ?? 120_000,
      maxBuffer: 100 * 1024 * 1024,
    });

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

    for (const s of result.Secrets ?? []) {
      findings.push({
        id: s.RuleID ?? `trivy-secret-${findings.length + 1}`,
        title: s.Title ?? "Hardcoded secret",
        severity: mapSeverity(s.Severity),
        description: s.Match ? `Secret detected: ${s.Match}` : "Trivy detected a hardcoded secret.",
        location: s.StartLine !== undefined
          ? { file: target, line: s.StartLine }
          : target ? { file: target } : undefined,
      });
    }
  }

  return findings;
}
