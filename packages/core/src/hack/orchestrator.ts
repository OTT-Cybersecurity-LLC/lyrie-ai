/**
 * Lyrie Hack — Orchestrator
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Run lifecycle for `lyrie hack <target>`.
 *
 * Phase 2 — SCAN includes optional external scanner adapters:
 *   • NucleiAdapter   (web vulnerability templates — 26.9k⭐ ecosystem)
 *   • TrivyAdapter    (container/fs/repo CVEs + binary verification)
 *   • SemgrepAdapter  (SAST, 30 languages, 20k+ rules)
 *   • TruffleHogAdapter (secret detection with Lyrie AI judgment layer)
 *
 * CLI adapter flags:
 *   lyrie hack <target> --adapters all         # all available
 *   lyrie hack <target> --adapters nuclei,semgrep
 *   lyrie hack <target> --no-adapters          # skip external scanners
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import type { RawFinding } from "../pentest/stages-validator";
import type { AdapterFinding, AdapterResult } from "../adapters/adapter-types";
import { NucleiAdapter } from "../adapters/nuclei";
import { TrivyAdapter } from "../adapters/trivy";
import { SemgrepAdapter } from "../adapters/semgrep";
import { TruffleHogAdapter } from "../adapters/trufflehog";

// ─── Public types ─────────────────────────────────────────────────────────────

export type HackMode = "quick" | "standard" | "deep" | "paranoid";
export type AdapterSet = "all" | "none" | Set<string>;

export interface HackOptions {
  mode?: HackMode;
  /**
   * Which external scanner adapters to invoke in Phase 2.
   *  "all"  — run every adapter that isAvailable() (default in standard/deep/paranoid)
   *  "none" — skip all external adapters (--no-adapters flag)
   *  Set    — run only the named adapters e.g. new Set(["nuclei","semgrep"])
   */
  adapters?: AdapterSet;
  /** Injected adapters for testing (overrides real binaries). */
  _adapterOverrides?: Partial<AdapterOverrides>;
}

export interface AdapterOverrides {
  nuclei: NucleiAdapter;
  trivy: TrivyAdapter;
  semgrep: SemgrepAdapter;
  trufflehog: TruffleHogAdapter;
}

export interface HackPhase2Result {
  /** Raw findings from built-in scanner. */
  builtinFindings: RawFinding[];
  /** Findings emitted by external adapters, converted to RawFinding. */
  adapterFindings: RawFinding[];
  /** Raw adapter results (for reporting / binaryVerified warnings). */
  adapterResults: AdapterResult[];
}

// ─── Adapter finding → RawFinding conversion ─────────────────────────────────

const SEVERITY_MAP: Record<AdapterFinding["severity"], RawFinding["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

export function adapterFindingToRaw(
  f: AdapterFinding,
  source: string,
): RawFinding {
  return {
    id: `${source}-${f.id}`,
    title: f.title,
    severity: SEVERITY_MAP[f.severity] ?? "info",
    description: f.description,
    file: f.location?.file,
    line: f.location?.line,
    cwe: f.cwe,
    category: "other",
  };
}

// ─── Adapter selection logic ──────────────────────────────────────────────────

function shouldRunAdapter(name: string, adapters: AdapterSet): boolean {
  if (adapters === "none") return false;
  if (adapters === "all") return true;
  return adapters.has(name);
}

// ─── Phase 2 — external adapter dispatch ─────────────────────────────────────

/**
 * Run Phase 2 external scanner adapters.
 *
 * Adapters run when:
 *   1. options.adapters includes the adapter (or is "all")
 *   2. The adapter's isAvailable() is true
 *   3. mode is not "quick" (quick = built-in scanner only, no external tools)
 *
 * Trivy note: The Trivy adapter always verifies the trivy binary hash before
 * trusting its output (supply-chain incident defence). A hash mismatch sets
 * binaryVerified=false and emits a warning in AdapterResult.warnings, but
 * does NOT stop the scan — the operator decides whether to act on those results.
 * This is Lyrie's "scanner-of-scanners" attestation model.
 */
export async function runAdapterPhase(
  target: string,
  options: HackOptions,
): Promise<HackPhase2Result> {
  const mode = options.mode ?? "standard";
  const adapterSet: AdapterSet =
    options.adapters ??
    (mode === "quick" ? "none" : "all");

  const overrides = options._adapterOverrides ?? {};

  const nuclei = overrides.nuclei ?? new NucleiAdapter();
  const trivy = overrides.trivy ?? new TrivyAdapter();
  const semgrep = overrides.semgrep ?? new SemgrepAdapter();
  const trufflehog = overrides.trufflehog ?? new TruffleHogAdapter();

  const adapterResults: AdapterResult[] = [];
  const adapterFindings: RawFinding[] = [];

  if (shouldRunAdapter("nuclei", adapterSet) && await nuclei.isAvailable()) {
    const result = await nuclei.scan(target);
    adapterResults.push(result);
    adapterFindings.push(...result.findings.map(f => adapterFindingToRaw(f, "nuclei")));
  }

  if (shouldRunAdapter("trivy", adapterSet) && await trivy.isAvailable()) {
    const result = await trivy.scan(target, { mode: "fs" });
    adapterResults.push(result);
    adapterFindings.push(...result.findings.map(f => adapterFindingToRaw(f, "trivy")));
  }

  if (shouldRunAdapter("semgrep", adapterSet) && await semgrep.isAvailable()) {
    const result = await semgrep.scan(target);
    adapterResults.push(result);
    adapterFindings.push(...result.findings.map(f => adapterFindingToRaw(f, "semgrep")));
  }

  if (shouldRunAdapter("trufflehog", adapterSet) && await trufflehog.isAvailable()) {
    const result = await trufflehog.scan(target);
    adapterResults.push(result);
    adapterFindings.push(...result.findings.map(f => adapterFindingToRaw(f, "trufflehog")));
  }

  return {
    builtinFindings: [],
    adapterFindings,
    adapterResults,
  };
}
