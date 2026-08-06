/**
 * LocalBackend — runs Lyrie scans on the calling host.
 *
 * Default backend; the dry-run path preserves today's exact behavior (empty
 * SARIF, no work). The NON-dry-run path now actually runs a scan: it invokes
 * the real Lyrie OSS-scan pipeline (`runOssScan` — the same
 * attack-surface + multi-language scanner + Stages A–F validator used by
 * `lyrie scan`) against the target working tree and maps the confirmed
 * findings into the unified `BackendRunResult` (status / highestSeverity /
 * findingCount / SARIF).
 *
 * Injectable executor:
 *   The scan is dispatched through an injectable `scanExecutor` callback so
 *   tests can substitute a deterministic executor and never shell out. The
 *   DEFAULT executor is a REAL scan (`defaultLocalScanExecutor`) — NOT a
 *   stub that always returns "pass". Only the explicit `dryRun` config path
 *   short-circuits to an empty result.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  Backend,
  BackendRunRequest,
  BackendRunResult,
  LocalBackendConfig,
} from "./types";
import type { ValidatedFinding } from "../pentest/stages-validator";

// ─── Scan-executor contract ────────────────────────────────────────────────────

/**
 * A concrete scan of a local working tree. Returns the raw confirmed
 * findings; the backend maps them into a BackendRunResult. Injectable so
 * tests never touch the real (heavier) OSS-scan pipeline, but the DEFAULT is
 * a real scan.
 */
export type LocalScanExecutor = (
  request: BackendRunRequest,
  config: LocalBackendConfig,
) => Promise<LocalScanExecutorResult>;

export interface LocalScanExecutorResult {
  /** Confirmed findings from the scan (only `confirmed: true` are counted). */
  findings: ValidatedFinding[];
  /** Number of files actually inspected. */
  filesScanned: number;
  /** Optional pre-rendered SARIF; when omitted the backend synthesizes one. */
  sarif?: string;
  /** Optional markdown summary. */
  markdown?: string;
}

type Severity = BackendRunResult["highestSeverity"];

const SEV_RANK: Record<Severity, number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

const FAIL_ON_RANK: Record<BackendRunRequest["failOn"], number> = {
  none: 0,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

// ─── LocalBackend ──────────────────────────────────────────────────────────────

export class LocalBackend implements Backend {
  readonly kind = "local" as const;
  readonly displayName = "Lyrie Local";

  protected config: LocalBackendConfig;
  private readonly scanExecutor: LocalScanExecutor;

  constructor(config: LocalBackendConfig = {}, scanExecutor?: LocalScanExecutor) {
    this.config = config;
    this.scanExecutor = scanExecutor ?? defaultLocalScanExecutor;
  }

  isConfigured(): boolean {
    // Always available — runs in-process / on-host.
    return true;
  }

  async preflight(): Promise<{ ok: boolean; reason?: string }> {
    return { ok: true };
  }

  async run(request: BackendRunRequest): Promise<BackendRunResult> {
    const start = Date.now();
    const costPerSecond =
      parseFloat(process.env["LYRIE_LOCAL_COST_PER_SECOND"] ?? "0") || 0;

    if (this.config.dryRun) {
      return {
        backend: "local",
        status: "pass",
        highestSeverity: "none",
        findingCount: 0,
        sarif: emptySarif(),
        markdown: "_Lyrie LocalBackend dry-run — no scan performed._",
        runId: `local-dryrun-${start}`,
        durationMs: Date.now() - start,
        costUsd: 0,
        provider: { mode: "dry-run" },
      };
    }

    // ── Real scan path ──────────────────────────────────────────────────────
    let scan: LocalScanExecutorResult;
    try {
      scan = await this.scanExecutor(request, this.config);
    } catch (err) {
      const durationMs = Date.now() - start;
      return {
        backend: "local",
        status: "error",
        highestSeverity: "none",
        findingCount: 0,
        durationMs,
        costUsd: (durationMs / 1000) * costPerSecond,
        error: err instanceof Error ? err.message : String(err),
        provider: { cwd: this.config.cwd ?? request.target },
      };
    }

    const confirmed = scan.findings.filter((f) => f.confirmed);
    const highestSeverity = highestOf(confirmed);
    const failFloor = FAIL_ON_RANK[request.failOn];
    // "fail" when any confirmed finding is at or above the failOn floor.
    const status: BackendRunResult["status"] =
      failFloor > 0 && SEV_RANK[highestSeverity] >= failFloor ? "fail" : "pass";

    const durationMs = Date.now() - start;
    const costUsd = (durationMs / 1000) * costPerSecond;
    if (costPerSecond > 0) {
      console.log(`[local] estimated cost: $${costUsd.toFixed(4)}`);
    }

    return {
      backend: "local",
      status,
      highestSeverity,
      findingCount: confirmed.length,
      sarif: scan.sarif ?? sarifFromFindings(confirmed),
      markdown:
        scan.markdown ??
        `_LocalBackend scan: ${confirmed.length} confirmed finding(s) across ${scan.filesScanned} file(s); highest severity ${highestSeverity}._`,
      runId: `local-${start}`,
      durationMs,
      costUsd,
      provider: {
        cwd: this.config.cwd ?? request.target,
        filesScanned: scan.filesScanned,
      },
    };
  }
}

// ─── Default real scan executor ─────────────────────────────────────────────────

/**
 * Real default: run the Lyrie OSS-scan pipeline against the local target
 * directory (via the `__preCloned` hook so it scans in place rather than
 * cloning). Dynamic import keeps the heavier pentest pipeline off the
 * LocalBackend's import path unless a real scan is actually requested.
 */
export const defaultLocalScanExecutor: LocalScanExecutor = async (request, config) => {
  const { runOssScan } = await import("../pentest/oss-scan/service");
  const dir = config.cwd ?? request.target;

  const result = await runOssScan(
    // repoUrl is ignored on the __preCloned path but validated for shape; use
    // a canonical placeholder so URL validation never rejects an on-disk path.
    { repoUrl: "https://github.com/lyrie-ai/local-scan" },
    {
      __preCloned: { dir, resolvedUrl: `file://${dir}` },
      maxFiles: 5000,
    },
  );

  if ("ok" in result && result.ok === false) {
    throw new Error(`local scan failed: ${result.reason}${result.detail ? ` — ${result.detail}` : ""}`);
  }

  const okResult = result as Exclude<typeof result, { ok: false }>;

  return {
    findings: okResult.findings,
    filesScanned: okResult.filesScanned,
  };
};

// ─── SARIF helpers ───────────────────────────────────────────────────────────

function highestOf(findings: ValidatedFinding[]): Severity {
  let top: Severity = "none";
  for (const f of findings) {
    const sev = f.finding.severity as Severity;
    if (SEV_RANK[sev] > SEV_RANK[top]) top = sev;
  }
  return top;
}

function sarifLevel(sev: string): "error" | "warning" | "note" | "none" {
  switch (sev) {
    case "critical":
    case "high":
      return "error";
    case "medium":
    case "low":
      return "warning";
    case "info":
      return "note";
    default:
      return "none";
  }
}

/** Build a minimal-but-valid SARIF 2.1.0 doc from confirmed findings. */
export function sarifFromFindings(findings: ValidatedFinding[]): string {
  const results = findings.map((v) => {
    const f = v.finding;
    return {
      ruleId: f.id,
      level: sarifLevel(f.severity),
      message: { text: f.title },
      locations: f.file
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: f.line ? { startLine: f.line } : undefined,
              },
            },
          ]
        : [],
      properties: {
        severity: f.severity,
        confidence: v.confidence,
        exploitabilityScore: v.exploitabilityScore,
      },
    };
  });

  return JSON.stringify({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Lyrie Agent",
            informationUri: "https://lyrie.ai",
            organization: "OTT Cybersecurity LLC",
            rules: [],
          },
        },
        results,
      },
    ],
  });
}

/**
 * The smallest valid SARIF 2.1.0 document for empty-result happy-paths.
 * Exported because Daytona/Modal mock paths reuse it.
 */
export function emptySarif(): string {
  return sarifFromFindings([]);
}
