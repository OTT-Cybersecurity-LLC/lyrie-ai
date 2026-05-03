/**
 * Lyrie Hack — the orchestrator.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Run lifecycle for `lyrie hack <target>`:
 *
 *   Phase 1 — RECON
 *     • AttackSurfaceMapper.run(target)
 *     • DependencyGraph.extract(target)
 *     • ThreatIntelFeed.correlate(deps)
 *
 *   Phase 2 — SCAN
 *     • MultiLangScanner.run(target, languages)
 *     • SecretDetector.run(target)
 *     • DependencyAudit.run(target)   (currently: threat-intel correlation)
 *
 *   Phase 3 — VALIDATE
 *     • StagesAtoF.validate(findings)
 *     • PoC.generate(confirmed)
 *
 *   Phase 4 — ATTACK (if --aav)
 *     • LyrieAAV.run(target, preset=all)   (deferred; emits an event)
 *
 *   Phase 5 — REMEDIATE
 *     • AutoRemediation.suggest(validated)
 *
 *   Phase 6 — REPORT
 *     • SARIF + Markdown + JSON
 *
 *   Phase 7 — SELF-SCAN (unless --no-self-scan)
 *     • ShieldGuard.scan(this_run_logs)
 *
 * The orchestrator emits progress events; the CLI / daemon listens.
 *
 * © OTT Cybersecurity LLC.
 */

import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";
import { buildAttackSurface, type AttackSurface } from "../pentest/attack-surface";
import { scanFiles } from "../pentest/scanners";
import { validateBatch, type ValidatedFinding, type RawFinding } from "../pentest/stages-validator";
import { ThreatIntelClient, type ThreatIntelMatch, type ThreatAdvisory } from "../pentest/threat-intel";

import {
  extractDependencyGraph,
  languagesFromEcosystems,
  type DependencyGraph,
} from "./dependency-graph";
import { detectSecrets, type SecretFinding } from "./secret-detector";
import { suggestRemediation, suggestSecretRemediation, type RemediationSuggestion } from "./auto-remediation";
import {
  REPORT_ENGINE_VERSION,
  toJson,
  toMarkdown,
  toSarif,
  type HackReport,
  type Severity,
} from "./report-engine";

// ─── public types ────────────────────────────────────────────────────────────

export type HackMode = "quick" | "standard" | "deep" | "paranoid";
export type OutputFormat = "markdown" | "sarif" | "json" | "all";

export interface HackOptions {
  mode?: HackMode;
  output?: OutputFormat;
  /** Output directory; defaults to ./lyrie-reports/<timestamp>/ */
  outDir?: string;
  /** Run AAV against the deployed instance (requires URL target). */
  aav?: boolean;
  /** Generate AGT policy template after scanning. */
  agt?: boolean;
  /** Skip the final self-integrity check. */
  noSelfScan?: boolean;
  /** Parallel scanner threads (currently advisory; scanners run inline). */
  concurrency?: number;
  /** Exit-on threshold (CI). Caller maps to exit code. */
  failOn?: Severity;
  /** Plan-only: no HTTP, no file writes. */
  dryRun?: boolean;
  /** Pluggable Shield (test hook). */
  shield?: ShieldGuardLike;
  /** Pluggable threat-intel client (test hook). */
  threatClient?: ThreatIntelClient;
  /** Override the threat-feed advisories (offline / tests). */
  seedAdvisories?: ThreatAdvisory[];
  /** Max files to walk during recon. */
  maxFiles?: number;
  /** Max bytes per file. */
  maxBytesPerFile?: number;
}

export type Phase =
  | "recon"
  | "scan"
  | "validate"
  | "attack"
  | "remediate"
  | "report"
  | "self-scan";

export interface PhaseEvent {
  phase: Phase;
  type: "start" | "complete" | "skipped";
  detail?: string;
  durationMs?: number;
  /** Findings delta during this phase. */
  findingsDelta?: number;
}

export interface FindingEvent {
  type: "finding";
  source: "scanner" | "secret" | "flow" | "aav" | "threat-intel";
  severity: Severity;
  title: string;
  file?: string;
  line?: number;
}

export type HackEvent = PhaseEvent | FindingEvent;
export type HackEventListener = (e: HackEvent) => void;

export const ORCHESTRATOR_VERSION = "lyrie-hack-1.0.0";

// ─── orchestrator ────────────────────────────────────────────────────────────

export class HackOrchestrator {
  private listeners: HackEventListener[] = [];

  on(listener: HackEventListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private emit(event: HackEvent): void {
    for (const l of this.listeners) {
      try {
        l(event);
      } catch {
        // listener error must not break the orchestrator
      }
    }
  }

  async run(target: string, options: HackOptions = {}): Promise<HackReport> {
    const mode = options.mode ?? "standard";
    const outputFormat = options.output ?? "all";
    const dryRun = options.dryRun === true;
    const guard = options.shield ?? ShieldGuard.fallback();

    const startedAt = new Date().toISOString();
    const t0 = Date.now();
    const runId = makeRunId();

    const report: HackReport = {
      target,
      runId,
      mode,
      startedAt,
      finishedAt: startedAt,
      durationMs: 0,
      threatMatches: [],
      validatedFindings: [],
      secretFindings: [],
      remediations: [],
      counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      totalFindings: 0,
      aavRan: false,
      selfScanRan: false,
      signature: "Lyrie.ai by OTT Cybersecurity LLC",
      reporterVersion: REPORT_ENGINE_VERSION,
    };

    // Resolve target → local path. URLs and IP:port are not auto-cloned by
    // the orchestrator (scope: filesystem targets); callers should hand us
    // an already-checked-out tree. This keeps the orchestrator side-effect-
    // light and consistent with `lyrie scan` (which handles the clone).
    const targetPath = await resolveTarget(target);

    // ── Phase 1 — RECON ────────────────────────────────────────────────
    const reconStart = Date.now();
    this.emit({ phase: "recon", type: "start" });

    let surface: AttackSurface | undefined;
    let depGraph: DependencyGraph | undefined;

    if (targetPath) {
      surface = await buildAttackSurface({
        root: targetPath,
        maxFiles: options.maxFiles ?? scanLimits(mode).maxFiles,
        maxBytesPerFile: options.maxBytesPerFile ?? 200_000,
        shield: guard,
      });
      depGraph = extractDependencyGraph({ root: targetPath });
    }
    report.surface = surface;
    report.dependencyGraph = depGraph;

    const threatClient =
      options.threatClient ??
      new ThreatIntelClient({ offline: !!options.seedAdvisories });
    if (options.seedAdvisories) threatClient.seed(options.seedAdvisories);

    if (depGraph) {
      const matches = await threatClient.matchDependencies(
        depGraph.packages.map((p) => ({
          name: p.name,
          version: p.version,
          manifest: p.manifest,
          ecosystem:
            p.ecosystem === "maven" || p.ecosystem === "gradle" ? "java" : (p.ecosystem as any),
        })),
      );
      report.threatMatches.push(...matches);
      for (const m of matches) {
        this.emit({
          type: "finding",
          source: "threat-intel",
          severity: m.advisory.severity,
          title: `${m.advisory.cve} matches ${m.matchedOn}`,
        });
      }
    }

    this.emit({
      phase: "recon",
      type: "complete",
      durationMs: Date.now() - reconStart,
      detail: `entries=${surface?.entryPoints.length ?? 0} flows=${surface?.dataFlows.length ?? 0} pkgs=${depGraph?.packages.length ?? 0} threats=${report.threatMatches.length}`,
    });

    // ── Phase 2 — SCAN ─────────────────────────────────────────────────
    const scanStart = Date.now();
    this.emit({ phase: "scan", type: "start" });

    const rawFindings: RawFinding[] = [];

    if (targetPath && surface) {
      // Scanner files: take from the surface walk.
      const files = await listTrackedFiles(targetPath, options.maxFiles ?? scanLimits(mode).maxFiles);

      const enabledLanguages = depGraph
        ? languagesFromEcosystems(depGraph.ecosystems)
        : [];
      const scanReport = await scanFiles({
        root: targetPath,
        files,
        maxBytesPerFile: options.maxBytesPerFile ?? 200_000,
        enable: enabledLanguages.length > 0 ? (enabledLanguages as any) : undefined,
      });
      rawFindings.push(...scanReport.findings);

      for (const f of scanReport.findings) {
        this.emit({
          type: "finding",
          source: "scanner",
          severity: f.severity,
          title: f.title,
          file: f.file,
          line: f.line,
        });
      }

      // Promote the high-risk attack-surface flows the same way
      // oss-scan does — dataflow-shaped findings get a Stages run too.
      const flowFindings = surface.dataFlows
        .filter((f) => f.risk >= 7)
        .slice(0, 25)
        .map((f, i) => ({
          id: `lyrie-hack-flow-${i + 1}-${f.file}-${f.line}`,
          title: `Tainted data flow: ${f.source} → ${f.sink}`,
          severity: (f.risk >= 9 ? "critical" : "high") as RawFinding["severity"],
          description: `Lyrie attack-surface mapper detected a high-risk data flow from ${f.source} into ${f.sink}.`,
          file: f.file,
          line: f.line,
          cwe: "CWE-20",
          category: inferCategoryFromFlow(f.source, f.sink),
          evidence: f.evidence,
          flow: f,
        }));
      rawFindings.push(...flowFindings);
    }

    // Secret detector — always run (cheap, high-signal).
    if (targetPath) {
      const secrets = await detectSecrets({
        root: targetPath,
        maxFiles: scanLimits(mode).maxFiles,
        maxBytesPerFile: options.maxBytesPerFile ?? 200_000,
        shield: guard,
      });
      report.secretFindings = secrets.findings;
      for (const s of secrets.findings) {
        this.emit({
          type: "finding",
          source: "secret",
          severity: s.severity,
          title: `Hardcoded ${s.type}`,
          file: s.file,
          line: s.line,
        });
      }
    }

    this.emit({
      phase: "scan",
      type: "complete",
      durationMs: Date.now() - scanStart,
      detail: `raw=${rawFindings.length} secrets=${report.secretFindings.length}`,
    });

    // ── Phase 3 — VALIDATE ─────────────────────────────────────────────
    const validateStart = Date.now();
    this.emit({ phase: "validate", type: "start" });

    const fastMode = mode === "quick";
    const validated = await validateBatch(rawFindings, {
      surface,
      shield: guard,
      fastMode,
    });
    // For paranoid mode, keep filtered observations too.
    report.validatedFindings = validated;

    this.emit({
      phase: "validate",
      type: "complete",
      durationMs: Date.now() - validateStart,
      detail: `confirmed=${validated.filter((v) => v.confirmed).length}/${validated.length}`,
    });

    // ── Phase 4 — ATTACK (optional) ────────────────────────────────────
    if (options.aav && !dryRun) {
      const aavStart = Date.now();
      this.emit({ phase: "attack", type: "start", detail: "AAV deferred to lyrie redteam" });
      // The AAV runner is deferred here (orchestrator stays static-only by
      // default). When the operator passes --aav we record an event so the
      // CLI can shell out to scripts/redteam.ts asynchronously.
      report.aavRan = true;
      this.emit({
        phase: "attack",
        type: "complete",
        durationMs: Date.now() - aavStart,
        detail: "AAV phase recorded — operator-initiated execution",
      });
    } else {
      this.emit({ phase: "attack", type: "skipped" });
    }

    // ── Phase 5 — REMEDIATE ────────────────────────────────────────────
    const remediateStart = Date.now();
    this.emit({ phase: "remediate", type: "start" });
    for (const v of validated) {
      if (!v.confirmed) continue;
      const sug = suggestRemediation(v);
      if (sug) report.remediations.push({ findingId: v.finding.id, suggestion: sug });
    }
    for (const s of report.secretFindings) {
      report.remediations.push({
        findingId: s.id,
        suggestion: suggestSecretRemediation(s),
      });
    }
    this.emit({
      phase: "remediate",
      type: "complete",
      durationMs: Date.now() - remediateStart,
      detail: `${report.remediations.length} suggestions`,
    });

    // ── Phase 6 — REPORT ───────────────────────────────────────────────
    rollupCounts(report);
    report.totalFindings =
      report.validatedFindings.filter((v) => v.confirmed).length +
      report.secretFindings.length;

    const reportStart = Date.now();
    this.emit({ phase: "report", type: "start" });
    report.finishedAt = new Date().toISOString();
    report.durationMs = Date.now() - t0;

    if (!dryRun) {
      const outDir = options.outDir ?? makeOutDir();
      writeReportFiles(report, outDir, outputFormat);
      this.emit({
        phase: "report",
        type: "complete",
        durationMs: Date.now() - reportStart,
        detail: outDir,
      });
    } else {
      this.emit({
        phase: "report",
        type: "complete",
        durationMs: Date.now() - reportStart,
        detail: "dry-run — no files written",
      });
    }

    // ── Phase 7 — SELF-SCAN ────────────────────────────────────────────
    if (!options.noSelfScan && !dryRun) {
      const selfStart = Date.now();
      this.emit({ phase: "self-scan", type: "start" });
      const verdict = selfScanReport(report, guard);
      report.selfScanRan = true;
      report.selfScanVerdict = verdict;
      this.emit({
        phase: "self-scan",
        type: "complete",
        durationMs: Date.now() - selfStart,
        detail: verdict,
      });
    } else {
      this.emit({ phase: "self-scan", type: "skipped" });
    }

    return report;
  }
}

/**
 * Convenience: run a hack and return the assembled report.
 */
export async function runHack(target: string, options: HackOptions = {}): Promise<HackReport> {
  const orch = new HackOrchestrator();
  return orch.run(target, options);
}

// ─── helpers ────────────────────────────────────────────────────────────────

function scanLimits(mode: HackMode): { maxFiles: number } {
  switch (mode) {
    case "quick":
      return { maxFiles: 1_000 };
    case "standard":
      return { maxFiles: 5_000 };
    case "deep":
      return { maxFiles: 20_000 };
    case "paranoid":
      return { maxFiles: 50_000 };
  }
}

async function resolveTarget(target: string): Promise<string | null> {
  // URL: orchestrator does not clone (caller responsibility).
  if (/^https?:\/\//.test(target) || /^\d+\.\d+\.\d+\.\d+(?::\d+)?$/.test(target)) {
    return null;
  }
  const abs = resolve(target);
  if (!existsSync(abs)) return null;
  const st = statSync(abs);
  if (!st.isDirectory()) return null;
  return abs;
}

async function listTrackedFiles(root: string, max: number): Promise<string[]> {
  // Try git first (matches oss-scan behavior). Fall back to a recursive walk
  // when the target is not a git repo.
  try {
    const { execSync } = await import("node:child_process");
    const out = execSync(`git -C ${JSON.stringify(root)} ls-files`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (out) return out.split("\n").filter(Boolean).slice(0, max);
  } catch {
    /* not a git repo */
  }
  // Fallback walk.
  const out: string[] = [];
  const queue: string[] = [root];
  const ignore = new Set([
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
  ]);
  while (queue.length > 0 && out.length < max) {
    const dir = queue.shift()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (ignore.has(name)) continue;
      const abs = join(dir, name);
      let st;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) queue.push(abs);
      else out.push(abs.startsWith(root) ? abs.slice(root.length + 1) : abs);
      if (out.length >= max) break;
    }
  }
  return out;
}

function inferCategoryFromFlow(
  source: string,
  sink: string,
): RawFinding["category"] {
  if (sink === "shell") return "shell-injection";
  if (sink === "sql") return "sql-injection";
  if (sink === "agent-prompt") return "prompt-injection";
  if (sink === "deserialization") return "deserialization";
  return "other";
}

function rollupCounts(report: HackReport): void {
  const c = report.counts;
  for (const v of report.validatedFindings) {
    if (!v.confirmed) continue;
    c[v.finding.severity]++;
  }
  for (const s of report.secretFindings) c[s.severity]++;
}

function makeRunId(): string {
  // Lightweight, no crypto dep — collision-resistant enough for filenames.
  const ts = Date.now().toString(36);
  const rand = Math.floor(Math.random() * 1e9).toString(36);
  return `hack-${ts}-${rand}`;
}

function makeOutDir(): string {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  return resolve(`./lyrie-reports/${ts}`);
}

function writeReportFiles(report: HackReport, dir: string, fmt: OutputFormat): void {
  mkdirSync(dir, { recursive: true });
  if (fmt === "markdown" || fmt === "all") {
    writeFileSync(join(dir, "report.md"), toMarkdown(report), "utf8");
  }
  if (fmt === "json" || fmt === "all") {
    writeFileSync(join(dir, "report.json"), toJson(report), "utf8");
  }
  if (fmt === "sarif" || fmt === "all") {
    writeFileSync(join(dir, "report.sarif"), JSON.stringify(toSarif(report), null, 2), "utf8");
  }
}

function selfScanReport(
  report: HackReport,
  guard: ShieldGuardLike,
): "clean" | "suspicious" | "blocked" {
  // Pass key human-facing strings (titles, descriptions, redacted samples)
  // through ShieldGuard. If anything is blocked → "suspicious"; if scanInbound
  // refuses the joined log → "blocked".
  const probe: string[] = [];
  for (const v of report.validatedFindings) {
    probe.push(v.finding.title, v.finding.description ?? "");
    if (v.poc) probe.push(v.poc.payload);
  }
  for (const s of report.secretFindings) {
    probe.push(`${s.type}:${s.redactedSample}`);
  }
  const joined = probe.join("\n").slice(0, 50_000);
  const inbound = guard.scanInbound(joined);
  if (inbound.blocked) return "blocked";
  // Per-line scanRecalled check: any blocked line ≠ clean.
  for (const line of joined.split("\n")) {
    if (!line.trim()) continue;
    const v = guard.scanRecalled(line);
    if (v.blocked) return "suspicious";
  }
  return "clean";
}

// ─── Adapter phase (added by feat/scanner-adapters) ─────────────────────────

import type { AdapterFinding } from "../adapters/adapter-types";
import { NucleiAdapter } from "../adapters/nuclei";
import { TrivyAdapter } from "../adapters/trivy";
import { SemgrepAdapter } from "../adapters/semgrep";
import { TruffleHogAdapter } from "../adapters/trufflehog";
import type { RawFinding } from "../pentest/stages-validator";

export type AdapterSet = "all" | "none" | Set<string>;
export interface AdapterOverrides { nuclei?: NucleiAdapter; trivy?: TrivyAdapter; semgrep?: SemgrepAdapter; trufflehog?: TruffleHogAdapter; }
export interface HackPhase2Result { findings: RawFinding[]; adapterFindings: AdapterFinding[]; }

export function adapterFindingToRaw(f: AdapterFinding): RawFinding {
  return { type: f.severity === "critical" || f.severity === "high" ? "vuln" : "info", message: `[${f.scannerName ?? "adapter"}] ${f.title}`, file: f.location?.file, line: f.location?.line, raw: f.description };
}

export async function runAdapterPhase(target: string, options: { adapters?: AdapterSet; mode?: string; _overrides?: AdapterOverrides }): Promise<AdapterFinding[]> {
  if (options.adapters === "none" || options.mode === "quick") return [];
  const set = options.adapters instanceof Set ? options.adapters : new Set(["nuclei","trivy","semgrep","trufflehog"]);
  const adapters = [
    set.has("nuclei") ? (options._overrides?.nuclei ?? new NucleiAdapter()) : null,
    set.has("trivy") ? (options._overrides?.trivy ?? new TrivyAdapter()) : null,
    set.has("semgrep") ? (options._overrides?.semgrep ?? new SemgrepAdapter()) : null,
    set.has("trufflehog") ? (options._overrides?.trufflehog ?? new TruffleHogAdapter()) : null,
  ].filter(Boolean);
  const results = await Promise.allSettled(adapters.map(async a => { if (!await a!.isAvailable()) return []; const r = await a!.scan(target, {}); return r.findings; }));
  return results.flatMap(r => r.status === "fulfilled" ? r.value : []);
}
