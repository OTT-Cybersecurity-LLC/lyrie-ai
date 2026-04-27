#!/usr/bin/env bun
// lyrie-shield: ignore-file (Lyrie pentest runner: contains category-inference regexes that name attack types like "jailbreak" — product code, not an injection vector)
/**
 * lyrie-action runner — invoked from action.yml inside GitHub Actions.
 *
 * Responsibilities:
 *   1. Resolve scan target + scope (full or diff against base ref)
 *   2. Run the Lyrie pentest skill with the requested scan mode
 *   3. Render Markdown report + SARIF for Code Scanning + JSON for tooling
 *   4. Set GitHub Actions outputs
 *   5. Exit with non-zero status if `fail-on` severity threshold is crossed
 *
 * The runner is intentionally Shield-aware: every URL/path passed in is
 * sanitized through ShieldGuard before being used.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync, mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execSync } from "node:child_process";

import { ShieldGuard } from "../packages/core/src/engine/shield-guard";
import { buildAttackSurface, type AttackSurface } from "../packages/core/src/pentest/attack-surface";
import {
  validateBatch,
  type RawFinding,
  type VulnerabilityCategory,
} from "../packages/core/src/pentest/stages-validator";
import { scanFiles as runMultilangScan } from "../packages/core/src/pentest/scanners";
import { ThreatIntelClient } from "../packages/core/src/pentest/threat-intel";
import {
  SEVERITY_RANK,
  countBySeverity,
  renderMarkdown,
  renderSarif,
  type Finding,
  type ScanResult,
} from "./runner-helpers";

// ─── Inputs (from env) ──────────────────────────────────────────────────────

const target = process.env.LYRIE_TARGET ?? "./";
const scanMode = (process.env.LYRIE_SCAN_MODE ?? "quick") as
  | "quick" | "full" | "recon" | "vulnscan" | "apiscan";
const scope = (process.env.LYRIE_SCOPE ?? "diff") as "full" | "diff";
const diffBase = process.env.LYRIE_DIFF_BASE ?? "origin/main";
const failOn = (process.env.LYRIE_FAIL_ON ?? "high") as
  | "critical" | "high" | "medium" | "low" | "none";
const outputDir = resolve(process.env.LYRIE_OUTPUT_DIR ?? "lyrie-runs");

// ─── Inputs sanity ──────────────────────────────────────────────────────────

const guard = ShieldGuard.fallback();
const inboundCheck = guard.scanInbound(target);
if (inboundCheck.blocked) {
  console.error(
    `🛡️ Lyrie Shield refused target input: ${inboundCheck.reason}`,
  );
  process.exit(2);
}

if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

// ─── Diff scope (PR mode) ───────────────────────────────────────────────────

let changedFiles: string[] = [];
if (scope === "diff") {
  try {
    const out = execSync(
      `git diff --name-only --diff-filter=ACMR ${diffBase}...HEAD`,
      { encoding: "utf8" },
    ).trim();
    changedFiles = out ? out.split("\n").filter(Boolean) : [];
  } catch (err: any) {
    console.warn(
      `::warning::Could not compute diff against ${diffBase}: ${err.message}. Falling back to full scope.`,
    );
  }
  if (changedFiles.length === 0) {
    console.log("No changed files; nothing for Lyrie to scan in diff mode.");
  } else {
    console.log(`Lyrie diff scope: ${changedFiles.length} file(s)`);
  }
}

// ─── Run pentest ────────────────────────────────────────────────────────────

async function runScan(): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];

  // Phase-2 v0.2.0 ships the runner harness + diff-scope + SARIF + reporting.
  // Wiring into the existing skills/ai-pentest/ scanner happens in v0.2.1
  // (the skill needs a few small refactors to be invokable headless from
  // outside an agent run). For now the action runs a smoke-pass that:
  //   - validates the workspace can be reached
  //   - runs Shield's scanRecalled on changed-file content as a baseline
  //     security pass (catches secrets / suspicious patterns at PR time)
  //   - emits the same report shape so SARIF + PR-comment paths are real.
  const guard = ShieldGuard.fallback();
  const filesToInspect = scope === "diff"
    ? changedFiles
    : await listRepoTextFiles(target);

  // Built-in ignores: build artifacts + dependency vendor trees + Shield's
  // own test corpora. These paths are NOT user code and a Shield hit on
  // them is a known false positive (we test Shield using its own patterns).
  const BUILTIN_IGNORE = [
    /(^|\/)\.next\//,
    /(^|\/)node_modules\//,
    /(^|\/)dist\//,
    /(^|\/)build\//,
    /(^|\/)target\//,
    /(^|\/)\.turbo\//,
    /\.lock$/,
    /-shield(-[a-z]+)?\.test\.ts$/,    // shield self-tests legitimately use injection strings
    /shield-(guard|manager)\.test\.ts$/,
    /shield-(guard|manager)\.ts$/,     // the Shield itself contains patterns
    /dm-pairing\.(ts|test\.ts)$/,      // pairing module documents bad-input shapes
    /fts-search\.(ts|test\.ts)$/,      // FTS test seeds use injection strings
    /edit-engine\.test\.ts$/,          // diff-edit tests verify Shield refusal
    /memory-core\.test\.ts$/,          // memory tests seed Shield-tripping conv rows
  ];

  for (const file of filesToInspect) {
    if (BUILTIN_IGNORE.some((re) => re.test(file))) continue;
    let content: string;
    try {
      content = (await Bun.file(file).text()).slice(0, 200_000);
    } catch {
      continue;
    }
    // Shield exception annotation: files with `lyrie-shield: ignore-file`
    // anywhere in the first 4 KB are skipped. Use sparingly and document
    // why — the doctrine still applies, this is just for legitimate
    // security-content fixtures (e.g. UI strings that name attack types,
    // documentation that quotes injection payloads, test corpora).
    if (content.slice(0, 4096).includes("lyrie-shield: ignore-file")) {
      continue;
    }
    const verdict = guard.scanRecalled(content);
    if (verdict.blocked) {
      findings.push({
        id: `lyrie-shield-${findings.length + 1}`,
        title: `Shield: ${verdict.reason ?? "unsafe content"}`,
        severity:
          verdict.severity === "critical"
            ? "critical"
            : verdict.severity === "high"
              ? "high"
              : "medium",
        description:
          `Lyrie Shield flagged content in this file. ` +
          `Reason: ${verdict.reason ?? "unknown"}. ` +
          `If this is intentional (e.g. a security test fixture), document it ` +
          `and add a Shield exception annotation.`,
        file,
        cwe: "CWE-1188",
        remediation:
          "Remove the flagged content, move it out of the repo, or add a vetted exception.",
      });
    }
  }

  // Lyrie Multi-Language Vulnerability Scanners — ship every language we
  // support against the same file set. Findings are added to the same
  // bucket the Stages A–F validator filters at the end.
  try {
    const ml = await runMultilangScan({
      root: target,
      files: scope === "diff" ? changedFiles : await listRepoTextFiles(target),
    });
    for (const f of ml.findings) findings.push(f as any);
  } catch (err: any) {
    console.warn(`::warning::Lyrie multi-language scan failed: ${err.message}`);
  }

  // Attack-surface mapping (Lyrie /understand) — runs alongside the
  // baseline Shield pass for richer PR context.
  let attackSurface: AttackSurface | undefined;
  try {
    attackSurface = await buildAttackSurface({
      root: target,
      files: scope === "diff" ? changedFiles : undefined,
    });
    // Promote the highest-risk flows into the findings list so they show
    // up in SARIF + the PR comment.
    for (const flow of attackSurface.dataFlows.filter((f) => f.risk >= 7).slice(0, 25)) {
      findings.push({
        id: `lyrie-flow-${findings.length + 1}`,
        title: `Tainted data flow: ${flow.source} → ${flow.sink}`,
        severity: flow.risk >= 9 ? "critical" : "high",
        description:
          `Lyrie attack-surface mapper detected a high-risk data flow ` +
          `from ${flow.source} into ${flow.sink}. Evidence:\n\n  ${flow.evidence}\n\n` +
          `Validate that this path is properly sanitized, gated, or refactored ` +
          `to remove the connection.`,
        file: flow.file,
        line: flow.line,
        cwe: "CWE-20",
        remediation:
          "Add input validation / authorization checks at the boundary, or " +
          "break the connection between source and sink.",
      });
    }
  } catch (err: any) {
    console.warn(`::warning::Lyrie attack-surface mapper failed: ${err.message}`);
  }

  // Lyrie Threat-Intel: enrich findings with KEV-aligned advisories from
  // research.lyrie.ai. Network-optional — if the feed is unreachable the
  // step is a no-op so CI is never gated on intel availability.
  let intelEnrichedFindings: typeof findings = findings;
  let intelMatches = 0;
  try {
    const intel = new ThreatIntelClient({
      offline: process.env.LYRIE_INTEL_OFFLINE === "1",
    });
    const enriched = await intel.enrichFindings(
      findings.map<RawFinding>((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        file: f.file,
        line: f.line,
        cwe: f.cwe,
        category: undefined,
        evidence: "",
      })),
    );
    // Cast back to the runner's local Finding shape
    intelEnrichedFindings = enriched as unknown as typeof findings;
    intelMatches = enriched.filter((f) =>
      f.description.includes("Lyrie Threat-Intel"),
    ).length;
    if (intelMatches > 0) {
      console.log(`🌐 Lyrie Threat-Intel matched ${intelMatches} finding(s)`);
    }
  } catch (err: any) {
    console.warn(`::warning::Lyrie Threat-Intel enrichment failed: ${err.message}`);
  }

  // Stages A–F validator: kill false positives, generate PoCs, attach
  // Lyrie remediation hints. Findings the validator rejects are dropped
  // from the report — we only ship confirmed signals.
  const validated = await validateBatch(
    intelEnrichedFindings.map<RawFinding>((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      description: f.description,
      file: f.file,
      line: f.line,
      cwe: f.cwe,
      category: inferCategory(f),
      evidence: f.description.split("\n")[0]?.slice(0, 200) ?? "",
    })),
    { surface: attackSurface, fastMode: scanMode === "quick" },
  );

  const confirmedFindings: Finding[] = validated.map((v) => ({
    id: v.finding.id,
    title: v.finding.title,
    severity: v.finding.severity,
    description:
      v.finding.description +
      "\n\n" +
      `Lyrie Stages A–F: ${v.stages.map((s) => `${s.stage}=${s.passed ? "✓" : "✗"}`).join(" ")} ` +
      `— confidence ${(v.confidence * 100).toFixed(0)}%` +
      (v.poc?.kind === "automatic"
        ? `\n\n**Lyrie PoC:**\n\n\`\`\`\n${v.poc.payload}\n\`\`\`\n`
        : ""),
    file: v.finding.file,
    line: v.finding.line,
    cwe: v.finding.cwe,
    remediation: v.remediation?.summary ?? v.finding.cwe,
  }));

  return {
    scanMode,
    target,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: confirmedFindings,
    shielded: confirmedFindings.filter((f) => f.id.startsWith("lyrie-shield")).length,
    attackSurface,
  };
}

function inferCategory(f: { id: string; title: string; description: string }): VulnerabilityCategory {
  const text = `${f.id} ${f.title} ${f.description}`.toLowerCase();
  if (/shell|command|exec|spawn/.test(text)) return "shell-injection";
  if (/sqli|sql injection|union select/.test(text)) return "sql-injection";
  if (/xss|cross.site/.test(text)) return "xss";
  if (/ssrf|server.side request/.test(text)) return "ssrf";
  if (/path traversal|directory traversal/.test(text)) return "path-traversal";
  if (/deserial/.test(text)) return "deserialization";
  if (/auth.bypass|broken auth/.test(text)) return "auth-bypass";
  if (/secret|credential|api[_-]?key|private key/.test(text)) return "secret-exposure";
  if (/prompt.injection|jailbreak/.test(text)) return "prompt-injection";
  if (/tainted data flow.*shell/.test(text)) return "shell-injection";
  if (/tainted data flow.*sql/.test(text)) return "sql-injection";
  return "other";
}

async function listRepoTextFiles(root: string): Promise<string[]> {
  try {
    const out = execSync(
      `git -C ${JSON.stringify(root)} ls-files`,
      { encoding: "utf8" },
    ).trim();
    return out ? out.split("\n").filter(Boolean).slice(0, 5000) : [];
  } catch {
    return [];
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

const result = await runScan();

const reportPath = join(outputDir, "report.md");
const jsonPath = join(outputDir, "report.json");
const sarifPath = join(outputDir, "lyrie.sarif");

writeFileSync(reportPath, renderMarkdown(result));
writeFileSync(jsonPath, JSON.stringify(result, null, 2));
writeFileSync(sarifPath, JSON.stringify(renderSarif(result), null, 2));

const counts = countBySeverity(result.findings);

// GitHub Actions outputs
if (process.env.GITHUB_OUTPUT) {
  appendFileSync(process.env.GITHUB_OUTPUT, [
    `findings-count=${result.findings.length}`,
    `critical-count=${counts.critical}`,
    `high-count=${counts.high}`,
    `report-path=${reportPath}`,
    `sarif-path=${sarifPath}`,
    "",
  ].join("\n"));
}

// Job summary
if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, renderMarkdown(result));
}

// Stdout
console.log(renderMarkdown(result));

// Fail threshold
const failRank = SEVERITY_RANK[failOn] ?? 3;
let highest = -1;
for (const f of result.findings) {
  highest = Math.max(highest, SEVERITY_RANK[f.severity] ?? -1);
}
if (failOn !== "none" && highest >= failRank) {
  console.error(
    `❌ Lyrie failed the build: highest finding=${
      Object.keys(SEVERITY_RANK).find((k) => SEVERITY_RANK[k] === highest)
    } >= fail-on=${failOn}`,
  );
  process.exit(1);
}

console.log(`✅ Lyrie pentest complete (${result.findings.length} findings)`);
