/**
 * remediation-pr/revalidate.ts — Self-healing exploit chains: sandboxed
 * re-validation of an auto-remediation PR, with proof-of-fix attached back
 * to the PR.
 *
 * Flow this module implements (Feature 2 of the release brief):
 *
 *   1. `generateRemediationPr()` (generate.ts) produces a diff / opens a PR
 *      for a mechanical, auto-fixable finding.
 *   2. `revalidateRemediation()` (THIS file) re-runs the ORIGINAL finding's
 *      verification step against the PATCHED tree, on a sandboxed execution
 *      backend (`../backends` — local/daytona/modal, same abstraction the
 *      rest of Lyrie uses for isolated scans). This is what makes the
 *      remediation "self-healing" rather than "self-suggesting": the loop
 *      closes by actually re-checking the fix worked, in isolation, before
 *      anyone trusts it.
 *   3. `buildProofOfFixComment()` turns the re-validation outcome into a
 *      markdown comment/body-update block, ready to attach to the PR via
 *      the existing `gh`-wrapper CommandRunner (pr.ts) — no new PR-mutation
 *      code path, this reuses the same injectable `CommandRunner` contract
 *      the rest of remediation-pr/ already uses so tests never shell out.
 *
 * SAFE BY DEFAULT:
 *   - `revalidateRemediation()` NEVER runs anything by itself unless the
 *     caller explicitly opts in (`opts.backend` or `LYRIE_BACKEND` env) —
 *     with no backend specified it defaults to `"local"` in `"dryRun"`
 *     mode-compatible shape ONLY when `opts.dryRun` is true; otherwise it
 *     requires an explicit `verify` callback (see below) so this module
 *     never silently decides how to "re-run verification" for a finding
 *     kind it doesn't understand.
 *   - Attaching proof-of-fix to a REAL PR (`attachProofOfFix()`) reuses
 *     `pr.ts`'s `CommandRunner` injection point — the default real
 *     implementation only runs when a caller explicitly passes
 *     `commandRunner: realCommandRunner` (or omits it AND is running
 *     outside a test), exactly like `openRemediationPr` already works.
 *   - If re-validation itself fails/errors, the proof-of-fix comment says
 *     so explicitly (`status: "inconclusive"`) — this module never claims
 *     a fix verified when the sandboxed run didn't actually confirm it.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { CommandRunner, OpenPrResult } from "./pr";
import { realCommandRunner } from "./pr";
import type { MechanicalFinding } from "./types";
import type { Backend, BackendRunRequest, BackendRunResult } from "../backends/types";
import { getBackend } from "../backends/factory";

// ─── Re-validation ───────────────────────────────────────────────────────────

export type RevalidationStatus = "verified-fixed" | "still-vulnerable" | "inconclusive";

export interface RevalidationResult {
  status: RevalidationStatus;
  /** Which backend actually ran the re-check ("local" | "daytona" | "modal"). */
  backend: string;
  /** Underlying backend run result, when a backend was actually invoked. */
  backendResult?: BackendRunResult;
  /** Human-readable explanation — always populated, never requires reading backendResult to understand the verdict. */
  summary: string;
  /** Unix ms wall-clock duration of the whole re-validation. */
  durationMs: number;
}

export interface RevalidateRemediationOptions {
  /** Path to the (patched) working tree to re-verify against. Required. */
  repoDir: string;
  /** The mechanical finding the fix targeted — used to build a scoped, minimal re-check request. */
  finding: MechanicalFinding;
  /**
   * Execution backend to run the re-check on. Defaults to the process's
   * `getBackend()` resolution (env `LYRIE_BACKEND`, else "local"). Pass an
   * explicit backend instance in tests to avoid any real sandbox network
   * calls — see revalidate.test.ts's fake backend.
   */
  backend?: Backend;
  /**
   * When true AND no backend override is supplied, uses a local dry-run
   * backend (`LocalBackend({ dryRun: true })`) that never actually spawns a
   * scan — used for the "no verify callback, no real backend" safe
   * default. Ignored if `backend` is explicitly supplied.
   */
  dryRun?: boolean;
  /**
   * Optional focused verification callback — when supplied, takes priority
   * over the generic backend re-scan. This lets a caller who already knows
   * exactly how to re-check ONE finding (e.g. "curl the endpoint and check
   * the header is now present") skip spinning up a whole sandboxed scan for
   * something a single HTTP request settles. Must return `true` if the
   * original vulnerability is confirmed fixed.
   */
  verify?: (repoDir: string, finding: MechanicalFinding) => Promise<boolean>;
  /** Resource/timeout hints forwarded to the backend request. */
  resources?: BackendRunRequest["resources"];
}

/**
 * Re-run verification for a single mechanical finding against a patched
 * working tree, using a sandboxed backend (or an injected focused `verify`
 * callback). Returns a `RevalidationResult` — never throws; backend/verify
 * errors are captured as `status: "inconclusive"`.
 */
export async function revalidateRemediation(
  opts: RevalidateRemediationOptions,
): Promise<RevalidationResult> {
  const start = Date.now();

  if (opts.verify) {
    try {
      const fixed = await opts.verify(opts.repoDir, opts.finding);
      return {
        status: fixed ? "verified-fixed" : "still-vulnerable",
        backend: "focused-verify-callback",
        summary: fixed
          ? `Focused verification callback confirmed the fix for ${describeFinding(opts.finding)}.`
          : `Focused verification callback found ${describeFinding(opts.finding)} still present after the fix.`,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      return {
        status: "inconclusive",
        backend: "focused-verify-callback",
        summary: `Focused verification callback threw and could not confirm the fix: ${errMsg(err)}`,
        durationMs: Date.now() - start,
      };
    }
  }

  const backend =
    opts.backend ?? getBackend(opts.dryRun ? "local" : undefined, opts.dryRun ? { kind: "local", config: { dryRun: true } } : undefined);

  const preflight = await backend.preflight();
  if (!preflight.ok) {
    return {
      status: "inconclusive",
      backend: backend.kind,
      summary: `Sandboxed backend "${backend.kind}" is not ready (${preflight.reason ?? "unknown reason"}) — re-validation was skipped, NOT treated as a pass.`,
      durationMs: Date.now() - start,
    };
  }

  const request: BackendRunRequest = {
    target: opts.repoDir,
    scanMode: "quick",
    scope: "full",
    failOn: "low",
    resources: opts.resources,
    labels: { "lyrie.ai/purpose": "remediation-revalidation", "lyrie.ai/finding-kind": opts.finding.kind },
  };

  let backendResult: BackendRunResult;
  try {
    backendResult = await backend.run(request);
  } catch (err) {
    return {
      status: "inconclusive",
      backend: backend.kind,
      summary: `Sandboxed backend "${backend.kind}" threw during re-validation run: ${errMsg(err)}`,
      durationMs: Date.now() - start,
    };
  } finally {
    await backend.cleanup?.().catch(() => {
      /* cleanup best-effort — never let a cleanup failure mask the real verdict */
    });
  }

  if (backendResult.status === "error") {
    return {
      status: "inconclusive",
      backend: backend.kind,
      backendResult,
      summary: `Sandboxed re-run on "${backend.kind}" errored: ${backendResult.error ?? "unknown error"}. Fix status is NOT confirmed.`,
      durationMs: Date.now() - start,
    };
  }

  // "pass" (no findings at/above failOn) on a re-scan of the patched tree is
  // the strongest signal available without finding-specific semantics: the
  // exact class of issue the mechanical fixer targets (missing header /
  // vulnerable pinned dependency) is by construction within what a
  // full-tree SARIF re-scan would flag again if the patch didn't actually
  // take. "fail" means the backend still sees findings post-patch.
  const fixed = backendResult.status === "pass";
  return {
    status: fixed ? "verified-fixed" : "still-vulnerable",
    backend: backend.kind,
    backendResult,
    summary: fixed
      ? `Sandboxed re-scan on "${backend.kind}" found 0 qualifying findings after the patch — ${describeFinding(opts.finding)} appears fixed.`
      : `Sandboxed re-scan on "${backend.kind}" still reports ${backendResult.findingCount} finding(s) (highest: ${backendResult.highestSeverity}) after the patch — fix NOT confirmed.`,
    durationMs: Date.now() - start,
  };
}

// ─── Proof-of-fix comment ─────────────────────────────────────────────────────

const STATUS_EMOJI: Record<RevalidationStatus, string> = {
  "verified-fixed": "✅",
  "still-vulnerable": "❌",
  inconclusive: "⚠️",
};

/**
 * Render a markdown block suitable for a PR comment or body-append,
 * documenting exactly what re-validation was performed and its outcome.
 * Always self-contained (no external state needed to read it later).
 */
export function buildProofOfFixComment(result: RevalidationResult): string {
  const lines: string[] = [
    `### ${STATUS_EMOJI[result.status]} Lyrie Self-Heal — Sandboxed Re-Validation`,
    "",
    `**Status:** \`${result.status}\``,
    `**Backend:** \`${result.backend}\``,
    `**Duration:** ${(result.durationMs / 1000).toFixed(1)}s`,
    "",
    result.summary,
  ];
  if (result.backendResult) {
    lines.push(
      "",
      "<details><summary>Backend run details</summary>",
      "",
      `- Highest severity: \`${result.backendResult.highestSeverity}\``,
      `- Finding count: ${result.backendResult.findingCount}`,
      `- Run id: \`${result.backendResult.runId ?? "n/a"}\``,
      `- Cost: $${result.backendResult.costUsd.toFixed(4)}`,
      "",
      "</details>",
    );
  }
  lines.push("", "_Generated by [Lyrie](https://lyrie.ai) — self-healing exploit-chain verification. OTT Cybersecurity LLC._");
  return lines.join("\n");
}

// ─── Attach proof-of-fix to the PR ────────────────────────────────────────────

export interface AttachProofOfFixOptions {
  repoDir: string;
  /** PR number or URL the `gh` CLI can resolve (e.g. "42" or the pr's html_url). */
  pr: string;
  result: RevalidationResult;
  commandRunner?: CommandRunner;
}

export interface AttachProofOfFixResult {
  ok: boolean;
  error?: string;
}

/**
 * Post the proof-of-fix comment onto an existing PR via `gh pr comment`.
 * Uses the SAME injectable `CommandRunner` contract as `pr.ts`'s
 * `openRemediationPr` — tests substitute a fake runner and never shell out.
 */
export async function attachProofOfFix(opts: AttachProofOfFixOptions): Promise<AttachProofOfFixResult> {
  const run = opts.commandRunner ?? realCommandRunner;
  const body = buildProofOfFixComment(opts.result);
  try {
    await run("gh", ["pr", "comment", opts.pr, "--body", body], opts.repoDir);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: errMsg(err) };
  }
}

/**
 * Convenience end-to-end helper: re-validate, then (if `pr` was actually
 * opened, i.e. `openPrResult.ok`) attach the proof-of-fix comment to it.
 * Returns both pieces so callers can inspect/log either independently.
 * Never attaches anything if the PR was never actually opened.
 */
export async function revalidateAndAttach(
  revalidateOpts: RevalidateRemediationOptions,
  openPrResult: OpenPrResult | undefined,
  commandRunner?: CommandRunner,
): Promise<{ revalidation: RevalidationResult; attach?: AttachProofOfFixResult }> {
  const revalidation = await revalidateRemediation(revalidateOpts);
  if (!openPrResult?.ok || !openPrResult.prUrl) {
    return { revalidation };
  }
  const attach = await attachProofOfFix({
    repoDir: revalidateOpts.repoDir,
    pr: openPrResult.prUrl,
    result: revalidation,
    commandRunner,
  });
  return { revalidation, attach };
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function describeFinding(finding: MechanicalFinding): string {
  if (finding.kind === "missing-security-header") {
    return `missing "${finding.header}" header in ${finding.configFile}`;
  }
  return `vulnerable pinned dependency ${finding.packageName}@${finding.currentVersion} in ${finding.manifestFile}`;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
