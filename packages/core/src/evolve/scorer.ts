/**
 * Lyrie LyrieEvolve — Task Outcome Scoring System
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Records and scores task outcomes across Lyrie domains. Scored outcomes
 * feed the Dream Cycle, skill extraction, and Contexture Layer.
 *
 * Score values:
 *   0    — failed / rejected / harmful
 *   0.5  — partial / ambiguous
 *   1    — success / confirmed value
 *
 * © OTT Cybersecurity LLC — All rights reserved.
 */

import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";

// ─── Public types ─────────────────────────────────────────────────────────────

export type Domain = "cyber" | "seo" | "trading" | "code" | "general";
export type Score = 0 | 0.5 | 1;

/** Per-domain signals used to compute a score. */
export interface CyberSignals {
  /** Vulnerability confirmed via Stages A–F. */
  confirmed?: boolean;
  /** Finding was false-positive (reduces score). */
  falsePositive?: boolean;
  /** Shield blocked a malicious payload (positive signal). */
  shieldBlocked?: boolean;
  /** PoC generated automatically. */
  pocGenerated?: boolean;
  /** Remediation patch applied. */
  patchApplied?: boolean;
}

export interface SeoSignals {
  /** Keywords ranked on first page. */
  keywordsRanked?: number;
  /** Content published. */
  contentPublished?: boolean;
  /** Backlinks acquired. */
  backlinksAcquired?: number;
  /** Audit issues resolved. */
  issuesResolved?: number;
  /** Page speed improved (ms saved). */
  speedImprovementMs?: number;
}

export interface TradingSignals {
  /** PnL ratio (positive = profitable). */
  pnlRatio?: number;
  /** Trade was closed profitably. */
  profitable?: boolean;
  /** Max drawdown exceeded limit. */
  drawdownExceeded?: boolean;
  /** Risk rules respected. */
  riskRespected?: boolean;
  /** Signal accuracy (0–1). */
  signalAccuracy?: number;
}

export interface CodeSignals {
  /** Tests pass after change. */
  testsPass?: boolean;
  /** Build succeeds. */
  buildSucceeds?: boolean;
  /** No linting errors. */
  noLintErrors?: boolean;
  /** Lines changed. */
  linesChanged?: number;
  /** PR merged. */
  prMerged?: boolean;
}

export interface GeneralSignals {
  /** Task was completed. */
  completed?: boolean;
  /** User explicitly approved output. */
  userApproved?: boolean;
  /** User rejected output. */
  userRejected?: boolean;
  /** Retries needed (0 = ideal). */
  retries?: number;
}

export type DomainSignals =
  | { domain: "cyber"; signals: CyberSignals }
  | { domain: "seo"; signals: SeoSignals }
  | { domain: "trading"; signals: TradingSignals }
  | { domain: "code"; signals: CodeSignals }
  | { domain: "general"; signals: GeneralSignals };

export interface TaskOutcome {
  /** Stable session/task id. */
  id: string;
  /** Unix ms timestamp. */
  timestamp: number;
  /** The domain of the task. */
  domain: Domain;
  /** Score: 0 = fail, 0.5 = partial, 1 = success. */
  score: Score;
  /** Domain-specific signals used to compute the score. */
  signals: CyberSignals | SeoSignals | TradingSignals | CodeSignals | GeneralSignals;
  /** Free-form summary of what happened. */
  summary?: string;
  /** Number of times this skill pattern has been used (for pruning). */
  useCount?: number;
  /** Shield verdict if any input was scanned. */
  shieldVerdict?: { blocked: boolean; severity?: string };
  /** Lyrie provenance. */
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
}

/** Options for Scorer. */
export interface ScorerOptions {
  /** Override the output file path (default: ~/.lyrie/evolve/outcomes.jsonl). */
  outPath?: string;
  /** Inject a Shield guard for scanning summaries. */
  shield?: ShieldGuardLike;
  /** When true, skip disk writes (useful for tests). */
  dryRun?: boolean;
}

// ─── Scorer class ─────────────────────────────────────────────────────────────

export class Scorer {
  private readonly outPath: string;
  private readonly shield: ShieldGuardLike;
  private readonly dryRun: boolean;

  constructor(opts: ScorerOptions = {}) {
    this.outPath =
      opts.outPath ?? join(homedir(), ".lyrie", "evolve", "outcomes.jsonl");
    this.shield = opts.shield ?? ShieldGuard.fallback();
    this.dryRun = opts.dryRun ?? false;
  }

  /**
   * Compute a score for the given domain + signals and persist the outcome.
   * Returns the fully populated TaskOutcome.
   */
  score(
    id: string,
    domainSignals: DomainSignals,
    summary?: string,
  ): TaskOutcome {
    // Shield-scan the summary before storing (scanRecalled: summaries are
    // recalled/stored text, not direct inbound user messages).
    const shieldVerdict = summary
      ? this.shield.scanRecalled(summary)
      : undefined;

    const computed = this._computeScore(domainSignals);

    const outcome: TaskOutcome = {
      id,
      timestamp: Date.now(),
      domain: domainSignals.domain,
      score: computed,
      signals: domainSignals.signals,
      summary: shieldVerdict?.blocked ? "[redacted by Shield]" : summary,
      useCount: 0,
      shieldVerdict: shieldVerdict
        ? { blocked: shieldVerdict.blocked, severity: shieldVerdict.severity }
        : undefined,
      signature: "Lyrie.ai by OTT Cybersecurity LLC",
    };

    if (!this.dryRun) {
      this._append(outcome);
    }

    return outcome;
  }

  /** Compute score without persisting (useful for dry-run / tests). */
  computeScore(domainSignals: DomainSignals): Score {
    return this._computeScore(domainSignals);
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private _computeScore(ds: DomainSignals): Score {
    switch (ds.domain) {
      case "cyber":
        return scoreCyber(ds.signals);
      case "seo":
        return scoreSeo(ds.signals);
      case "trading":
        return scoreTrading(ds.signals);
      case "code":
        return scoreCode(ds.signals);
      case "general":
        return scoreGeneral(ds.signals);
    }
  }

  private _append(outcome: TaskOutcome): void {
    const dir = this.outPath.split("/").slice(0, -1).join("/");
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    appendFileSync(this.outPath, JSON.stringify(outcome) + "\n", "utf8");
  }
}

// ─── Domain-specific scoring rules ───────────────────────────────────────────

export function scoreCyber(s: CyberSignals): Score {
  // False positive kills it immediately.
  if (s.falsePositive) return 0;

  // High confidence: confirmed + (poc or patch).
  if (s.confirmed && (s.pocGenerated || s.patchApplied)) return 1;

  // Confirmed but no PoC yet — good partial.
  if (s.confirmed) return 0.5;

  // Shield blocked something harmful: valuable signal.
  if (s.shieldBlocked) return 0.5;

  return 0;
}

export function scoreSeo(s: SeoSignals): Score {
  let points = 0;
  let total = 0;

  if (s.keywordsRanked !== undefined) {
    total++;
    if (s.keywordsRanked >= 3) points++;
    else if (s.keywordsRanked >= 1) points += 0.5;
  }
  if (s.contentPublished !== undefined) {
    total++;
    if (s.contentPublished) points++;
  }
  if (s.backlinksAcquired !== undefined) {
    total++;
    if (s.backlinksAcquired >= 5) points++;
    else if (s.backlinksAcquired >= 1) points += 0.5;
  }
  if (s.issuesResolved !== undefined) {
    total++;
    if (s.issuesResolved >= 10) points++;
    else if (s.issuesResolved >= 1) points += 0.5;
  }
  if (s.speedImprovementMs !== undefined) {
    total++;
    if (s.speedImprovementMs >= 500) points++;
    else if (s.speedImprovementMs > 0) points += 0.5;
  }

  if (total === 0) return 0;
  const ratio = points / total;
  if (ratio >= 0.75) return 1;
  if (ratio >= 0.4) return 0.5;
  return 0;
}

export function scoreTrading(s: TradingSignals): Score {
  // Drawdown exceeded is a hard fail regardless of PnL.
  if (s.drawdownExceeded) return 0;

  // Risk rules not respected: fail.
  if (s.riskRespected === false) return 0;

  let positive = 0;
  let total = 0;

  if (s.profitable !== undefined) {
    total++;
    if (s.profitable) positive++;
  }
  if (s.pnlRatio !== undefined) {
    total++;
    if (s.pnlRatio > 0.02) positive++;
    else if (s.pnlRatio > 0) positive += 0.5;
  }
  if (s.signalAccuracy !== undefined) {
    total++;
    if (s.signalAccuracy >= 0.65) positive++;
    else if (s.signalAccuracy >= 0.5) positive += 0.5;
  }

  if (total === 0) return 0;
  const ratio = positive / total;
  if (ratio >= 0.75) return 1;
  if (ratio >= 0.4) return 0.5;
  return 0;
}

export function scoreCode(s: CodeSignals): Score {
  // Tests fail = hard fail.
  if (s.testsPass === false) return 0;

  // Build fail = hard fail.
  if (s.buildSucceeds === false) return 0;

  let positive = 0;
  let total = 0;

  if (s.testsPass !== undefined) { total++; if (s.testsPass) positive++; }
  if (s.buildSucceeds !== undefined) { total++; if (s.buildSucceeds) positive++; }
  if (s.noLintErrors !== undefined) { total++; if (s.noLintErrors) positive++; }
  if (s.prMerged !== undefined) { total++; if (s.prMerged) positive++; }
  // Lines changed: any lines = partial contribution
  if (s.linesChanged !== undefined) { total++; if (s.linesChanged > 0) positive += 0.5; }

  if (total === 0) return 0;
  const ratio = positive / total;
  if (ratio >= 0.75) return 1;
  if (ratio >= 0.4) return 0.5;
  return 0;
}

export function scoreGeneral(s: GeneralSignals): Score {
  // Explicit rejection = fail.
  if (s.userRejected) return 0;

  // Explicit approval = success.
  if (s.userApproved && s.completed) return 1;
  if (s.userApproved) return 0.5;

  // Completed with no retries = success.
  if (s.completed && (s.retries === undefined || s.retries === 0)) return 1;

  // Completed with retries = partial.
  if (s.completed) return 0.5;

  return 0;
}

// ─── Helpers exposed for tests ────────────────────────────────────────────────

export const __internals = {
  scoreCyber,
  scoreSeo,
  scoreTrading,
  scoreCode,
  scoreGeneral,
};

export const SCORER_VERSION = "lyrie-evolve-scorer-1.0.0";
