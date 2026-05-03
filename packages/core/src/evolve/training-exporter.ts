/**
 * Lyrie LyrieEvolve — Training Data Exporter
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Exports high-quality TaskOutcome records as JSONL training data
 * for fine-tuning Lyrie's own model on the H200.
 *
 * Supported formats:
 *   - atropos      GRPO-compatible JSONL (reward field, domain field)
 *   - openai-sft   OpenAI fine-tuning format (messages array)
 *   - sharegpt     ShareGPT conversation format
 *
 * © OTT Cybersecurity LLC — All rights reserved.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";

import type { TaskOutcome } from "./scorer";

// ─── Public types ─────────────────────────────────────────────────────────────

export type ExportDomain = "cyber" | "seo" | "trading" | "code" | "all";
export type ExportFormat = "atropos" | "openai-sft" | "sharegpt";

export interface ExportOptions {
  /** Minimum score to include (0.0–1.0). Default: 0.5. */
  minScore: number;
  /** Domains to include. Use ["all"] for all domains. Default: ["all"]. */
  domains: ExportDomain[];
  /** Maximum samples to export. Default: 10000. */
  maxSamples: number;
  /** Output JSONL file path. */
  outputPath: string;
  /** Export format. Default: "atropos". */
  format: ExportFormat;
}

export interface ExportResult {
  /** Number of samples written to the output file. */
  samplesExported: number;
  /** Per-domain breakdown of exported samples. */
  domainsBreakdown: Record<string, number>;
  /** Resolved output path. */
  outputPath: string;
  /** File size in bytes. */
  sizeBytes: number;
}

/** Atropos GRPO training record. */
export interface AtroposRecord {
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
  reward: number;
  domain: string;
  task_id: string;
}

/** OpenAI SFT fine-tune record. */
export interface OpenAISFTRecord {
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
}

/** ShareGPT conversation record. */
export interface ShareGPTRecord {
  conversations: Array<{ from: "human" | "gpt" | "system"; value: string }>;
  reward: number;
  domain: string;
}

export interface TrainingExporterOptions {
  /** Path to outcomes.jsonl. Default: ~/.lyrie/evolve/outcomes.jsonl. */
  outcomesPath?: string;
  /** Skip disk writes (for tests). Default: false. */
  dryRun?: boolean;
}

// ─── Domain system prompts ────────────────────────────────────────────────────

const DOMAIN_SYSTEM_PROMPTS: Record<string, string> = {
  cyber: "You are Lyrie, an autonomous cyber operations AI by OTT Cybersecurity LLC. You perform vulnerability assessments, threat hunting, and security remediation with precision and ethical constraint.",
  seo: "You are Lyrie, an autonomous SEO operations AI by OTT Cybersecurity LLC. You analyze search rankings, optimize content, acquire backlinks, and audit technical SEO issues.",
  trading: "You are Lyrie, an autonomous trading AI by OTT Cybersecurity LLC. You analyze market signals, manage risk, and execute trades with strict drawdown limits and risk-respecting discipline.",
  code: "You are Lyrie, an autonomous engineering AI by OTT Cybersecurity LLC. You write, review, test, and refactor code with a focus on correctness, security, and simplicity.",
  general: "You are Lyrie, an autonomous AI assistant by OTT Cybersecurity LLC. You complete tasks accurately, efficiently, and with minimal retries.",
};

const DEFAULT_SYSTEM_PROMPT =
  "You are Lyrie, an autonomous AI by OTT Cybersecurity LLC. Complete tasks accurately and safely.";

// ─── TrainingExporter ─────────────────────────────────────────────────────────

export class TrainingExporter {
  private readonly outcomesPath: string;
  private readonly dryRun: boolean;

  constructor(opts: TrainingExporterOptions = {}) {
    this.outcomesPath =
      opts.outcomesPath ??
      join(homedir(), ".lyrie", "evolve", "outcomes.jsonl");
    this.dryRun = opts.dryRun ?? false;
  }

  /**
   * Export training data from stored outcomes.
   * Returns metadata about what was exported.
   */
  async export(options: Partial<ExportOptions> & { outputPath: string }): Promise<ExportResult> {
    const opts = this._resolveOptions(options);

    // Load + filter outcomes
    const outcomes = this._loadOutcomes();
    const filtered = this._filterOutcomes(outcomes, opts);

    // Build records
    const records = filtered.map((o) => this._buildRecord(o, opts.format));

    // Compute breakdown
    const domainsBreakdown = this._computeBreakdown(filtered);

    // Write JSONL
    const jsonl = records.map((r) => JSON.stringify(r)).join("\n") + (records.length > 0 ? "\n" : "");
    if (!this.dryRun && records.length > 0) {
      this._ensureDir(opts.outputPath);
      writeFileSync(opts.outputPath, jsonl, "utf8");
    }

    const sizeBytes =
      !this.dryRun && existsSync(opts.outputPath)
        ? statSync(opts.outputPath).size
        : Buffer.byteLength(jsonl, "utf8");

    return {
      samplesExported: records.length,
      domainsBreakdown,
      outputPath: opts.outputPath,
      sizeBytes,
    };
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private _resolveOptions(
    partial: Partial<ExportOptions> & { outputPath: string },
  ): ExportOptions {
    return {
      minScore: partial.minScore ?? 0.5,
      domains: partial.domains ?? ["all"],
      maxSamples: partial.maxSamples ?? 10000,
      outputPath: partial.outputPath,
      format: partial.format ?? "atropos",
    };
  }

  private _loadOutcomes(): TaskOutcome[] {
    if (!existsSync(this.outcomesPath)) return [];
    const raw = readFileSync(this.outcomesPath, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .flatMap((l) => {
        try {
          return [JSON.parse(l) as TaskOutcome];
        } catch {
          return [];
        }
      });
  }

  private _filterOutcomes(
    outcomes: TaskOutcome[],
    opts: ExportOptions,
  ): TaskOutcome[] {
    const wantAll =
      opts.domains.length === 0 ||
      opts.domains.includes("all");

    return outcomes
      .filter((o) => o.score >= opts.minScore)
      .filter((o) =>
        wantAll ? true : (opts.domains as string[]).includes(o.domain),
      )
      .slice(0, opts.maxSamples);
  }

  private _buildRecord(
    outcome: TaskOutcome,
    format: ExportFormat,
  ): AtroposRecord | OpenAISFTRecord | ShareGPTRecord {
    const systemPrompt =
      DOMAIN_SYSTEM_PROMPTS[outcome.domain] ?? DEFAULT_SYSTEM_PROMPT;
    const userContent = outcome.summary
      ? `Task: ${outcome.summary}`
      : `Complete a ${outcome.domain} task successfully.`;
    const assistantContent = outcome.summary
      ? `Completed: ${outcome.summary} [score=${outcome.score}, domain=${outcome.domain}]`
      : `Task completed with score ${outcome.score}.`;

    switch (format) {
      case "atropos":
        return {
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userContent },
            { role: "assistant", content: assistantContent },
          ],
          reward: outcome.score,
          domain: outcome.domain,
          task_id: outcome.id ?? randomUUID(),
        } satisfies AtroposRecord;

      case "openai-sft":
        return {
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userContent },
            { role: "assistant", content: assistantContent },
          ],
        } satisfies OpenAISFTRecord;

      case "sharegpt":
        return {
          conversations: [
            { from: "system", value: systemPrompt },
            { from: "human", value: userContent },
            { from: "gpt", value: assistantContent },
          ],
          reward: outcome.score,
          domain: outcome.domain,
        } satisfies ShareGPTRecord;
    }
  }

  private _computeBreakdown(outcomes: TaskOutcome[]): Record<string, number> {
    const breakdown: Record<string, number> = {};
    for (const o of outcomes) {
      breakdown[o.domain] = (breakdown[o.domain] ?? 0) + 1;
    }
    return breakdown;
  }

  private _ensureDir(filePath: string): void {
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  // ─── Status helper (used by CLI) ───────────────────────────────────────────

  /**
   * Return a summary of training-ready data without exporting.
   */
  status(): TrainingStatus {
    const outcomes = this._loadOutcomes();
    const ready = outcomes.filter((o) => o.score >= 0.5);

    const byDomain: Record<string, number> = {};
    for (const o of ready) {
      byDomain[o.domain] = (byDomain[o.domain] ?? 0) + 1;
    }

    const lastExportTimestamp =
      outcomes.length > 0
        ? Math.max(...outcomes.map((o) => o.timestamp))
        : undefined;

    return {
      totalOutcomes: outcomes.length,
      readySamples: ready.length,
      byDomain,
      lastExportTimestamp,
      outcomesPath: this.outcomesPath,
    };
  }
}

export interface TrainingStatus {
  totalOutcomes: number;
  readySamples: number;
  byDomain: Record<string, number>;
  lastExportTimestamp: number | undefined;
  outcomesPath: string;
}

// ─── Version ───────────────────────────────────────────────────────────────────

export const TRAINING_EXPORTER_VERSION = "lyrie-evolve-training-exporter-1.0.0";
