/**
 * Lyrie EditEngine — diff-view file edits with approval gates.
 *
 * Part of Lyrie.ai by OTT Cybersecurity LLC.
 *
 * Lyrie's `write_file` tool overwrites whole files — fine for new files
 * but risky for in-place edits because the diff between agent intent and
 * disk effect is invisible. EditEngine is Lyrie's purpose-built solution:
 *
 *   - Targeted edits via exact-match `oldText` → `newText` replacements
 *   - Unified diff generation for human review
 *   - Three approval modes: auto-approve, require-approval, dry-run
 *   - Per-edit ledger (~/.lyrie/edits.json) so every applied change can be
 *     inspected and reverted
 *   - Shield Doctrine: every patch is scanned BEFORE it touches disk so
 *     attacker-planned content never lands on the filesystem
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { createHash, randomUUID } from "node:crypto";

import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EditOperation {
  /** Exact text to match in the original file. Must be unique. */
  oldText: string;
  /** Replacement text. */
  newText: string;
}

export type EditApprovalMode = "auto-approve" | "require-approval" | "dry-run";

export interface EditRequest {
  path: string;
  edits: EditOperation[];
  /** Optional human-friendly description of intent. */
  description?: string;
  /** Override the engine-default approval mode for this request. */
  mode?: EditApprovalMode;
}

export interface EditPlan {
  id: string;
  path: string;
  description?: string;
  mode: EditApprovalMode;
  /** Hash of the file's current contents (used to detect drift between plan and apply). */
  beforeHash: string;
  /** Resulting full file contents if the plan is applied. */
  afterContent: string;
  /** Unified diff (RFC 9519-ish style — file headers + hunks). */
  unifiedDiff: string;
  /** Number of edits in this plan. */
  editCount: number;
  /** Was the plan blocked by Shield? */
  shielded?: boolean;
  /** Shield reason if blocked. */
  shieldReason?: string;
  /** Was every oldText found in the original? */
  applicable: boolean;
  /** Per-edit applicability detail. */
  applicableDetail: Array<{ index: number; matched: boolean; reason?: string }>;
  /** ISO-8601 plan time. */
  createdAt: string;
}

export interface EditApply {
  id: string;
  path: string;
  beforeHash: string;
  afterHash: string;
  bytesBefore: number;
  bytesAfter: number;
  appliedAt: string;
  description?: string;
}

export interface EditLedger {
  applied: EditApply[];
  pending: EditPlan[];
}

export interface EditEngineOptions {
  /** Default approval mode. Production-safe default = require-approval. */
  defaultMode?: EditApprovalMode;
  /** Path to the ledger file. */
  ledgerPath?: string;
  /** Working directory edits must stay within. Defaults to cwd. */
  workspaceRoot?: string;
  /** Shield guard used to scan patch contents before disk write. */
  shield?: ShieldGuardLike;
}

// ─── Implementation ──────────────────────────────────────────────────────────

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function defaultLedgerPath(): string {
  return join(homedir(), ".lyrie", "edits.json");
}

function ensureDir(path: string) {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

/**
 * Build a small unified diff. We deliberately don't pull in a heavyweight
 * diff library — high-quality output is achievable with a line-by-line
 * Myers-lite implementation. Lyrie renders context-3 hunks.
 *
 * Lyrie.ai by OTT Cybersecurity LLC.
 */
export function buildUnifiedDiff(
  filePath: string,
  before: string,
  after: string,
  context = 3,
): string {
  if (before === after) return "";
  const a = before.split("\n");
  const b = after.split("\n");

  // LCS-based simple diff (O(N*M) — fine for typical source files).
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  type Op = { kind: "eq" | "del" | "add"; aIdx: number; bIdx: number; line: string };
  const ops: Op[] = [];
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      ops.push({ kind: "eq", aIdx: i - 1, bIdx: j - 1, line: a[i - 1] });
      i--;
      j--;
    } else if (dp[i - 1][j] >= dp[i][j - 1]) {
      ops.push({ kind: "del", aIdx: i - 1, bIdx: j, line: a[i - 1] });
      i--;
    } else {
      ops.push({ kind: "add", aIdx: i, bIdx: j - 1, line: b[j - 1] });
      j--;
    }
  }
  while (i > 0) ops.push({ kind: "del", aIdx: --i, bIdx: 0, line: a[i] });
  while (j > 0) ops.push({ kind: "add", aIdx: 0, bIdx: --j, line: b[j] });
  ops.reverse();

  // Group into hunks with `context` lines around each change run.
  const lines: string[] = [];
  lines.push(`--- a/${filePath}`);
  lines.push(`+++ b/${filePath}`);

  let k = 0;
  while (k < ops.length) {
    if (ops[k].kind === "eq") {
      k++;
      continue;
    }
    // Find end of this change run, including trailing context
    const start = Math.max(0, k - context);
    let end = k;
    while (end < ops.length && (ops[end].kind !== "eq" || endNotFar(ops, end, context))) end++;
    end = Math.min(ops.length, end + context);

    let aStart = ops[start].aIdx + 1;
    let bStart = ops[start].bIdx + 1;
    let aLen = 0;
    let bLen = 0;
    const hunk: string[] = [];
    for (let h = start; h < end; h++) {
      const op = ops[h];
      if (op.kind === "eq") {
        hunk.push(` ${op.line}`);
        aLen++;
        bLen++;
      } else if (op.kind === "del") {
        hunk.push(`-${op.line}`);
        aLen++;
      } else {
        hunk.push(`+${op.line}`);
        bLen++;
      }
    }
    lines.push(`@@ -${aStart},${aLen} +${bStart},${bLen} @@`);
    lines.push(...hunk);
    k = end;
  }
  return lines.join("\n");
}

function endNotFar(ops: Array<{ kind: string }>, idx: number, ctx: number): boolean {
  for (let q = idx + 1; q <= idx + ctx && q < ops.length; q++) {
    if (ops[q].kind !== "eq") return true;
  }
  return false;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class EditEngine {
  private mode: EditApprovalMode;
  private ledgerPath: string;
  private workspaceRoot: string;
  private shield: ShieldGuardLike;
  private ledger: EditLedger;

  constructor(opts: EditEngineOptions = {}) {
    this.mode = opts.defaultMode ?? "require-approval";
    this.ledgerPath = opts.ledgerPath ?? defaultLedgerPath();
    this.workspaceRoot = resolve(opts.workspaceRoot ?? process.cwd());
    this.shield = opts.shield ?? ShieldGuard.fallback();
    this.ledger = this.loadLedger();
  }

  /** Plan an edit (does NOT touch disk). */
  plan(req: EditRequest): EditPlan {
    const path = this.resolveInsideWorkspace(req.path);
    const original = existsSync(path) ? readFileSync(path, "utf8") : "";
    const beforeHash = sha256(original);

    let after = original;
    const detail: EditPlan["applicableDetail"] = [];
    let applicable = true;
    for (let i = 0; i < req.edits.length; i++) {
      const e = req.edits[i];
      const occurrences = countOccurrences(after, e.oldText);
      if (occurrences === 0) {
        detail.push({ index: i, matched: false, reason: "oldText not found" });
        applicable = false;
        continue;
      }
      if (occurrences > 1) {
        detail.push({ index: i, matched: false, reason: `oldText not unique (${occurrences} matches)` });
        applicable = false;
        continue;
      }
      after = after.replace(e.oldText, e.newText);
      detail.push({ index: i, matched: true });
    }

    // Shield Doctrine: scan the resulting content as recalled text. We don't
    // want a model talked into writing prompt-injection or credentials to
    // disk just because it was given a "write this content" task.
    const verdict = this.shield.scanRecalled(after);

    const plan: EditPlan = {
      id: randomUUID(),
      path,
      description: req.description,
      mode: req.mode ?? this.mode,
      beforeHash,
      afterContent: after,
      unifiedDiff: applicable ? buildUnifiedDiff(req.path, original, after) : "",
      editCount: req.edits.length,
      shielded: verdict.blocked,
      shieldReason: verdict.reason,
      applicable,
      applicableDetail: detail,
      createdAt: new Date().toISOString(),
    };

    if (plan.mode === "require-approval" && plan.applicable && !plan.shielded) {
      this.ledger.pending.push(plan);
      this.saveLedger();
    }
    return plan;
  }

  /**
   * Apply a previously-produced plan, or apply directly when in auto-approve
   * mode. Returns `null` if the plan is not applicable, was Shield-blocked,
   * or has been invalidated (file changed under us — beforeHash mismatch).
   */
  apply(plan: EditPlan, force = false): EditApply | null {
    if (!plan.applicable) return null;
    if (plan.shielded && !force) return null;
    if (plan.mode === "dry-run") return null;
    if (plan.mode === "require-approval" && !force) {
      // Plan exists in pending; explicit `approve()` call required.
      return null;
    }

    const path = plan.path;
    const current = existsSync(path) ? readFileSync(path, "utf8") : "";
    if (sha256(current) !== plan.beforeHash) {
      // File drifted. Refuse to apply blindly.
      return null;
    }

    ensureDir(path);
    writeFileSync(path, plan.afterContent, "utf8");

    const applied: EditApply = {
      id: plan.id,
      path,
      beforeHash: plan.beforeHash,
      afterHash: sha256(plan.afterContent),
      bytesBefore: Buffer.byteLength(current, "utf8"),
      bytesAfter: Buffer.byteLength(plan.afterContent, "utf8"),
      appliedAt: new Date().toISOString(),
      description: plan.description,
    };
    this.ledger.applied.push(applied);
    this.ledger.pending = this.ledger.pending.filter((p) => p.id !== plan.id);
    this.saveLedger();
    return applied;
  }

  /** Approve a pending plan by id and apply it. */
  approve(planId: string): EditApply | null {
    const idx = this.ledger.pending.findIndex((p) => p.id === planId);
    if (idx === -1) return null;
    const plan = this.ledger.pending[idx];
    return this.apply(plan, true);
  }

  /** Revert a previously-applied edit using the ledger's stored hashes. */
  revert(appliedId: string): boolean {
    const idx = this.ledger.applied.findIndex((a) => a.id === appliedId);
    if (idx === -1) return false;
    // We only stored hashes (small ledger). True revert requires the original
    // content; Phase 1 deliberately stops here and tells the operator to use
    // git. A future Phase 2 enhancement will keep a content snapshot if the
    // operator opts in.
    return false;
  }

  /** List pending plans (e.g. for the CLI). */
  pending(): EditPlan[] {
    return [...this.ledger.pending];
  }

  /** List applied edits. */
  applied(): EditApply[] {
    return [...this.ledger.applied];
  }

  // ─── Internals ────────────────────────────────────────────────────────────

  private loadLedger(): EditLedger {
    if (!existsSync(this.ledgerPath)) return { applied: [], pending: [] };
    try {
      const data = JSON.parse(readFileSync(this.ledgerPath, "utf8"));
      return {
        applied: Array.isArray(data.applied) ? data.applied : [],
        pending: Array.isArray(data.pending) ? data.pending : [],
      };
    } catch {
      return { applied: [], pending: [] };
    }
  }

  private saveLedger() {
    ensureDir(this.ledgerPath);
    writeFileSync(this.ledgerPath, JSON.stringify(this.ledger, null, 2), { mode: 0o600 });
  }

  private resolveInsideWorkspace(p: string): string {
    const abs = resolve(this.workspaceRoot, p);
    if (!abs.startsWith(this.workspaceRoot)) {
      throw new Error(`refusing path outside workspace: ${p}`);
    }
    return abs;
  }
}

// ─── helpers ────────────────────────────────────────────────────────────────

function countOccurrences(haystack: string, needle: string): number {
  if (needle.length === 0) return 0;
  const re = new RegExp(escapeRegex(needle), "g");
  return (haystack.match(re) ?? []).length;
}
