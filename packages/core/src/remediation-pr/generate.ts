/**
 * remediation-pr/generate.ts — library entry point:
 * `generateRemediationPr(finding, suggestion)`.
 *
 * Usable purely as a diff generator (no PR opened) or, when `openPr: true`
 * is explicitly passed AND the caller supplies a `repoDir` that is NOT this
 * repo's own working tree, actually opens a PR via `pr.ts`'s `gh` wrapper.
 *
 * Safety gate (hard-coded, not configurable away): `generateRemediationPr`
 * refuses to call `openRemediationPr` if `repoDir` resolves to the
 * lyrie-agent working tree itself (self-modifying-PR footgun) \u2014 per the
 * prompt contract: "NOT against lyrie-agent itself and NOT opening real
 * PRs against the public OTT-Cybersecurity-LLC/lyrie-ai repo unless the
 * finding is real and verified safe." The demonstration/test path in this
 * feature always targets a disposable fixture repo (see generate.test.ts),
 * never a real PR.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { generateHeaderFix } from "./header-fix";
import { generateDependencyFix } from "./dependency-fix";
import { openRemediationPr, type CommandRunner, type OpenPrResult } from "./pr";
import {
  revalidateAndAttach,
  type AttachProofOfFixResult,
  type RevalidationResult,
} from "./revalidate";
import type {
  GeneratedDiff,
  MechanicalFinding,
  MechanicalFixResult,
  MechanicalFixSkipped,
} from "./types";
import type { Backend, BackendResourceHints } from "../backends/types";
import type { RemediationSuggestion } from "../hack/auto-remediation";

/**
 * Opt-in self-heal re-validation config. When supplied AND a PR is actually
 * opened, `generateRemediationPr` re-runs verification against the patched
 * tree (via `revalidateAndAttach`) and posts a proof-of-fix comment to the
 * PR. Omitting `revalidate` entirely preserves the previous behavior exactly
 * (no re-validation, no extra `gh` calls).
 */
export interface RevalidateOption {
  /**
   * Execution backend to run the re-check on. Pass an explicit backend
   * instance in tests to avoid any real sandbox network call. Omit to use
   * `getBackend()` env resolution (defaults to local).
   */
  backend?: Backend;
  /**
   * Optional focused verification callback — takes priority over the generic
   * backend re-scan when supplied (see revalidate.ts).
   */
  verify?: (repoDir: string, finding: MechanicalFinding) => Promise<boolean>;
  /**
   * When true AND no backend override supplied, re-validate with a local
   * dry-run backend (never spawns a real scan). Safe default for demos.
   */
  dryRun?: boolean;
  /** Resource/timeout hints forwarded to the backend request. */
  resources?: BackendResourceHints;
}

export interface GenerateRemediationPrOptions {
  /** Working tree to patch. Required if openPr is true. */
  repoDir?: string;
  /** Actually open a PR via `gh` (default false — diff-only). */
  openPr?: boolean;
  baseBranch?: string;
  /** Injectable command runner for tests. */
  commandRunner?: CommandRunner;
  /**
   * Opt-in self-healing loop. When present AND `openPr` opened a PR, run
   * sandboxed re-validation against the patched tree and attach a
   * proof-of-fix comment to the PR. Omit for no behavior change.
   */
  revalidate?: RevalidateOption;
}

export type GenerateRemediationPrResult =
  | { attempted: false; reason: string }
  | {
      attempted: true;
      diff: GeneratedDiff;
      pr?: OpenPrResult;
      /** Present only when `revalidate` was supplied AND a PR was opened. */
      revalidation?: RevalidationResult;
      /** Present only when a proof-of-fix comment was attached to the PR. */
      proofOfFix?: AttachProofOfFixResult;
    };

/** This module's own directory \u2014 used only to compute lyrie-agent's repo root for the self-modification guard. */
function lyrieAgentRepoRoot(): string {
  // packages/core/src/remediation-pr/generate.ts -> repo root is 4 levels up.
  const here = fileURLToPath(import.meta.url);
  return resolve(here, "..", "..", "..", "..", "..");
}

function isSelfRepo(repoDir: string): boolean {
  return resolve(repoDir) === lyrieAgentRepoRoot();
}

/**
 * Generate (and optionally open) a remediation PR for a mechanical finding.
 *
 * Given a mock/real finding + a `RemediationSuggestion` marked
 * `autoFixable: true`, produces a syntactically-valid diff. Given a
 * non-auto-fixable suggestion (or `undefined`), returns `{ attempted: false
 * }` immediately \u2014 no diff/PR generation is attempted, falling through to
 * the normal manual-report path (report-engine.ts's SARIF/markdown output
 * still includes the suggestion as before; this function is purely
 * additive).
 */
export async function generateRemediationPr(
  finding: MechanicalFinding,
  suggestion: RemediationSuggestion | undefined | null,
  opts: GenerateRemediationPrOptions = {},
): Promise<GenerateRemediationPrResult> {
  if (!suggestion || suggestion.autoFixable !== true) {
    return { attempted: false, reason: "suggestion is not marked autoFixable \u2014 falling through to manual report" };
  }

  let result: MechanicalFixResult | MechanicalFixSkipped;

  if (finding.kind === "missing-security-header") {
    const currentContent =
      opts.repoDir && existsSync(join(opts.repoDir, finding.configFile))
        ? readFileSync(join(opts.repoDir, finding.configFile), "utf8")
        : undefined;
    result = generateHeaderFix(finding, currentContent);
  } else if (finding.kind === "pinned-dependency-fix-available") {
    const manifestPath = opts.repoDir ? join(opts.repoDir, finding.manifestFile) : undefined;
    if (!manifestPath || !existsSync(manifestPath)) {
      return { attempted: false, reason: `manifest ${finding.manifestFile} not found under repoDir` };
    }
    result = generateDependencyFix(finding, readFileSync(manifestPath, "utf8"));
  } else {
    // Exhaustiveness guard \u2014 if a new MechanicalFindingKind is ever added
    // without a generator, refuse loudly instead of silently no-op-ing.
    const _exhaustive: never = finding;
    return { attempted: false, reason: `unsupported finding kind: ${JSON.stringify(_exhaustive)}` };
  }

  if (!result.ok) {
    return { attempted: false, reason: result.reason };
  }

  if (!opts.openPr) {
    return { attempted: true, diff: result.diff };
  }

  if (!opts.repoDir) {
    return { attempted: false, reason: "openPr: true requires repoDir" };
  }
  if (isSelfRepo(opts.repoDir)) {
    return {
      attempted: false,
      reason: "refusing to open a PR against lyrie-agent's own working tree (self-modification guard)",
    };
  }

  const pr = await openRemediationPr(
    {
      repoDir: opts.repoDir,
      branchName: result.diff.branchName,
      file: result.diff.file,
      newContent: result.diff.newContent,
      prTitle: result.diff.prTitle,
      prBody: result.diff.prBody,
      baseBranch: opts.baseBranch,
    },
    opts.commandRunner,
  );

  // ── Self-healing loop (opt-in) ────────────────────────────────────────────
  // Only runs when the caller explicitly supplied `revalidate` AND a PR was
  // actually opened. `revalidateAndAttach` itself is a no-op on `pr.ok=false`
  // / missing prUrl, so no proof-of-fix is ever posted to a PR that failed to
  // open. Re-validation runs against the same patched working tree.
  if (!opts.revalidate) {
    return { attempted: true, diff: result.diff, pr };
  }

  const { revalidation, attach } = await revalidateAndAttach(
    {
      repoDir: opts.repoDir,
      finding,
      backend: opts.revalidate.backend,
      verify: opts.revalidate.verify,
      dryRun: opts.revalidate.dryRun,
      resources: opts.revalidate.resources,
    },
    pr,
    opts.commandRunner,
  );

  return { attempted: true, diff: result.diff, pr, revalidation, proofOfFix: attach };
}
