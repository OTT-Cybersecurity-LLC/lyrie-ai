/**
 * remediation-pr/types.ts — mechanical (auto-fixable) remediation shapes.
 *
 * Deliberately narrow: only the two finding classes explicitly scoped in
 * this feature (missing security header, pinned dependency with a known
 * fix version) get a `MechanicalFinding` shape and therefore a generated
 * diff. Everything else routes through the existing
 * `packages/core/src/hack/auto-remediation.ts` manual-report path — no
 * diff/PR generation is even attempted.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { RemediationSuggestion } from "../hack/auto-remediation";

export type MechanicalFindingKind = "missing-security-header" | "pinned-dependency-fix-available";

export interface MissingHeaderFinding {
  kind: "missing-security-header";
  /** Header name, lower-cased, e.g. "content-security-policy". */
  header: string;
  /** Recommended value to set. */
  recommendedValue: string;
  /** Path to the config file to patch, relative to repo root. */
  configFile: string;
  /** "next-config" | "express" \u2014 which patcher to use. Extend as new frameworks are supported. */
  configKind: "next-config";
}

export interface DependencyFixFinding {
  kind: "pinned-dependency-fix-available";
  /** Package name, e.g. "lodash". */
  packageName: string;
  /** Currently pinned version as it appears in the manifest. */
  currentVersion: string;
  /** Known-good fixed version from the advisory (ThreatAdvisory.patchedVersion). */
  fixedVersion: string;
  /** Path to the manifest file to patch, relative to repo root (e.g. "package.json"). */
  manifestFile: string;
  /** CVE id driving this fix, for the PR description. */
  cve?: string;
}

export type MechanicalFinding = MissingHeaderFinding | DependencyFixFinding;

/** Result of successfully generating a mechanical fix. */
export interface GeneratedDiff {
  /** Path (relative to repo root) that was modified. */
  file: string;
  /** Full new file contents after the fix is applied. */
  newContent: string;
  /** Unified-diff-style before/after for the PR body (human-readable, not `git diff` output). */
  before: string;
  after: string;
  /** Suggested PR title. */
  prTitle: string;
  /** Suggested PR body (markdown). */
  prBody: string;
  /** Suggested branch name. */
  branchName: string;
}

export interface MechanicalFixResult {
  ok: true;
  diff: GeneratedDiff;
}
export interface MechanicalFixSkipped {
  ok: false;
  reason: string;
}

/** Re-exported for convenience so callers don't need two import paths. */
export type { RemediationSuggestion };
