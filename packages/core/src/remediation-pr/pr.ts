/**
 * remediation-pr/pr.ts — thin `gh` CLI wrapper for opening auto-remediation
 * PRs against a target repo working tree.
 *
 * Isolated from generate.ts so it's injectable/mockable in tests \u2014 no test
 * in this feature ever actually shells out to `gh` or `git` (see
 * generate.test.ts): this module's real implementation is only exercised
 * by a human/CI explicitly opting in to open a real PR.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface OpenPrOptions {
  /** Absolute path to the target repo's working tree (git-clean, on a base branch). */
  repoDir: string;
  branchName: string;
  file: string;
  newContent: string;
  prTitle: string;
  prBody: string;
  /** Base branch to open the PR against. Default "main". */
  baseBranch?: string;
}

export interface OpenPrResult {
  ok: boolean;
  prUrl?: string;
  error?: string;
}

/** Injectable command runner \u2014 real impl shells out; tests substitute a fake. */
export type CommandRunner = (cmd: string, args: string[], cwd: string) => Promise<{ stdout: string; stderr: string }>;

export const realCommandRunner: CommandRunner = async (cmd, args, cwd) => {
  const { stdout, stderr } = await execFileAsync(cmd, args, { cwd });
  return { stdout, stderr };
};

/**
 * Create a branch, write `newContent` to `file`, commit, push, and open a
 * PR via `gh pr create`. Uses `git`/`gh` exactly the way this repo's own
 * Dependabot-adjacent automation would (conventional-commit message,
 * feature-branch-per-fix, no direct pushes to main).
 *
 * Every step is via the injected `run` (defaults to a real subprocess) so
 * this function is unit-testable without ever touching a real git repo or
 * GitHub API.
 */
export async function openRemediationPr(opts: OpenPrOptions, run: CommandRunner = realCommandRunner): Promise<OpenPrResult> {
  const base = opts.baseBranch ?? "main";
  try {
    await run("git", ["checkout", "-b", opts.branchName, base], opts.repoDir);
    await writeFileAtRepoRoot(opts.repoDir, opts.file, opts.newContent, run);
    await run("git", ["add", opts.file], opts.repoDir);
    await run("git", ["commit", "-m", opts.prTitle], opts.repoDir);
    await run("git", ["push", "-u", "origin", opts.branchName], opts.repoDir);
    const { stdout } = await run(
      "gh",
      ["pr", "create", "--title", opts.prTitle, "--body", opts.prBody, "--base", base, "--head", opts.branchName],
      opts.repoDir,
    );
    const prUrl = stdout.trim().split("\n").pop();
    return { ok: true, prUrl };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Writing a file's content isn't a `gh`/`git` subprocess call, so this is
 * separated for clarity \u2014 uses node:fs directly rather than shelling out
 * to `echo`/`cat` (which would need fragile escaping of arbitrary file
 * contents).
 */
async function writeFileAtRepoRoot(
  repoDir: string,
  file: string,
  content: string,
  _run: CommandRunner,
): Promise<void> {
  const { writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  writeFileSync(join(repoDir, file), content, "utf8");
}
