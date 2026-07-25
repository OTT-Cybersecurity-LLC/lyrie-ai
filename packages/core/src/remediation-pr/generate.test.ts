/**
 * generate.test.ts — end-to-end (diff generation + PR flow) tests against a
 * disposable tmp fixture repo. Never calls real `gh`/`git` over the
 * network — `CommandRunner` is faked to record calls instead, per the
 * prompt contract's "not against lyrie-agent itself, not a real PR against
 * the public repo" constraint. File writes DO happen for real (against the
 * tmp fixture only) so the diff-application path is genuinely exercised.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateRemediationPr } from "./generate";
import type { CommandRunner } from "./pr";
import type { DependencyFixFinding, MissingHeaderFinding } from "./types";
import type { RemediationSuggestion } from "../hack/auto-remediation";

function withFixtureRepo<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "lyrie-remediation-fixture-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const autoFixableSuggestion: RemediationSuggestion = {
  description: "Add missing security header",
  confidence: 0.95,
  signature: "Lyrie.ai by OTT Cybersecurity LLC",
  autoFixable: true,
};

const manualOnlySuggestion: RemediationSuggestion = {
  description: "Fix a SQL injection — requires understanding the query builder call site",
  confidence: 0.9,
  signature: "Lyrie.ai by OTT Cybersecurity LLC",
  // autoFixable intentionally omitted/false — this is the "app logic" case.
};

function fakeCommandRunner(): { runner: CommandRunner; calls: Array<{ cmd: string; args: string[] }> } {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const runner: CommandRunner = async (cmd, args) => {
    calls.push({ cmd, args });
    if (cmd === "gh" && args.includes("pr") && args.includes("create")) {
      return { stdout: "https://github.com/example/fixture/pull/1\n", stderr: "" };
    }
    return { stdout: "", stderr: "" };
  };
  return { runner, calls };
}

describe("generateRemediationPr — mechanical missing-header finding", () => {
  test("diff-only mode (openPr not set): generates a valid diff, no PR attempted", async () => {
    await withFixtureRepo(async (dir) => {
      const finding: MissingHeaderFinding = {
        kind: "missing-security-header",
        header: "content-security-policy",
        recommendedValue: "default-src 'self'",
        configFile: "next.config.ts",
        configKind: "next-config",
      };

      const result = await generateRemediationPr(finding, autoFixableSuggestion, { repoDir: dir });
      expect(result.attempted).toBe(true);
      if (result.attempted) {
        expect(result.diff.newContent).toContain("Content-Security-Policy");
        expect(result.pr).toBeUndefined();
      }
    });
  });

  test("openPr: true against a disposable fixture repo — full flow via faked gh/git", async () => {
    await withFixtureRepo(async (dir) => {
      writeFileSync(
        join(dir, "next.config.ts"),
        `import type { NextConfig } from "next";\n\nconst nextConfig: NextConfig = {};\n\nexport default nextConfig;\n`,
        "utf8",
      );

      const finding: MissingHeaderFinding = {
        kind: "missing-security-header",
        header: "x-frame-options",
        recommendedValue: "DENY",
        configFile: "next.config.ts",
        configKind: "next-config",
      };

      const { runner, calls } = fakeCommandRunner();
      const result = await generateRemediationPr(finding, autoFixableSuggestion, {
        repoDir: dir,
        openPr: true,
        commandRunner: runner,
      });

      expect(result.attempted).toBe(true);
      if (result.attempted) {
        expect(result.pr?.ok).toBe(true);
        expect(result.pr?.prUrl).toContain("github.com");
      }

      // The fixture file was actually rewritten on disk.
      const written = readFileSync(join(dir, "next.config.ts"), "utf8");
      expect(written).toContain("X-Frame-Options");

      // git/gh were invoked in the expected sequence — never against a real remote.
      expect(calls.map((c) => c.cmd)).toEqual(["git", "git", "git", "git", "gh"]);
      expect(calls[0].args).toContain("checkout");
      expect(calls[calls.length - 1].args).toContain("create");
    });
  });
});

describe("generateRemediationPr — mechanical dependency finding", () => {
  test("bumps a fixture package.json end-to-end (diff-only)", async () => {
    await withFixtureRepo(async (dir) => {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "fixture", dependencies: { lodash: "^4.17.20" } }, null, 2),
        "utf8",
      );

      const finding: DependencyFixFinding = {
        kind: "pinned-dependency-fix-available",
        packageName: "lodash",
        currentVersion: "4.17.20",
        fixedVersion: "4.17.21",
        manifestFile: "package.json",
        cve: "CVE-2021-23337",
      };

      const result = await generateRemediationPr(finding, autoFixableSuggestion, { repoDir: dir });
      expect(result.attempted).toBe(true);
      if (result.attempted) {
        expect(JSON.parse(result.diff.newContent).dependencies.lodash).toBe("^4.17.21");
      }
    });
  });

  test("missing manifest file: not attempted", async () => {
    await withFixtureRepo(async (dir) => {
      mkdirSync(dir, { recursive: true }); // dir exists but no package.json
      const finding: DependencyFixFinding = {
        kind: "pinned-dependency-fix-available",
        packageName: "lodash",
        currentVersion: "4.17.20",
        fixedVersion: "4.17.21",
        manifestFile: "package.json",
      };
      const result = await generateRemediationPr(finding, autoFixableSuggestion, { repoDir: dir });
      expect(result.attempted).toBe(false);
    });
  });
});

describe("generateRemediationPr — non-auto-fixable findings", () => {
  test("a finding with a non-auto-fixable suggestion: no PR-generation attempted at all", async () => {
    await withFixtureRepo(async (dir) => {
      const finding: MissingHeaderFinding = {
        kind: "missing-security-header",
        header: "content-security-policy",
        recommendedValue: "default-src 'self'",
        configFile: "next.config.ts",
        configKind: "next-config",
      };
      const result = await generateRemediationPr(finding, manualOnlySuggestion, { repoDir: dir, openPr: true });
      expect(result.attempted).toBe(false);
      if (!result.attempted) {
        expect(result.reason).toContain("not marked autoFixable");
      }
    });
  });

  test("undefined suggestion: no PR-generation attempted", async () => {
    await withFixtureRepo(async (dir) => {
      const finding: MissingHeaderFinding = {
        kind: "missing-security-header",
        header: "content-security-policy",
        recommendedValue: "default-src 'self'",
        configFile: "next.config.ts",
        configKind: "next-config",
      };
      const result = await generateRemediationPr(finding, undefined, { repoDir: dir });
      expect(result.attempted).toBe(false);
    });
  });
});

describe("generateRemediationPr — self-modification guard", () => {
  test("refuses to open a PR against lyrie-agent's own working tree", async () => {
    const finding: MissingHeaderFinding = {
      kind: "missing-security-header",
      header: "content-security-policy",
      recommendedValue: "default-src 'self'",
      configFile: "packages/ui/next.config.ts",
      configKind: "next-config",
    };
    // repoDir resolves to THIS repo's root — must be refused even with openPr: true.
    const repoRoot = join(import.meta.dir, "..", "..", "..", "..");
    const { runner, calls } = fakeCommandRunner();
    const result = await generateRemediationPr(finding, autoFixableSuggestion, {
      repoDir: repoRoot,
      openPr: true,
      commandRunner: runner,
    });
    expect(result.attempted).toBe(false);
    if (!result.attempted) {
      expect(result.reason).toContain("self-modification guard");
    }
    // Confirms no git/gh command was ever invoked against the real repo.
    expect(calls.length).toBe(0);
  });
});
