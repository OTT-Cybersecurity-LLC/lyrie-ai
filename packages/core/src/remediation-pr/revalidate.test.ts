/**
 * revalidate.test.ts — sandboxed re-validation of auto-remediation PRs +
 * proof-of-fix attachment. Every backend/gh interaction is faked — no real
 * sandbox spin-up, no real `gh` calls, per the same "never touch a real
 * repo/registry from tests" discipline as generate.test.ts.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import type { CommandRunner } from "./pr";
import type { MissingHeaderFinding, DependencyFixFinding } from "./types";
import type { Backend, BackendRunRequest, BackendRunResult } from "../backends/types";
import { emptySarif } from "../backends/local";
import {
  revalidateRemediation,
  buildProofOfFixComment,
  attachProofOfFix,
  revalidateAndAttach,
} from "./revalidate";

const HEADER_FINDING: MissingHeaderFinding = {
  kind: "missing-security-header",
  header: "content-security-policy",
  recommendedValue: "default-src 'self'",
  configFile: "next.config.ts",
  configKind: "next-config",
};

const DEP_FINDING: DependencyFixFinding = {
  kind: "pinned-dependency-fix-available",
  packageName: "lodash",
  currentVersion: "4.17.20",
  fixedVersion: "4.17.21",
  manifestFile: "package.json",
  cve: "CVE-2021-23337",
};

function fakeBackend(result: Partial<BackendRunResult>, preflightOk = true): Backend {
  return {
    kind: "local",
    displayName: "Fake Backend",
    isConfigured: () => true,
    preflight: async () => (preflightOk ? { ok: true } : { ok: false, reason: "not configured" }),
    run: async (_req: BackendRunRequest): Promise<BackendRunResult> => ({
      backend: "local",
      status: "pass",
      highestSeverity: "none",
      findingCount: 0,
      sarif: emptySarif(),
      durationMs: 5,
      costUsd: 0,
      ...result,
    }),
  };
}

function throwingBackend(): Backend {
  return {
    kind: "modal",
    displayName: "Throwing Backend",
    isConfigured: () => true,
    preflight: async () => ({ ok: true }),
    run: async () => {
      throw new Error("sandbox exploded");
    },
  };
}

function fakeCommandRunner(): { runner: CommandRunner; calls: Array<{ cmd: string; args: string[] }> } {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const runner: CommandRunner = async (cmd, args) => {
    calls.push({ cmd, args });
    return { stdout: "", stderr: "" };
  };
  return { runner, calls };
}

// ─── revalidateRemediation — backend-driven path ─────────────────────────────

describe("revalidateRemediation — sandboxed backend re-run", () => {
  test("backend reports pass (0 findings) → verified-fixed", async () => {
    const backend = fakeBackend({ status: "pass", findingCount: 0 });
    const result = await revalidateRemediation({
      repoDir: "/tmp/fixture-repo",
      finding: HEADER_FINDING,
      backend,
    });
    expect(result.status).toBe("verified-fixed");
    expect(result.backend).toBe("local");
    expect(result.summary).toContain("appears fixed");
  });

  test("backend reports fail (findings remain) → still-vulnerable", async () => {
    const backend = fakeBackend({ status: "fail", findingCount: 2, highestSeverity: "high" });
    const result = await revalidateRemediation({
      repoDir: "/tmp/fixture-repo",
      finding: DEP_FINDING,
      backend,
    });
    expect(result.status).toBe("still-vulnerable");
    expect(result.summary).toContain("still reports 2 finding");
  });

  test("backend preflight failure → inconclusive, never claims a pass", async () => {
    const backend = fakeBackend({}, false);
    const result = await revalidateRemediation({
      repoDir: "/tmp/fixture-repo",
      finding: HEADER_FINDING,
      backend,
    });
    expect(result.status).toBe("inconclusive");
    expect(result.summary).toContain("not ready");
  });

  test("backend.run() throwing → inconclusive, not a false pass", async () => {
    const backend = throwingBackend();
    const result = await revalidateRemediation({
      repoDir: "/tmp/fixture-repo",
      finding: HEADER_FINDING,
      backend,
    });
    expect(result.status).toBe("inconclusive");
    expect(result.summary).toContain("threw during re-validation");
  });

  test("backend status='error' → inconclusive", async () => {
    const backend = fakeBackend({ status: "error", error: "workspace creation failed" });
    const result = await revalidateRemediation({
      repoDir: "/tmp/fixture-repo",
      finding: HEADER_FINDING,
      backend,
    });
    expect(result.status).toBe("inconclusive");
    expect(result.summary).toContain("workspace creation failed");
  });

  test("calls backend.cleanup() even when run() succeeds", async () => {
    let cleanedUp = false;
    const backend: Backend = {
      ...fakeBackend({ status: "pass" }),
      cleanup: async () => {
        cleanedUp = true;
      },
    };
    await revalidateRemediation({ repoDir: "/tmp/x", finding: HEADER_FINDING, backend });
    expect(cleanedUp).toBe(true);
  });

  test("cleanup() throwing does not mask the real verdict", async () => {
    const backend: Backend = {
      ...fakeBackend({ status: "pass" }),
      cleanup: async () => {
        throw new Error("cleanup boom");
      },
    };
    const result = await revalidateRemediation({ repoDir: "/tmp/x", finding: HEADER_FINDING, backend });
    expect(result.status).toBe("verified-fixed");
  });
});

// ─── revalidateRemediation — focused verify callback path ────────────────────

describe("revalidateRemediation — focused verify callback", () => {
  test("callback returning true → verified-fixed, backend never invoked", async () => {
    let backendCalled = false;
    const backend: Backend = {
      ...fakeBackend({}),
      run: async () => {
        backendCalled = true;
        throw new Error("should never be called");
      },
    };
    const result = await revalidateRemediation({
      repoDir: "/tmp/x",
      finding: HEADER_FINDING,
      backend,
      verify: async () => true,
    });
    expect(result.status).toBe("verified-fixed");
    expect(result.backend).toBe("focused-verify-callback");
    expect(backendCalled).toBe(false);
  });

  test("callback returning false → still-vulnerable", async () => {
    const result = await revalidateRemediation({
      repoDir: "/tmp/x",
      finding: HEADER_FINDING,
      verify: async () => false,
    });
    expect(result.status).toBe("still-vulnerable");
  });

  test("callback throwing → inconclusive", async () => {
    const result = await revalidateRemediation({
      repoDir: "/tmp/x",
      finding: HEADER_FINDING,
      verify: async () => {
        throw new Error("curl failed: ECONNREFUSED");
      },
    });
    expect(result.status).toBe("inconclusive");
    expect(result.summary).toContain("ECONNREFUSED");
  });
});

// ─── revalidateRemediation — safe-by-default dry-run path ────────────────────

describe("revalidateRemediation — dryRun default (no backend, no verify)", () => {
  test("dryRun:true uses LocalBackend dry-run and reports verified-fixed with 0 findings", async () => {
    const result = await revalidateRemediation({
      repoDir: "/tmp/x",
      finding: HEADER_FINDING,
      dryRun: true,
    });
    expect(result.status).toBe("verified-fixed");
    expect(result.backend).toBe("local");
  });
});

// ─── buildProofOfFixComment ───────────────────────────────────────────────────

describe("buildProofOfFixComment", () => {
  test("verified-fixed renders a ✅ header and includes backend details", () => {
    const md = buildProofOfFixComment({
      status: "verified-fixed",
      backend: "daytona",
      backendResult: {
        backend: "daytona",
        status: "pass",
        highestSeverity: "none",
        findingCount: 0,
        durationMs: 4200,
        costUsd: 0.0123,
        runId: "ws-abc123",
      },
      summary: "Sandboxed re-scan found 0 qualifying findings.",
      durationMs: 4321,
    });
    expect(md).toContain("✅");
    expect(md).toContain("verified-fixed");
    expect(md).toContain("daytona");
    expect(md).toContain("ws-abc123");
    expect(md).toContain("Lyrie");
  });

  test("inconclusive renders a ⚠️ header without backendResult section", () => {
    const md = buildProofOfFixComment({
      status: "inconclusive",
      backend: "local",
      summary: "Backend was not ready.",
      durationMs: 10,
    });
    expect(md).toContain("⚠️");
    expect(md).not.toContain("<details>");
  });

  test("still-vulnerable renders a ❌ header", () => {
    const md = buildProofOfFixComment({
      status: "still-vulnerable",
      backend: "modal",
      summary: "Still vulnerable.",
      durationMs: 10,
    });
    expect(md).toContain("❌");
  });
});

// ─── attachProofOfFix ──────────────────────────────────────────────────────────

describe("attachProofOfFix", () => {
  test("invokes `gh pr comment` with the rendered markdown, never a real subprocess in tests", async () => {
    const { runner, calls } = fakeCommandRunner();
    const result = await attachProofOfFix({
      repoDir: "/tmp/fixture-repo",
      pr: "https://github.com/example/fixture/pull/1",
      result: {
        status: "verified-fixed",
        backend: "local",
        summary: "All good.",
        durationMs: 12,
      },
      commandRunner: runner,
    });
    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe("gh");
    expect(calls[0].args).toContain("comment");
    expect(calls[0].args).toContain("https://github.com/example/fixture/pull/1");
    expect(calls[0].args.join(" ")).toContain("Lyrie Self-Heal");
  });

  test("command runner failure surfaces ok:false with an error message", async () => {
    const failingRunner: CommandRunner = async () => {
      throw new Error("gh: command not found");
    };
    const result = await attachProofOfFix({
      repoDir: "/tmp/x",
      pr: "1",
      result: { status: "verified-fixed", backend: "local", summary: "ok", durationMs: 1 },
      commandRunner: failingRunner,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toContain("gh: command not found");
  });
});

// ─── revalidateAndAttach (end-to-end) ─────────────────────────────────────────

describe("revalidateAndAttach", () => {
  test("re-validates and attaches proof-of-fix when a PR was actually opened", async () => {
    const backend = fakeBackend({ status: "pass" });
    const { runner, calls } = fakeCommandRunner();

    const { revalidation, attach } = await revalidateAndAttach(
      { repoDir: "/tmp/fixture-repo", finding: HEADER_FINDING, backend },
      { ok: true, prUrl: "https://github.com/example/fixture/pull/7" },
      runner,
    );

    expect(revalidation.status).toBe("verified-fixed");
    expect(attach?.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].args).toContain("https://github.com/example/fixture/pull/7");
  });

  test("does not attempt to attach anything when no PR was opened", async () => {
    const backend = fakeBackend({ status: "pass" });
    const { runner, calls } = fakeCommandRunner();

    const { revalidation, attach } = await revalidateAndAttach(
      { repoDir: "/tmp/fixture-repo", finding: HEADER_FINDING, backend },
      undefined,
      runner,
    );

    expect(revalidation.status).toBe("verified-fixed");
    expect(attach).toBeUndefined();
    expect(calls).toHaveLength(0);
  });

  test("does not attempt to attach anything when PR open failed", async () => {
    const backend = fakeBackend({ status: "pass" });
    const { runner, calls } = fakeCommandRunner();

    const { attach } = await revalidateAndAttach(
      { repoDir: "/tmp/fixture-repo", finding: HEADER_FINDING, backend },
      { ok: false, error: "push rejected" },
      runner,
    );

    expect(attach).toBeUndefined();
    expect(calls).toHaveLength(0);
  });
});
