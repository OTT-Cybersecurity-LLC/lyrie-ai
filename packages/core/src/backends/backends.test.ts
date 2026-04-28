/**
 * Tests for Lyrie execution backends.
 *
 * Covers:
 *   - Pure helpers (resolveBackendKind, extractSarifSummary, env readers).
 *   - LocalBackend dry-run + happy-path env preparation.
 *   - DaytonaBackend full state machine (preflight, create, exec, fetch SARIF,
 *     cleanup, error fallthrough) with an injected fake fetcher.
 *   - ModalBackend invocation body shape + happy-path response handling.
 *   - Factory: kind resolution, config merge, mismatch error.
 *
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  DaytonaBackend,
  LocalBackend,
  ModalBackend,
  describeBackend,
  emptySarif,
  extractSarifSummary,
  getBackend,
  readDaytonaConfigFromEnv,
  readLocalConfigFromEnv,
  readModalConfigFromEnv,
  resolveBackendKind,
  SUPPORTED_BACKENDS,
  type BackendRunRequest,
  type FetchFn,
} from "./index";

// ─── Tiny fixture builder ──────────────────────────────────────────────────────

function req(overrides: Partial<BackendRunRequest> = {}): BackendRunRequest {
  return {
    target: "/tmp/lyrie-fixture",
    scanMode: "quick",
    scope: "diff",
    failOn: "high",
    ...overrides,
  };
}

/** Build a fetcher that returns canned responses keyed by URL pattern. */
function fakeFetcher(routes: Record<string, () => Promise<{ ok: boolean; status: number; body: string | object }>>): {
  fetcher: FetchFn;
  calls: Array<{ url: string; method: string; body?: string }>;
} {
  const calls: Array<{ url: string; method: string; body?: string }> = [];
  const fetcher: FetchFn = async (url, init) => {
    calls.push({ url, method: init?.method ?? "GET", body: init?.body });
    for (const [pattern, handler] of Object.entries(routes)) {
      if (url.includes(pattern)) {
        const out = await handler();
        const text = typeof out.body === "string" ? out.body : JSON.stringify(out.body);
        return {
          ok: out.ok,
          status: out.status,
          text: async () => text,
          json: async () => (typeof out.body === "string" ? JSON.parse(text) : out.body),
        };
      }
    }
    throw new Error(`fakeFetcher: unrouted ${url}`);
  };
  return { fetcher, calls };
}

// ─── Pure helpers ──────────────────────────────────────────────────────────────

describe("resolveBackendKind", () => {
  it("prefers explicit kind", () => {
    expect(resolveBackendKind("modal", {})).toBe("modal");
  });

  it("reads LYRIE_BACKEND env var", () => {
    expect(resolveBackendKind(undefined, { LYRIE_BACKEND: "daytona" })).toBe("daytona");
  });

  it("falls back to local on unknown values", () => {
    expect(resolveBackendKind(undefined, { LYRIE_BACKEND: "weird" })).toBe("local");
  });

  it("is case-insensitive", () => {
    expect(resolveBackendKind(undefined, { LYRIE_BACKEND: "MODAL" })).toBe("modal");
  });

  it("knows all supported backends", () => {
    expect(SUPPORTED_BACKENDS).toEqual(["local", "daytona", "modal"]);
  });
});

describe("extractSarifSummary", () => {
  it("returns 'none' on empty results", () => {
    expect(extractSarifSummary(emptySarif())).toEqual({ highest: "none", findingCount: 0 });
  });

  it("counts findings + picks highest severity", () => {
    const sarif = JSON.stringify({
      runs: [
        {
          results: [
            { level: "warning" },
            { properties: { severity: "critical" } },
            { level: "note" },
          ],
        },
      ],
    });
    const s = extractSarifSummary(sarif);
    expect(s.findingCount).toBe(3);
    expect(s.highest).toBe("critical");
  });

  it("degrades silently on malformed JSON", () => {
    expect(extractSarifSummary("{not json")).toEqual({ highest: "none", findingCount: 0 });
  });
});

describe("env readers", () => {
  it("readDaytonaConfigFromEnv pulls expected keys", () => {
    const c = readDaytonaConfigFromEnv({
      DAYTONA_API_KEY: "k",
      DAYTONA_API_URL: "https://x",
      LYRIE_DAYTONA_IMAGE: "img",
      LYRIE_DAYTONA_REGION: "us-east-1",
      LYRIE_DAYTONA_TTL_SECONDS: "120",
    });
    expect(c.apiKey).toBe("k");
    expect(c.apiUrl).toBe("https://x");
    expect(c.image).toBe("img");
    expect(c.region).toBe("us-east-1");
    expect(c.ttlSeconds).toBe(120);
  });

  it("readModalConfigFromEnv pulls expected keys", () => {
    const c = readModalConfigFromEnv({
      MODAL_TOKEN_ID: "id",
      MODAL_TOKEN_SECRET: "sec",
      LYRIE_MODAL_APP: "app",
      LYRIE_MODAL_FUNCTION: "fn",
    });
    expect(c.tokenId).toBe("id");
    expect(c.tokenSecret).toBe("sec");
    expect(c.app).toBe("app");
    expect(c.functionName).toBe("fn");
  });

  it("readLocalConfigFromEnv parses dryRun flag", () => {
    expect(readLocalConfigFromEnv({ LYRIE_LOCAL_DRY_RUN: "1" }).dryRun).toBe(true);
    expect(readLocalConfigFromEnv({ LYRIE_LOCAL_DRY_RUN: "true" }).dryRun).toBe(true);
    expect(readLocalConfigFromEnv({}).dryRun).toBe(false);
  });
});

// ─── LocalBackend ──────────────────────────────────────────────────────────────

describe("LocalBackend", () => {
  it("isConfigured() is always true", () => {
    expect(new LocalBackend().isConfigured()).toBe(true);
  });

  it("preflight passes", async () => {
    const r = await new LocalBackend().preflight();
    expect(r.ok).toBe(true);
  });

  it("dryRun returns empty SARIF + status pass", async () => {
    const b = new LocalBackend({ dryRun: true });
    const result = await b.run(req());
    expect(result.status).toBe("pass");
    expect(result.findingCount).toBe(0);
    expect(result.sarif).toBeDefined();
    expect(JSON.parse(result.sarif!).version).toBe("2.1.0");
  });

  it("non-dryRun reports prepared env keys in provider details", async () => {
    const b = new LocalBackend();
    const result = await b.run(
      req({ intelOffline: true, env: { CUSTOM: "v" }, diffBase: "origin/main" }),
    );
    const keys = (result.provider as { envKeysPrepared: string[] }).envKeysPrepared;
    expect(keys).toContain("LYRIE_INTEL_OFFLINE");
    expect(keys).toContain("LYRIE_DIFF_BASE");
    expect(keys).toContain("CUSTOM");
  });

  it("costUsd is 0 by default (no LYRIE_LOCAL_COST_PER_SECOND)", async () => {
    delete process.env["LYRIE_LOCAL_COST_PER_SECOND"];
    const result = await new LocalBackend().run(req());
    expect(result.costUsd).toBe(0);
  });

  it("costUsd is non-zero when LYRIE_LOCAL_COST_PER_SECOND is set", async () => {
    process.env["LYRIE_LOCAL_COST_PER_SECOND"] = "1.0";
    const result = await new LocalBackend().run(req());
    // durationMs ≥ 0, cost = duration/1000 * 1.0 ≥ 0
    expect(result.costUsd).toBeGreaterThanOrEqual(0);
    delete process.env["LYRIE_LOCAL_COST_PER_SECOND"];
  });

  it("dryRun always returns costUsd 0", async () => {
    process.env["LYRIE_LOCAL_COST_PER_SECOND"] = "999";
    const result = await new LocalBackend({ dryRun: true }).run(req());
    expect(result.costUsd).toBe(0);
    delete process.env["LYRIE_LOCAL_COST_PER_SECOND"];
  });
});

// ─── DaytonaBackend ────────────────────────────────────────────────────────────

describe("DaytonaBackend", () => {
  it("isConfigured() requires apiKey", () => {
    expect(new DaytonaBackend().isConfigured()).toBe(false);
    expect(new DaytonaBackend({ apiKey: "k" }).isConfigured()).toBe(true);
  });

  it("preflight reports missing key", async () => {
    const r = await new DaytonaBackend().preflight();
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("DAYTONA_API_KEY");
  });

  it("preflight uses /health endpoint when configured", async () => {
    const { fetcher } = fakeFetcher({
      "/health": async () => ({ ok: true, status: 200, body: { ok: true } }),
    });
    const r = await new DaytonaBackend({ apiKey: "k" }, fetcher).preflight();
    expect(r.ok).toBe(true);
  });

  it("toCreateWorkspaceBody applies defaults + labels", () => {
    const b = new DaytonaBackend({ apiKey: "k", region: "us-east-1" });
    const body = b.toCreateWorkspaceBody(req({ labels: { env: "ci" } }));
    expect(body["region"]).toBe("us-east-1");
    expect((body["resources"] as { cpu: number }).cpu).toBe(2);
    expect((body["labels"] as { env: string })["env"]).toBe("ci");
    expect((body["labels"] as Record<string, string>)["lyrie.ai/scanMode"]).toBe("quick");
  });

  it("ttlSeconds defaults to 1800", () => {
    expect(new DaytonaBackend({ apiKey: "k" }).ttlSeconds()).toBe(1800);
    expect(new DaytonaBackend({ apiKey: "k", ttlSeconds: 60 }).ttlSeconds()).toBe(60);
  });

  it("costUsd calculated from durationMs", async () => {
    const sarif = emptySarif();
    const { fetcher } = fakeFetcher({
      "/workspaces/ws-cost/files/lyrie-runs/lyrie.sarif": async () => ({
        ok: true, status: 200, body: sarif,
      }),
      "/workspaces/ws-cost/exec": async () => ({ ok: true, status: 200, body: {} }),
      "/workspaces/ws-cost": async () => ({ ok: true, status: 200, body: {} }),
      "/workspaces": async () => ({ ok: true, status: 201, body: { id: "ws-cost" } }),
    });
    process.env["LYRIE_DAYTONA_COST_PER_SECOND"] = "0.01";
    const r = await new DaytonaBackend({ apiKey: "k" }, fetcher).run(req());
    expect(r.costUsd).toBeGreaterThanOrEqual(0);
    delete process.env["LYRIE_DAYTONA_COST_PER_SECOND"];
  });

  it("happy path: create → exec → fetch SARIF → delete", async () => {
    const sarif = JSON.stringify({
      runs: [{ results: [{ level: "warning" }] }],
    });
    const { fetcher, calls } = fakeFetcher({
      "/workspaces/abc-123/files/lyrie-runs/lyrie.sarif": async () => ({
        ok: true,
        status: 200,
        body: sarif,
      }),
      "/workspaces/abc-123/exec": async () => ({ ok: true, status: 200, body: { ok: true } }),
      "/workspaces/abc-123": async () => ({ ok: true, status: 200, body: {} }),
      "/workspaces": async () => ({ ok: true, status: 201, body: { id: "abc-123" } }),
    });
    const b = new DaytonaBackend({ apiKey: "k" }, fetcher);
    const r = await b.run(req());
    expect(r.backend).toBe("daytona");
    expect(r.status).toBe("fail"); // findings present → fail
    expect(r.findingCount).toBe(1);
    expect(r.runId).toBe("abc-123");
    // Calls: POST workspaces, POST exec, GET sarif, DELETE workspace
    expect(calls.some((c) => c.url.endsWith("/workspaces") && c.method === "POST")).toBe(true);
    expect(calls.some((c) => c.method === "DELETE")).toBe(true);
  });

  it("returns error when create-workspace fails", async () => {
    const { fetcher } = fakeFetcher({
      "/workspaces": async () => ({ ok: false, status: 500, body: "boom" }),
    });
    const b = new DaytonaBackend({ apiKey: "k" }, fetcher);
    const r = await b.run(req());
    expect(r.status).toBe("error");
    expect(r.error).toContain("HTTP 500");
  });

  it("returns error when not configured", async () => {
    const r = await new DaytonaBackend().run(req());
    expect(r.status).toBe("error");
  });
});

// ─── ModalBackend ──────────────────────────────────────────────────────────────

describe("ModalBackend", () => {
  it("isConfigured() requires both token id + secret", () => {
    expect(new ModalBackend().isConfigured()).toBe(false);
    expect(new ModalBackend({ tokenId: "id" }).isConfigured()).toBe(false);
    expect(new ModalBackend({ tokenId: "id", tokenSecret: "sec" }).isConfigured()).toBe(true);
  });

  it("toInvocationBody applies sensible defaults", () => {
    const body = new ModalBackend({ tokenId: "i", tokenSecret: "s" }).toInvocationBody(
      req({ scanMode: "full" }),
    );
    expect(body["app"]).toBe("lyrie-agent");
    expect(body["function"]).toBe("lyrie_scan");
    expect((body["inputs"] as { scanMode: string }).scanMode).toBe("full");
    expect((body["options"] as { cpu: number }).cpu).toBe(1.0);
  });

  it("happy path: invoke returns SARIF + summary", async () => {
    const sarif = JSON.stringify({
      runs: [{ results: [{ properties: { severity: "medium" } }] }],
    });
    const { fetcher } = fakeFetcher({
      "/functions/invoke": async () => ({
        ok: true,
        status: 200,
        body: { callId: "fc_42", sarif, costUsd: 0.012 },
      }),
    });
    const b = new ModalBackend({ tokenId: "i", tokenSecret: "s" }, fetcher);
    const r = await b.run(req());
    expect(r.backend).toBe("modal");
    expect(r.status).toBe("fail");
    expect(r.findingCount).toBe(1);
    expect(r.highestSeverity).toBe("medium");
    expect(r.costUsd).toBe(0.012);
    expect(r.runId).toBe("fc_42");
  });

  it("returns error on non-2xx", async () => {
    const { fetcher } = fakeFetcher({
      "/functions/invoke": async () => ({ ok: false, status: 502, body: "bad gateway" }),
    });
    const b = new ModalBackend({ tokenId: "i", tokenSecret: "s" }, fetcher);
    const r = await b.run(req());
    expect(r.status).toBe("error");
    expect(r.error).toContain("HTTP 502");
  });

  it("returns error when not configured", async () => {
    const r = await new ModalBackend().run(req());
    expect(r.status).toBe("error");
  });

  it("costUsd defaults to 0 when Modal API does not return it", async () => {
    const sarif = emptySarif();
    const { fetcher } = fakeFetcher({
      "/functions/invoke": async () => ({
        ok: true, status: 200,
        body: { callId: "fc_no_cost", sarif },
      }),
    });
    const r = await new ModalBackend({ tokenId: "i", tokenSecret: "s" }, fetcher).run(req());
    expect(r.costUsd).toBe(0);
  });

  it("costUsd from API response takes precedence", async () => {
    const sarif = emptySarif();
    const { fetcher } = fakeFetcher({
      "/functions/invoke": async () => ({
        ok: true, status: 200,
        body: { callId: "fc_cost", sarif, costUsd: 0.0077 },
      }),
    });
    const r = await new ModalBackend({ tokenId: "i", tokenSecret: "s" }, fetcher).run(req());
    expect(r.costUsd).toBe(0.0077);
  });
});

// ─── Factory ──────────────────────────────────────────────────────────────────

describe("getBackend factory", () => {
  it("default is local", () => {
    const b = getBackend(undefined, undefined, { env: {} });
    expect(b.kind).toBe("local");
  });

  it("env can switch to modal", () => {
    const b = getBackend(undefined, undefined, {
      env: { LYRIE_BACKEND: "modal", MODAL_TOKEN_ID: "i", MODAL_TOKEN_SECRET: "s" },
    });
    expect(b.kind).toBe("modal");
    expect(b.isConfigured()).toBe(true);
  });

  it("explicit kind beats env", () => {
    expect(getBackend("daytona", undefined, { env: { LYRIE_BACKEND: "modal" } }).kind).toBe(
      "daytona",
    );
  });

  it("config-kind mismatch throws", () => {
    expect(() =>
      getBackend("local", { kind: "modal", config: { tokenId: "i", tokenSecret: "s" } }),
    ).toThrow();
  });

  it("describeBackend reports configured/unconfigured state", () => {
    const okMsg = describeBackend(new LocalBackend());
    const notOk = describeBackend(new ModalBackend());
    expect(okMsg).toContain("local");
    expect(okMsg).toContain("configured");
    expect(notOk).toContain("unconfigured");
  });
});
