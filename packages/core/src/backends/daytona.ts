/**
 * DaytonaBackend — runs Lyrie scans inside a Daytona devbox.
 *
 * Daytona (https://daytona.io) provisions ephemeral, snapshot-based dev
 * environments. The DaytonaBackend:
 *
 *   1. Calls Daytona's REST API to create a workspace from a Lyrie image.
 *   2. Uploads the target (or clones the git URL) into the workspace.
 *   3. Executes `bun run action/runner.ts` inside the workspace.
 *   4. Streams stdout/SARIF back to the caller.
 *   5. Tears the workspace down (TTL fallback if cleanup fails).
 *
 * Network calls are isolated behind tiny `httpJson` / `httpStream` helpers so
 * tests can drive the whole flow with a fake fetch. v0.3.3 ships the contract
 * + state machine + happy-path; live Daytona ops happen behind LYRIE_LIVE=1
 * integration tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import { emptySarif } from "./local";
import type {
  Backend,
  BackendRunRequest,
  BackendRunResult,
  DaytonaBackendConfig,
} from "./types";

const DEFAULT_API = "https://app.daytona.io/api";
const DEFAULT_IMAGE = "ghcr.io/overthetopseo/lyrie-agent:latest";
const DEFAULT_TTL = 1800; // 30 min — long enough for full scan, short enough to avoid cost drift

export type FetchFn = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; text: () => Promise<string>; json: () => Promise<unknown> }>;

export class DaytonaBackend implements Backend {
  readonly kind = "daytona" as const;
  readonly displayName = "Lyrie · Daytona";

  protected config: DaytonaBackendConfig;
  /** Fetch hook — overridable in tests. */
  protected fetcher: FetchFn;

  constructor(config: DaytonaBackendConfig = {}, fetcher?: FetchFn) {
    this.config = config;
    this.fetcher = fetcher ?? defaultFetch();
  }

  isConfigured(): boolean {
    return Boolean(this.config.apiKey);
  }

  apiBase(): string {
    return (this.config.apiUrl ?? DEFAULT_API).replace(/\/$/, "");
  }

  image(): string {
    return this.config.image ?? DEFAULT_IMAGE;
  }

  ttlSeconds(): number {
    return this.config.ttlSeconds ?? DEFAULT_TTL;
  }

  async preflight(): Promise<{ ok: boolean; reason?: string }> {
    if (!this.isConfigured()) {
      return { ok: false, reason: "missing DAYTONA_API_KEY" };
    }
    try {
      const res = await this.fetcher(`${this.apiBase()}/health`, {
        method: "GET",
        headers: this.headers(),
      });
      if (!res.ok) return { ok: false, reason: `daytona /health -> HTTP ${res.status}` };
      return { ok: true };
    } catch (err) {
      return { ok: false, reason: `daytona unreachable: ${(err as Error).message}` };
    }
  }

  /**
   * Translate a BackendRunRequest into the JSON body the Daytona create-
   * workspace endpoint expects. Pure & test-friendly.
   */
  toCreateWorkspaceBody(request: BackendRunRequest): Record<string, unknown> {
    return {
      name: `lyrie-${Date.now()}`,
      image: this.image(),
      region: this.config.region,
      labels: {
        "lyrie.ai/scanMode": request.scanMode,
        "lyrie.ai/scope": request.scope,
        ...(request.labels ?? {}),
      },
      env: {
        LYRIE_TARGET: "/workspace/target",
        LYRIE_SCAN_MODE: request.scanMode,
        LYRIE_SCOPE: request.scope,
        LYRIE_FAIL_ON: request.failOn,
        ...(request.diffBase ? { LYRIE_DIFF_BASE: request.diffBase } : {}),
        ...(request.intelOffline ? { LYRIE_INTEL_OFFLINE: "1" } : {}),
        ...(request.env ?? {}),
      },
      resources: {
        cpu: request.resources?.cpu ?? 2,
        memoryMb: request.resources?.memoryMb ?? 2048,
        arch: request.resources?.arch ?? "x86_64",
      },
      ttlSeconds: this.ttlSeconds(),
      target: request.target,
    };
  }

  async run(request: BackendRunRequest): Promise<BackendRunResult> {
    const start = Date.now();
    if (!this.isConfigured()) {
      return {
        backend: "daytona",
        status: "error",
        highestSeverity: "none",
        findingCount: 0,
        durationMs: Date.now() - start,
        costUsd: 0,
        error: "daytona backend not configured (missing apiKey)",
      };
    }

    let workspaceId: string | undefined;
    try {
      // 1. Create workspace
      const createRes = await this.fetcher(`${this.apiBase()}/workspaces`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(this.toCreateWorkspaceBody(request)),
      });
      if (!createRes.ok) {
        return this.fail(start, `create workspace HTTP ${createRes.status}`);
      }
      const created = (await createRes.json()) as { id: string };
      workspaceId = created.id;

      // 2. Trigger scan command (Daytona exec endpoint)
      const execRes = await this.fetcher(
        `${this.apiBase()}/workspaces/${workspaceId}/exec`,
        {
          method: "POST",
          headers: this.headers(),
          body: JSON.stringify({
            command: "bun run action/runner.ts",
            cwd: "/workspace/lyrie-agent",
            timeoutSeconds:
              request.resources?.timeoutSeconds ?? this.ttlSeconds() - 60,
          }),
        },
      );
      if (!execRes.ok) {
        return this.fail(start, `exec HTTP ${execRes.status}`, workspaceId);
      }

      // 3. Pull SARIF
      const sarifRes = await this.fetcher(
        `${this.apiBase()}/workspaces/${workspaceId}/files/lyrie-runs/lyrie.sarif`,
        { method: "GET", headers: this.headers() },
      );
      const sarif = sarifRes.ok ? await sarifRes.text() : emptySarif();

      const durationMs = Date.now() - start;
      const rate = parseFloat(
        process.env["LYRIE_DAYTONA_COST_PER_SECOND"] ?? "0",
      ) || 0;
      const costUsd = (durationMs / 1000) * rate;
      console.log(
        `[daytona] workspace ${workspaceId} cost: $${costUsd.toFixed(4)} (${durationMs}ms @ $${rate}/sec)`,
      );
      const summary = extractSarifSummary(sarif);
      return {
        backend: "daytona",
        status: summary.findingCount > 0 ? "fail" : "pass",
        highestSeverity: summary.highest,
        findingCount: summary.findingCount,
        sarif,
        markdown: `_Lyrie Daytona run · workspace=${workspaceId}_`,
        runId: workspaceId,
        durationMs,
        costUsd,
        provider: {
          image: this.image(),
          region: this.config.region,
          ttlSeconds: this.ttlSeconds(),
        },
      };
    } catch (err) {
      return this.fail(start, (err as Error).message, workspaceId);
    } finally {
      if (workspaceId) {
        // Best-effort cleanup; TTL is the safety net.
        await this.fetcher(`${this.apiBase()}/workspaces/${workspaceId}`, {
          method: "DELETE",
          headers: this.headers(),
        }).catch(() => {});
      }
    }
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.config.apiKey ?? ""}`,
      "Content-Type": "application/json",
      "User-Agent": "lyrie-agent/0.3.3 (https://lyrie.ai)",
    };
  }

  private fail(
    start: number,
    error: string,
    workspaceId?: string,
  ): BackendRunResult {
    return {
      backend: "daytona",
      status: "error",
      highestSeverity: "none",
      findingCount: 0,
      runId: workspaceId,
      durationMs: Date.now() - start,
      costUsd: 0,
      error,
    };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Pull severity / count summary out of a SARIF document. Lenient — any parse
 * error degrades to "no findings".
 */
export function extractSarifSummary(sarif: string): {
  highest: BackendRunResult["highestSeverity"];
  findingCount: number;
} {
  try {
    const doc = JSON.parse(sarif) as {
      runs?: Array<{
        results?: Array<{ level?: string; properties?: { severity?: string } }>;
      }>;
    };
    const results = doc.runs?.flatMap((r) => r.results ?? []) ?? [];
    if (results.length === 0) return { highest: "none", findingCount: 0 };
    const order = ["critical", "high", "medium", "low", "info", "none"] as const;
    let highest: BackendRunResult["highestSeverity"] = "none";
    for (const r of results) {
      const sev =
        (r.properties?.severity as string | undefined) ??
        sarifLevelToSeverity(r.level);
      if (order.indexOf(sev as typeof order[number]) <
          order.indexOf(highest as typeof order[number])) {
        highest = sev as typeof order[number];
      }
    }
    return { highest, findingCount: results.length };
  } catch {
    return { highest: "none", findingCount: 0 };
  }
}

function sarifLevelToSeverity(
  level: string | undefined,
): BackendRunResult["highestSeverity"] {
  switch (level) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    default:
      return "info";
  }
}

// ─── Default fetcher (Bun / browser / Node 18+ all expose globalThis.fetch) ────

function defaultFetch(): FetchFn {
  return async (url, init) => {
    const res = await fetch(url, init as RequestInit | undefined);
    return {
      ok: res.ok,
      status: res.status,
      text: () => res.text(),
      json: () => res.json(),
    };
  };
}
