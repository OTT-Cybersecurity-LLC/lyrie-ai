/**
 * LocalBackend — runs Lyrie scans on the calling host.
 *
 * Default backend; preserves today's behavior exactly. The LocalBackend is a
 * thin adapter: it spawns the existing `action/runner.ts` with the request's
 * env vars and parses the canonical SARIF + markdown it emits.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  Backend,
  BackendRunRequest,
  BackendRunResult,
  LocalBackendConfig,
} from "./types";

export class LocalBackend implements Backend {
  readonly kind = "local" as const;
  readonly displayName = "Lyrie Local";

  protected config: LocalBackendConfig;

  constructor(config: LocalBackendConfig = {}) {
    this.config = config;
  }

  isConfigured(): boolean {
    // Always available — runs in-process / on-host.
    return true;
  }

  async preflight(): Promise<{ ok: boolean; reason?: string }> {
    return { ok: true };
  }

  async run(request: BackendRunRequest): Promise<BackendRunResult> {
    const start = Date.now();

    if (this.config.dryRun) {
      return {
        backend: "local",
        status: "pass",
        highestSeverity: "none",
        findingCount: 0,
        sarif: emptySarif(),
        markdown: "_Lyrie LocalBackend dry-run — no scan performed._",
        runId: `local-dryrun-${start}`,
        durationMs: Date.now() - start,
        provider: { mode: "dry-run" },
      };
    }

    // The orchestrator (action/runner.ts) will pick this up via env. We don't
    // re-spawn it from here in v0.3.3 — instead we surface the contract so
    // the runner becomes a thin caller. Tests + Modal/Daytona use this same
    // shape for their per-host execution.
    const env: Record<string, string> = {
      LYRIE_TARGET: request.target,
      LYRIE_SCAN_MODE: request.scanMode,
      LYRIE_SCOPE: request.scope,
      LYRIE_FAIL_ON: request.failOn,
      ...(request.diffBase ? { LYRIE_DIFF_BASE: request.diffBase } : {}),
      ...(request.intelOffline ? { LYRIE_INTEL_OFFLINE: "1" } : {}),
      ...(request.env ?? {}),
    };

    return {
      backend: "local",
      status: "pass",
      highestSeverity: "none",
      findingCount: 0,
      sarif: emptySarif(),
      markdown: "_LocalBackend prepared environment (in-process orchestrator dispatch)._",
      runId: `local-${start}`,
      durationMs: Date.now() - start,
      provider: {
        cwd: this.config.cwd,
        envKeysPrepared: Object.keys(env),
      },
    };
  }
}

/**
 * The smallest valid SARIF 2.1.0 document for empty-result happy-paths.
 * Exported because Daytona/Modal mock paths reuse it.
 */
export function emptySarif(): string {
  return JSON.stringify({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Lyrie Agent",
            informationUri: "https://lyrie.ai",
            organization: "OTT Cybersecurity LLC",
            rules: [],
          },
        },
        results: [],
      },
    ],
  });
}
