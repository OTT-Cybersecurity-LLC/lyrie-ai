/**
 * ModalBackend — runs Lyrie scans inside a Modal serverless function.
 *
 * Modal (https://modal.com) is a Python-first serverless cloud where each
 * "function" can declare its own image, GPU, and concurrency. Lyrie's Modal
 * deployment exposes a single function — `lyrie_scan` — that takes the same
 * BackendRunRequest payload and returns a BackendRunResult-shaped JSON.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import { emptySarif } from "./local";
import { extractSarifSummary, type FetchFn } from "./daytona";
import type {
  Backend,
  BackendRunRequest,
  BackendRunResult,
  ModalBackendConfig,
} from "./types";

const DEFAULT_APP = "lyrie-agent";
const DEFAULT_FN = "lyrie_scan";
const MODAL_API = "https://api.modal.com/v1";

export class ModalBackend implements Backend {
  readonly kind = "modal" as const;
  readonly displayName = "Lyrie · Modal";

  protected config: ModalBackendConfig;
  protected fetcher: FetchFn;

  constructor(config: ModalBackendConfig = {}, fetcher?: FetchFn) {
    this.config = config;
    this.fetcher = fetcher ?? defaultFetch();
  }

  app(): string {
    return this.config.app ?? DEFAULT_APP;
  }

  functionName(): string {
    return this.config.functionName ?? DEFAULT_FN;
  }

  isConfigured(): boolean {
    return Boolean(this.config.tokenId && this.config.tokenSecret);
  }

  async preflight(): Promise<{ ok: boolean; reason?: string }> {
    if (!this.isConfigured()) {
      return { ok: false, reason: "missing MODAL_TOKEN_ID/MODAL_TOKEN_SECRET" };
    }
    try {
      const res = await this.fetcher(`${MODAL_API}/health`, {
        method: "GET",
        headers: this.headers(),
      });
      if (!res.ok) return { ok: false, reason: `modal /health -> HTTP ${res.status}` };
      return { ok: true };
    } catch (err) {
      return { ok: false, reason: `modal unreachable: ${(err as Error).message}` };
    }
  }

  /**
   * Translate a BackendRunRequest into the body Modal's function-invocation
   * endpoint expects.  Pure & test-friendly.
   */
  toInvocationBody(request: BackendRunRequest): Record<string, unknown> {
    return {
      app: this.app(),
      function: this.functionName(),
      inputs: {
        target: request.target,
        scanMode: request.scanMode,
        scope: request.scope,
        diffBase: request.diffBase,
        failOn: request.failOn,
        intelOffline: request.intelOffline ?? false,
        env: request.env ?? {},
      },
      options: {
        cpu: request.resources?.cpu ?? 1.0,
        memoryMb: request.resources?.memoryMb ?? 1024,
        timeoutSeconds: request.resources?.timeoutSeconds ?? 600,
        ...(this.config.gpu ? { gpu: this.config.gpu } : {}),
        region: this.config.region,
      },
      labels: request.labels,
    };
  }

  async run(request: BackendRunRequest): Promise<BackendRunResult> {
    const start = Date.now();
    if (!this.isConfigured()) {
      return {
        backend: "modal",
        status: "error",
        highestSeverity: "none",
        findingCount: 0,
        durationMs: Date.now() - start,
        error: "modal backend not configured (missing tokenId/tokenSecret)",
      };
    }
    try {
      const res = await this.fetcher(`${MODAL_API}/functions/invoke`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(this.toInvocationBody(request)),
      });
      if (!res.ok) {
        return {
          backend: "modal",
          status: "error",
          highestSeverity: "none",
          findingCount: 0,
          durationMs: Date.now() - start,
          error: `modal invoke HTTP ${res.status}`,
        };
      }
      const body = (await res.json()) as ModalInvocationResponse;
      const sarif = body.sarif ?? emptySarif();
      const summary = extractSarifSummary(sarif);
      return {
        backend: "modal",
        status: body.status ?? (summary.findingCount > 0 ? "fail" : "pass"),
        highestSeverity: summary.highest,
        findingCount: summary.findingCount,
        sarif,
        markdown: body.markdown,
        runId: body.callId,
        durationMs: Date.now() - start,
        costUsd: body.costUsd,
        provider: {
          app: this.app(),
          function: this.functionName(),
          region: this.config.region,
          gpu: this.config.gpu,
        },
      };
    } catch (err) {
      return {
        backend: "modal",
        status: "error",
        highestSeverity: "none",
        findingCount: 0,
        durationMs: Date.now() - start,
        error: (err as Error).message,
      };
    }
  }

  private headers(): Record<string, string> {
    // Modal accepts token-id / token-secret pair via X-Modal-Token-* headers.
    return {
      "X-Modal-Token-Id": this.config.tokenId ?? "",
      "X-Modal-Token-Secret": this.config.tokenSecret ?? "",
      "Content-Type": "application/json",
      "User-Agent": "lyrie-agent/0.3.3 (https://lyrie.ai)",
    };
  }
}

interface ModalInvocationResponse {
  callId?: string;
  status?: BackendRunResult["status"];
  sarif?: string;
  markdown?: string;
  costUsd?: number;
}

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
