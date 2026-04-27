/**
 * Lyrie Execution Backends — types & contract.
 *
 * Lyrie scans run *somewhere*. Today they run on the host that invoked the
 * action. Phase-3 v0.3.3 introduces pluggable execution backends so the same
 * scan can transparently move to a serverless host:
 *
 *   - "local"    — current behavior (default). Run inline on the caller.
 *   - "daytona"  — spin up a Daytona devbox, run Lyrie inside, fetch SARIF.
 *   - "modal"    — invoke a Modal serverless function with the same shape.
 *
 * Every backend is a pure adapter: it takes a BackendRunRequest, returns a
 * BackendRunResult.  Call-sites stay backend-agnostic.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

// ─── Identity ──────────────────────────────────────────────────────────────────

export type BackendKind = "local" | "daytona" | "modal";

export const SUPPORTED_BACKENDS: readonly BackendKind[] = [
  "local",
  "daytona",
  "modal",
] as const;

// ─── Request shape ──────────────────────────────────────────────────────────────

export interface BackendRunRequest {
  /** Workspace path or git URL the backend should scan. */
  target: string;
  /** Scan profile, mirrors LYRIE_SCAN_MODE. */
  scanMode: "quick" | "full" | "recon" | "vulnscan" | "apiscan";
  /** "full" or "diff". Mirrors LYRIE_SCOPE. */
  scope: "full" | "diff";
  /** Diff base when scope=diff. */
  diffBase?: string;
  /** Severity floor at which the run should fail. */
  failOn: "critical" | "high" | "medium" | "low" | "none";
  /** Threat-intel offline mode override. */
  intelOffline?: boolean;
  /** Operator-supplied env vars passed through verbatim (filtered, no LYRIE_*_TOKEN secrets in logs). */
  env?: Record<string, string>;
  /** Operator-supplied resource hints. Backend decides how to honor. */
  resources?: BackendResourceHints;
  /** Free-form labels for cost-attribution / tracing. */
  labels?: Record<string, string>;
}

export interface BackendResourceHints {
  /** Soft CPU request (cores). */
  cpu?: number;
  /** Soft memory request in megabytes. */
  memoryMb?: number;
  /** Per-run timeout in seconds. */
  timeoutSeconds?: number;
  /** Optional: prefer ARM64 / x86_64 nodes. */
  arch?: "arm64" | "x86_64";
}

// ─── Result shape ───────────────────────────────────────────────────────────────

export interface BackendRunResult {
  /** Which backend served the request. */
  backend: BackendKind;
  /** Scan-level outcome: "pass" / "fail" / "error" (transport / scheduler problem). */
  status: "pass" | "fail" | "error";
  /** Highest severity discovered. */
  highestSeverity: "critical" | "high" | "medium" | "low" | "info" | "none";
  /** Total finding count (all severities). */
  findingCount: number;
  /** SARIF JSON as a string. Always populated on status≠"error". */
  sarif?: string;
  /** Markdown summary. */
  markdown?: string;
  /** Stable run identifier from the backend (e.g. Daytona workspace id, Modal call id). */
  runId?: string;
  /** Wall-clock duration in milliseconds. */
  durationMs: number;
  /** Optional: cost estimate in USD when the backend reports it. */
  costUsd?: number;
  /** Free-form provider details (region, image, container id, …). */
  provider?: Record<string, unknown>;
  /** Error message when status="error". */
  error?: string;
}

// ─── Backend interface ──────────────────────────────────────────────────────────

export interface Backend {
  /** Stable identifier. */
  readonly kind: BackendKind;
  /** Human-readable label. */
  readonly displayName: string;
  /** Whether the backend has its required configuration to run.  Cheap. */
  isConfigured(): boolean;
  /**
   * Lightweight pre-flight check (auth, quota, connectivity).  Backends that
   * don't need network for "ready" return true synchronously.
   */
  preflight(): Promise<{ ok: boolean; reason?: string }>;
  /** Execute a Lyrie scan and return the unified result. */
  run(request: BackendRunRequest): Promise<BackendRunResult>;
  /** Optional hook to release any backend-side state (no-op for stateless). */
  cleanup?(): Promise<void>;
}

// ─── Config shapes ──────────────────────────────────────────────────────────────

export interface DaytonaBackendConfig {
  apiUrl?: string;
  apiKey?: string;
  /** Image / template id (default: Lyrie's published image). */
  image?: string;
  /** Region pin. */
  region?: string;
  /** Workspace TTL in seconds; default: 1800 (30 min). */
  ttlSeconds?: number;
}

export interface ModalBackendConfig {
  /** Modal app slug, e.g. "lyrie-agent". */
  app?: string;
  /** Function name to invoke (default: "lyrie_scan"). */
  functionName?: string;
  /** API token (modal token id). */
  tokenId?: string;
  /** API token (modal token secret). */
  tokenSecret?: string;
  /** Optional region. */
  region?: string;
  /** Optional GPU class — Lyrie typically doesn't need GPU, keep undefined. */
  gpu?: string;
}

export interface LocalBackendConfig {
  /** When true, perform a dry-run that emits an empty SARIF (used in tests). */
  dryRun?: boolean;
  /** Override CWD for the spawned action runner. */
  cwd?: string;
}

export type AnyBackendConfig =
  | { kind: "local"; config?: LocalBackendConfig }
  | { kind: "daytona"; config: DaytonaBackendConfig }
  | { kind: "modal"; config: ModalBackendConfig };
