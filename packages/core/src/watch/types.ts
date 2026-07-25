/**
 * watch/types.ts — Shared shapes for continuous exposure monitoring
 * (`lyrie watch <domain>`).
 *
 * This is genuinely new surface: unlike the prompt contract that spawned
 * this feature assumed, `lyrie scan`/`lyrie hack` do not collect live-HTTP
 * security-header/TLS/exposed-path data anywhere in this codebase today —
 * `HackOrchestrator` (packages/core/src/hack/orchestrator.ts) is entirely
 * filesystem/repo-oriented (`resolveTarget()` maps to a local checkout).
 * There is no existing "shape" to reuse for that data, so `PostureSnapshot`
 * below is a new, minimal shape built for this feature. It IS designed so
 * a future `lyrie scan <url>` could reuse it without a rewrite.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

/** A single security-relevant HTTP response header we track. */
export type WatchedHeader =
  | "content-security-policy"
  | "strict-transport-security"
  | "x-frame-options"
  | "x-content-type-options"
  | "referrer-policy"
  | "permissions-policy"
  | "server"
  | "x-powered-by";

export const WATCHED_HEADERS: readonly WatchedHeader[] = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "server",
  "x-powered-by",
];

/** Common paths that should never be publicly reachable. Kept short and
 * conservative — this is a monitoring probe, not a scanner; false positives
 * on every tick would defeat the "low noise" design goal. */
export const COMMON_EXPOSED_PATHS: readonly string[] = [
  "/.env",
  "/.git/config",
  "/admin",
  "/.aws/credentials",
  "/wp-config.php.bak",
  "/.ssh/id_rsa",
];

export interface TlsInfo {
  /** Unix ms — certificate notAfter. */
  expiresAt: number;
  /** SHA-256 fingerprint (hex) of the leaf certificate, if available. */
  fingerprintSha256?: string;
  issuer?: string;
  subject?: string;
}

export interface ExposedPathResult {
  path: string;
  /** True if the path returned a non-404/non-redirect-to-404 status. */
  exposed: boolean;
  status?: number;
}

/**
 * One point-in-time capture of a domain's external security posture.
 * Intentionally flat/JSON-serialisable — this is persisted to disk between
 * `lyrie watch` ticks (see store.ts) and diffed on each subsequent run.
 */
export interface PostureSnapshot {
  domain: string;
  /** Unix ms — when this snapshot was taken. */
  takenAt: number;
  /** Lower-cased header name → raw header value (only WATCHED_HEADERS). */
  headers: Partial<Record<WatchedHeader, string>>;
  tls?: TlsInfo;
  exposedPaths: ExposedPathResult[];
  /** Subdomains discovered by whatever enum path is wired (may be empty — see probe.ts). */
  subdomains: string[];
  /** True if the initial HTTPS request itself failed (DNS/connect/etc). */
  unreachable?: boolean;
  error?: string;
}

/** Options controlling a single posture probe run. */
export interface ProbeOptions {
  /** Injectable fetch, defaults to globalThis.fetch. Enables pure unit tests. */
  fetchFn?: typeof fetch;
  /** Injectable TLS inspector, defaults to a real `node:tls` connect. Enables pure unit tests. */
  tlsInspector?: (domain: string) => Promise<TlsInfo | undefined>;
  /** Injectable subdomain enumerator. Returns [] when not wired (documented, not faked). */
  subdomainEnum?: (domain: string) => Promise<string[]>;
  /** Per-request timeout, ms. Default 8000. */
  timeoutMs?: number;
}
