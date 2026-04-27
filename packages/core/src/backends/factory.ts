/**
 * Backend factory — pick the right Lyrie execution backend at runtime.
 *
 * Resolution order:
 *   1. Explicit kind passed to `getBackend(kind, config?)`.
 *   2. `LYRIE_BACKEND` env var (`local` | `daytona` | `modal`).
 *   3. Default: `local`.
 *
 * The factory also reads each backend's required env vars when no config is
 * passed, so existing GitHub Actions workflows can opt-in to a serverless
 * backend purely by setting env vars.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import { LocalBackend } from "./local";
import { DaytonaBackend } from "./daytona";
import { ModalBackend } from "./modal";
import {
  SUPPORTED_BACKENDS,
  type AnyBackendConfig,
  type Backend,
  type BackendKind,
  type DaytonaBackendConfig,
  type LocalBackendConfig,
  type ModalBackendConfig,
} from "./types";

export interface BackendFactoryOptions {
  /** Override the default env source. Useful in tests. */
  env?: Record<string, string | undefined>;
}

export function resolveBackendKind(
  explicit: BackendKind | undefined,
  env: Record<string, string | undefined>,
): BackendKind {
  if (explicit) return explicit;
  const raw = (env["LYRIE_BACKEND"] ?? "").trim().toLowerCase();
  if (SUPPORTED_BACKENDS.includes(raw as BackendKind)) {
    return raw as BackendKind;
  }
  return "local";
}

export function readDaytonaConfigFromEnv(
  env: Record<string, string | undefined>,
): DaytonaBackendConfig {
  return {
    apiUrl: env["DAYTONA_API_URL"],
    apiKey: env["DAYTONA_API_KEY"],
    image: env["LYRIE_DAYTONA_IMAGE"],
    region: env["LYRIE_DAYTONA_REGION"],
    ttlSeconds: env["LYRIE_DAYTONA_TTL_SECONDS"]
      ? Number(env["LYRIE_DAYTONA_TTL_SECONDS"])
      : undefined,
  };
}

export function readModalConfigFromEnv(
  env: Record<string, string | undefined>,
): ModalBackendConfig {
  return {
    tokenId: env["MODAL_TOKEN_ID"],
    tokenSecret: env["MODAL_TOKEN_SECRET"],
    app: env["LYRIE_MODAL_APP"],
    functionName: env["LYRIE_MODAL_FUNCTION"],
    region: env["LYRIE_MODAL_REGION"],
    gpu: env["LYRIE_MODAL_GPU"],
  };
}

export function readLocalConfigFromEnv(
  env: Record<string, string | undefined>,
): LocalBackendConfig {
  return {
    dryRun: env["LYRIE_LOCAL_DRY_RUN"] === "1" || env["LYRIE_LOCAL_DRY_RUN"] === "true",
    cwd: env["LYRIE_LOCAL_CWD"],
  };
}

/**
 * Build a Backend.  When `cfg` is omitted, the appropriate env-var loader is
 * used. Throws only when an explicit unknown kind is requested.
 */
export function getBackend(
  kind?: BackendKind,
  cfg?: AnyBackendConfig,
  options?: BackendFactoryOptions,
): Backend {
  const env = options?.env ?? (process.env as Record<string, string | undefined>);
  const resolved = resolveBackendKind(kind, env);

  if (cfg && cfg.kind !== resolved) {
    throw new Error(
      `backend factory: kind mismatch (resolved=${resolved}, config=${cfg.kind})`,
    );
  }

  switch (resolved) {
    case "local": {
      const c = (cfg && cfg.kind === "local" ? cfg.config : undefined) ?? readLocalConfigFromEnv(env);
      return new LocalBackend(c);
    }
    case "daytona": {
      const c = cfg && cfg.kind === "daytona" ? cfg.config : readDaytonaConfigFromEnv(env);
      return new DaytonaBackend(c);
    }
    case "modal": {
      const c = cfg && cfg.kind === "modal" ? cfg.config : readModalConfigFromEnv(env);
      return new ModalBackend(c);
    }
    default: {
      const exhaustive: never = resolved;
      throw new Error(`unknown Lyrie backend kind: ${exhaustive as string}`);
    }
  }
}

/** Convenience for the runner CLI. */
export function describeBackend(b: Backend): string {
  const status = b.isConfigured() ? "✅ configured" : "⚠️  unconfigured";
  return `${b.displayName.padEnd(20)} (${b.kind})  ${status}`;
}
