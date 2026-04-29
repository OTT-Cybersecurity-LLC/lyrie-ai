/**
 * FallbackClassifier — Classify why a provider call failed so the
 * model router can choose the right fallback strategy.
 *
 * Classification is intentionally conservative: when in doubt, return
 * 'unclassified' rather than incorrectly retrying a permanent error.
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

export type FallbackReason =
  | "empty_response"
  | "no_error_details"
  | "provider_overload"
  | "context_too_large"
  | "model_not_available"
  | "live_session_conflict"
  | "unclassified";

// ─── Classification ───────────────────────────────────────────────────────────

/**
 * Classify why a provider call failed or returned an unusable response.
 *
 * @param error   The thrown error (may be null/undefined for non-throw failures)
 * @param response  Optional raw HTTP Response or response-like object
 */
export function classifyFallback(
  error: unknown,
  response?: Response | { status?: number; statusText?: string } | null
): FallbackReason {
  // ── 1. Empty / null response with no error ──────────────────────────────────
  if (!error && !response) return "empty_response";

  // ── 2. HTTP-status based ────────────────────────────────────────────────────
  const status = getStatus(error, response);
  if (status !== null) {
    if (status === 429 || status === 503 || status === 529) return "provider_overload";
    if (status === 413) return "context_too_large";
    if (status === 404) return "model_not_available";
    if (status === 409) return "live_session_conflict";
  }

  // ── 3. Error message based ─────────────────────────────────────────────────
  const msg = errorMessage(error);

  if (msg) {
    const lower = msg.toLowerCase();

    if (
      lower.includes("rate limit") ||
      lower.includes("rate_limit") ||
      lower.includes("too many requests") ||
      lower.includes("overloaded") ||
      lower.includes("capacity") ||
      lower.includes("quota exceeded")
    ) {
      return "provider_overload";
    }

    if (
      lower.includes("context length") ||
      lower.includes("context_length") ||
      lower.includes("token limit") ||
      lower.includes("too long") ||
      lower.includes("maximum context") ||
      lower.includes("max_tokens") ||
      lower.includes("input too large")
    ) {
      return "context_too_large";
    }

    if (
      lower.includes("model not found") ||
      lower.includes("model_not_found") ||
      lower.includes("no such model") ||
      lower.includes("does not exist") ||
      lower.includes("not available") ||
      lower.includes("not_available") ||
      lower.includes("deprecated")
    ) {
      return "model_not_available";
    }

    if (
      lower.includes("session conflict") ||
      lower.includes("live session") ||
      lower.includes("streaming conflict") ||
      lower.includes("concurrent")
    ) {
      return "live_session_conflict";
    }

    if (
      lower.includes("empty") ||
      lower.includes("no content") ||
      lower.includes("no response")
    ) {
      return "empty_response";
    }

    // Non-empty error but no useful details
    if (msg.trim().length < 5) return "no_error_details";

    return "unclassified";
  }

  // ── 4. Unknown error object with no message ─────────────────────────────────
  if (error !== null && error !== undefined) return "no_error_details";

  return "empty_response";
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getStatus(
  error: unknown,
  response?: Response | { status?: number; statusText?: string } | null
): number | null {
  if (response && typeof (response as { status?: number }).status === "number") {
    return (response as { status: number }).status;
  }
  if (error && typeof (error as { status?: number }).status === "number") {
    return (error as { status: number }).status;
  }
  if (error && typeof (error as { statusCode?: number }).statusCode === "number") {
    return (error as { statusCode: number }).statusCode;
  }
  return null;
}

function errorMessage(error: unknown): string | null {
  if (!error) return null;
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (typeof (error as { message?: string }).message === "string") {
    return (error as { message: string }).message;
  }
  return null;
}

// ─── Strategy hints ───────────────────────────────────────────────────────────

export interface FallbackStrategy {
  /** Should the caller retry with the same provider? */
  retry: boolean;
  /** Should the caller switch to a different provider/model? */
  switchProvider: boolean;
  /** Should the caller reduce context size before retrying? */
  reduceContext: boolean;
  /** Suggested delay in ms before retrying (0 = immediate) */
  retryDelayMs: number;
}

/**
 * Convert a FallbackReason into an actionable strategy for the model router.
 */
export function strategyForReason(reason: FallbackReason): FallbackStrategy {
  switch (reason) {
    case "provider_overload":
      return { retry: true, switchProvider: true, reduceContext: false, retryDelayMs: 2000 };
    case "context_too_large":
      return { retry: true, switchProvider: false, reduceContext: true, retryDelayMs: 0 };
    case "model_not_available":
      return { retry: false, switchProvider: true, reduceContext: false, retryDelayMs: 0 };
    case "live_session_conflict":
      return { retry: true, switchProvider: false, reduceContext: false, retryDelayMs: 500 };
    case "empty_response":
      return { retry: true, switchProvider: true, reduceContext: false, retryDelayMs: 1000 };
    case "no_error_details":
      return { retry: true, switchProvider: true, reduceContext: false, retryDelayMs: 500 };
    case "unclassified":
    default:
      return { retry: false, switchProvider: true, reduceContext: false, retryDelayMs: 0 };
  }
}
