/**
 * trust.ts — ATP-based trust gate for MCP server connections.
 *
 * `MCPSecurityScanner` (see @lyrie/core) is heuristic: it inspects config
 * shape and declared tool metadata for known-bad patterns, but it has no
 * concept of cryptographic identity — any server that doesn't trip a
 * heuristic gets connected.
 *
 * This module adds an optional, additive layer on top: an MCP server config
 * may carry an ATP Agent Identity Certificate (AIC) that vouches for it
 * (issued by whoever operates/publishes that server, or by a trust anchor
 * the operator trusts). When present, we verify the AIC — signature,
 * expiry, revocation, and scope coverage — via `@lyrie/atp` before the
 * server is allowed to connect.
 *
 * Design choices (documented per the prompt contract's "your call, document
 * it" requirement):
 *
 *   1. `trustPolicy` defaults to `"open"` — an MCP server with no `aic` field
 *      behaves exactly as before this change (backward compatible with every
 *      existing mcp.json in the wild). Only `"require-atp"` mode changes
 *      default behavior for uncertified servers.
 *
 *   2. Scope-mismatch handling: if a server's declared tool list is not
 *      fully covered by the AIC's `scope.allowedTools`, we DOWNGRADE rather
 *      than refuse — the registry only registers the subset of tools the
 *      cert actually covers (mirrors how ATP trust chains treat scope as a
 *      ceiling, not a pass/fail gate — see `packages/atp/src/trust-chain.ts`
 *      `isScopeSubset`). A hard refusal here would make partial/least-
 *      privilege certs unusable, which cuts against ATP's own design intent
 *      (encourage narrow scopes). Full refusal is reserved for identity
 *      failures (bad signature, expired, revoked) — those mean "this isn't
 *      who it claims to be" or "this claim is no longer valid", which is
 *      categorically different from "this claim is narrower than the
 *      server's full tool list".
 *
 *   3. `require-atp` mode refuses connection outright for any server with no
 *      AIC at all, or a structurally/cryptographically invalid one. A
 *      scope-mismatched-but-otherwise-valid cert still connects (downgraded)
 *      even in `require-atp` — the operator opted into trust enforcement,
 *      not into an all-or-nothing tool grant.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { verifyAic, type VerifyAicOptions } from "@lyrie/atp";
import type { AgentIdentityCertificate } from "@lyrie/atp";
import type { McpServerConfig } from "./types";

/** Registry-level trust enforcement policy. */
export type McpTrustPolicy = "open" | "warn-untrusted" | "require-atp";

/**
 * Optional per-server extension: attach an AIC that vouches for this MCP
 * server. Additive — omitting `aic` entirely preserves pre-ATP behavior.
 */
export interface McpServerTrustConfig extends McpServerConfig {
  /** Agent Identity Certificate vouching for this server's identity/scope. */
  aic?: AgentIdentityCertificate;
}

export type McpTrustDecision =
  | { outcome: "connect"; allowedTools?: string[]; reason?: string }
  | { outcome: "refuse"; reason: string };

export interface McpTrustCheckOptions {
  policy: McpTrustPolicy;
  /** Revocation predicate — same shape ATP's verifyAic() expects. */
  isRevoked?: (certId: string) => boolean;
  /** Wall-clock override for expiry checks (testability). */
  now?: number;
  /** The tools the server actually declares (for scope coverage checks). */
  declaredTools?: string[];
}

/**
 * Evaluate whether an MCP server should be connected, given the registry's
 * `trustPolicy` and (optionally) an AIC attached to its config.
 *
 * Pure function — does not touch the network or mutate any registry state,
 * so it's fully unit-testable independent of McpClient/McpRegistry.
 */
export function evaluateMcpTrust(
  serverName: string,
  cfg: McpServerTrustConfig,
  opts: McpTrustCheckOptions,
): McpTrustDecision {
  const { policy } = opts;
  const cert = cfg.aic;

  // ── No certificate attached ──────────────────────────────────────────────
  if (!cert) {
    if (policy === "require-atp") {
      return {
        outcome: "refuse",
        reason: `server "${serverName}" has no Agent Identity Certificate and trustPolicy is "require-atp"`,
      };
    }
    if (policy === "warn-untrusted") {
      console.warn(`[mcp] server "${serverName}" has no AIC — connecting untrusted (trustPolicy=warn-untrusted)`);
    }
    return { outcome: "connect" };
  }

  // ── Certificate present: verify it ───────────────────────────────────────
  const verifyOpts: VerifyAicOptions = {
    now: opts.now,
    isRevoked: opts.isRevoked,
  };
  const verdict = verifyAic(cert, verifyOpts);

  if (!verdict.valid) {
    // Any identity failure (bad signature, malformed, expired, revoked,
    // not-yet-valid) is a hard refuse regardless of policy — a server
    // presenting a broken certificate is worse than presenting none, since
    // it's actively claiming an identity it cannot back up.
    return {
      outcome: "refuse",
      reason: `server "${serverName}" AIC failed verification: ${verdict.code} — ${verdict.reason ?? "invalid"}`,
    };
  }

  // ── Valid certificate: check scope coverage against declared tools ──────
  const declared = opts.declaredTools ?? [];
  const scopeTools = cert.scope.allowedTools;
  const wildcard = scopeTools.includes("*");
  const denied = new Set(cert.scope.deniedTools ?? []);

  if (wildcard) {
    const allowedTools = declared.filter((t) => !denied.has(t));
    return { outcome: "connect", allowedTools };
  }

  const covered = declared.filter((t) => scopeTools.includes(t) && !denied.has(t));
  const uncovered = declared.filter((t) => !scopeTools.includes(t) || denied.has(t));

  if (uncovered.length > 0) {
    // Downgrade, don't refuse — see module-level doc comment for rationale.
    return {
      outcome: "connect",
      allowedTools: covered,
      reason:
        `server "${serverName}" AIC scope does not cover tool(s) [${uncovered.join(", ")}]; ` +
        `downgrading to cert-covered tools only: [${covered.join(", ")}]`,
    };
  }

  return { outcome: "connect", allowedTools: covered };
}
