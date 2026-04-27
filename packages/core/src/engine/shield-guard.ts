/**
 * ShieldGuard — Lightweight, dependency-free Shield surface used by every
 * Lyrie module that touches untrusted text (recalled memory, MCP tool
 * results, channel inbound, paired-sender first messages).
 *
 * Why a separate type?
 *   `ShieldManager` (engine/shield-manager.ts) is the full battery — it
 *   owns event logs, tool-call validation, path scoping, and is wired into
 *   the engine. Crossings outside the engine (memory, MCP, gateway middleware)
 *   need a *small* contract they can call without pulling the whole manager.
 *
 *   ShieldGuard is that contract. ShieldManager satisfies it natively, but
 *   isolated subsystems can also use the built-in heuristic fallback so
 *   Lyrie ships with a Shield on EVERY layer — even the admin CLIs.
 *
 * **Doctrine: every layer of Lyrie has a Shield hook. There is no path that
 * touches user-supplied text without passing through this contract.**
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export interface ShieldVerdict {
  blocked: boolean;
  /** Severity of the threat detected, if any. */
  severity?: "none" | "low" | "medium" | "high" | "critical";
  /** Human-readable reason. */
  reason?: string;
}

/** Minimal interface every Shield-aware caller depends on. */
export interface ShieldGuardLike {
  /** Scan free-form recalled text (memory snippets, MCP tool output). */
  scanRecalled(text: string): ShieldVerdict;
  /** Scan inbound user-supplied text (DM body, pairing greeting, etc). */
  scanInbound(text: string): ShieldVerdict;
}

// ─── Built-in heuristic fallback ─────────────────────────────────────────────

const PROMPT_INJECTION_PATTERNS: ReadonlyArray<RegExp> = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+(a|an|my)\s+/i,
  /system\s*prompt\s*(override|change|modify|replace)/i,
  /forget\s+(everything|all|your)\s+/i,
  /new\s+instructions?\s*:/i,
  /\bDAN\s+mode\b/i,
  /\bjailbreak\b/i,
  /reveal\s+(your|the)\s+(system|hidden|secret)\s+prompt/i,
  /output\s+(all|every|your)\s+(system|hidden|secret)/i,
  /<\s*\|\s*end\s*of\s*system\s*\|\s*>/i,
  /role\s*[:=]\s*(system|developer|admin|root)/i,
];

const EXFIL_PATTERNS: ReadonlyArray<RegExp> = [
  /api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}/i,
  /aws_secret_access_key/i,
  /private\s+key\s*-+begin/i,
  /-----BEGIN\s+(RSA|OPENSSH|PGP|DSA|EC)\s+PRIVATE\s+KEY-----/i,
];

const URL_RE = /\bhttps?:\/\/([^\s/]+)/gi;

/** Built-in heuristic guard used when no full ShieldManager is available. */
export class FallbackShieldGuard implements ShieldGuardLike {
  scanRecalled(text: string): ShieldVerdict {
    if (!text || text.length === 0) return { blocked: false };
    for (const re of PROMPT_INJECTION_PATTERNS) {
      if (re.test(text)) {
        return {
          blocked: true,
          severity: "high",
          reason: `prompt-injection pattern in recalled content: ${re.source}`,
        };
      }
    }
    for (const re of EXFIL_PATTERNS) {
      if (re.test(text)) {
        return {
          blocked: true,
          severity: "critical",
          reason: `secret-like material in recalled content`,
        };
      }
    }
    return { blocked: false };
  }

  scanInbound(text: string): ShieldVerdict {
    if (!text) return { blocked: false };
    // For inbound we are a bit more permissive — we only block on
    // critical signals; lower-severity prompt-injection attempts are
    // expected user content (e.g. they are asking ABOUT injection).
    for (const re of EXFIL_PATTERNS) {
      if (re.test(text)) {
        return {
          blocked: true,
          severity: "critical",
          reason: "credential-like material in inbound message",
        };
      }
    }
    return { blocked: false };
  }
}

// ─── Convenience namespace ──────────────────────────────────────────────────

export const ShieldGuard = {
  fallback(): ShieldGuardLike {
    return new FallbackShieldGuard();
  },
  /** Convenience helper — returns true if the verdict allows passage. */
  allows(v: ShieldVerdict): boolean {
    return !v.blocked;
  },
} as const;
