/**
 * scope.ts — Scope Declaration Language (SDL) operations.
 *
 * SDL is the third ATP primitive. It encodes what an agent may do, in a form
 * that is:
 *
 *   - Declarative   (no procedural rules — pure data)
 *   - Composable    (parent ⊇ child enforced by {@link mergeScopes})
 *   - Cryptographically bindable (carried inside a signed AIC)
 *
 * The trust-chain invariant `child.scope ⊆ parent.scope` (subset, never
 * widening) is the rule that prevents the agent equivalent of MCP RCE
 * privilege escalation — a sub-agent cannot grant itself capabilities its
 * parent never held.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { ScopeDeclaration, VerificationResult } from "./types";
import { ATP_VERSION } from "./types";

// ─── Construction & parsing ──────────────────────────────────────────────────

/**
 * Build a ScopeDeclaration with `version` filled in.
 * Use this rather than literal objects so version bumps are typesafe.
 */
export function makeScope(input: Omit<ScopeDeclaration, "version">): ScopeDeclaration {
  return { version: ATP_VERSION, ...input };
}

/**
 * Parse a JSON string (or arbitrary unknown value) into a validated
 * ScopeDeclaration. Throws on malformed input.
 *
 * Accepts JSON only — YAML support intentionally omitted from the reference
 * implementation to keep the dependency surface zero. Operators are expected
 * to pre-convert YAML at the orchestration layer.
 */
export function parseScope(input: string | unknown): ScopeDeclaration {
  const obj = typeof input === "string" ? JSON.parse(input) : input;
  const result = validateScope(obj);
  if (!result.valid) {
    throw new Error(`ATP: invalid scope (${result.code}): ${result.reason}`);
  }
  return obj as ScopeDeclaration;
}

// ─── Validation ──────────────────────────────────────────────────────────────

/** Structural validation. Does not check trust-chain relationships. */
export function validateScope(value: unknown): VerificationResult {
  if (!value || typeof value !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "scope must be an object" };
  }
  const s = value as Record<string, unknown>;

  if (s.version !== ATP_VERSION) {
    return {
      valid: false,
      code: "ATP_VERSION_MISMATCH",
      reason: `expected version ${ATP_VERSION}, got ${String(s.version)}`,
    };
  }
  if (!Array.isArray(s.allowedTools) || !s.allowedTools.every((x) => typeof x === "string")) {
    return { valid: false, code: "ATP_SCOPE_INVALID", reason: "allowedTools must be string[]" };
  }
  if (s.deniedTools !== undefined && !isStringArray(s.deniedTools)) {
    return { valid: false, code: "ATP_SCOPE_INVALID", reason: "deniedTools must be string[]" };
  }
  if (s.allowedDomains !== undefined && !isStringArray(s.allowedDomains)) {
    return { valid: false, code: "ATP_SCOPE_INVALID", reason: "allowedDomains must be string[]" };
  }
  if (typeof s.maxSubAgentDepth !== "number" || !Number.isInteger(s.maxSubAgentDepth) || s.maxSubAgentDepth < 0) {
    return {
      valid: false,
      code: "ATP_SCOPE_INVALID",
      reason: "maxSubAgentDepth must be a non-negative integer",
    };
  }
  if (s.requireApprovalFor !== undefined && !isStringArray(s.requireApprovalFor)) {
    return {
      valid: false,
      code: "ATP_SCOPE_INVALID",
      reason: "requireApprovalFor must be string[]",
    };
  }
  if (s.temporalScope !== undefined) {
    const t = s.temporalScope as Record<string, unknown>;
    if (t === null || typeof t !== "object") {
      return { valid: false, code: "ATP_SCOPE_INVALID", reason: "temporalScope must be object" };
    }
    if (t.validFrom !== undefined && typeof t.validFrom !== "number") {
      return { valid: false, code: "ATP_SCOPE_INVALID", reason: "temporalScope.validFrom must be number" };
    }
    if (t.validUntil !== undefined && typeof t.validUntil !== "number") {
      return { valid: false, code: "ATP_SCOPE_INVALID", reason: "temporalScope.validUntil must be number" };
    }
    if (typeof t.validFrom === "number" && typeof t.validUntil === "number" && t.validFrom > t.validUntil) {
      return {
        valid: false,
        code: "ATP_SCOPE_INVALID",
        reason: "temporalScope.validFrom must be ≤ validUntil",
      };
    }
    if (t.allowedHours !== undefined) {
      if (!Array.isArray(t.allowedHours) || !t.allowedHours.every((h) => typeof h === "number" && h >= 0 && h <= 23 && Number.isInteger(h))) {
        return {
          valid: false,
          code: "ATP_SCOPE_INVALID",
          reason: "temporalScope.allowedHours must be integers 0–23",
        };
      }
    }
  }
  if (s.dataScope !== undefined) {
    const d = s.dataScope as Record<string, unknown>;
    if (d === null || typeof d !== "object") {
      return { valid: false, code: "ATP_SCOPE_INVALID", reason: "dataScope must be object" };
    }
    if (d.allowedLabels !== undefined && !isStringArray(d.allowedLabels)) {
      return {
        valid: false,
        code: "ATP_SCOPE_INVALID",
        reason: "dataScope.allowedLabels must be string[]",
      };
    }
    if (d.deniedLabels !== undefined && !isStringArray(d.deniedLabels)) {
      return {
        valid: false,
        code: "ATP_SCOPE_INVALID",
        reason: "dataScope.deniedLabels must be string[]",
      };
    }
  }

  return { valid: true };
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

// ─── Subset / merge ──────────────────────────────────────────────────────────

/**
 * Returns true iff `child` is a subset of `parent`.
 *
 * Rules (applied in this order):
 *   - every tool in child.allowedTools must be allowed by parent
 *     (i.e. in parent.allowedTools AND not in parent.deniedTools)
 *   - child.allowedDomains must be ⊆ parent.allowedDomains (when parent
 *     specifies any). Glob entries match if the parent has either an
 *     identical glob OR a broader one (`*.x.com` covers `a.x.com`).
 *   - child.maxSubAgentDepth ≤ parent.maxSubAgentDepth
 *   - child temporal window must be within parent's
 *   - child requireApprovalFor must be a SUPERSET of parent's
 *     (children may add approvals, never remove them)
 *   - child dataScope.allowedLabels must be ⊆ parent's
 *   - child dataScope.deniedLabels must be ⊇ parent's (more restrictive)
 */
export function isScopeSubset(child: ScopeDeclaration, parent: ScopeDeclaration): boolean {
  // Tools
  const parentDenied = new Set(parent.deniedTools ?? []);
  const parentAllowed = new Set(parent.allowedTools);
  for (const t of child.allowedTools) {
    if (parentDenied.has(t)) return false;
    if (!parentAllowed.has(t) && !parent.allowedTools.includes("*")) return false;
  }
  // Child's deny list must include every tool parent denies.
  const childDenied = new Set(child.deniedTools ?? []);
  for (const t of parentDenied) if (!childDenied.has(t)) return false;

  // Domains
  if (parent.allowedDomains !== undefined) {
    if (child.allowedDomains === undefined) return false; // open-ended child > scoped parent
    for (const d of child.allowedDomains) {
      if (!parent.allowedDomains.some((p) => domainCovers(p, d))) return false;
    }
  }

  // Depth
  if (child.maxSubAgentDepth > parent.maxSubAgentDepth) return false;

  // Approval list — child must require approvals for at least everything parent does
  const childApproval = new Set(child.requireApprovalFor ?? []);
  for (const t of parent.requireApprovalFor ?? []) if (!childApproval.has(t)) return false;

  // Temporal window
  if (parent.temporalScope) {
    const pt = parent.temporalScope;
    const ct = child.temporalScope ?? {};
    if (pt.validFrom !== undefined) {
      if (ct.validFrom === undefined || ct.validFrom < pt.validFrom) return false;
    }
    if (pt.validUntil !== undefined) {
      if (ct.validUntil === undefined || ct.validUntil > pt.validUntil) return false;
    }
    if (pt.allowedHours && pt.allowedHours.length > 0) {
      if (!ct.allowedHours || ct.allowedHours.some((h) => !pt.allowedHours!.includes(h))) {
        return false;
      }
    }
  }

  // Data scope
  if (parent.dataScope?.allowedLabels) {
    if (!child.dataScope?.allowedLabels) return false;
    for (const l of child.dataScope.allowedLabels) {
      if (!parent.dataScope.allowedLabels.includes(l)) return false;
    }
  }
  if (parent.dataScope?.deniedLabels) {
    const childDeniedLabels = new Set(child.dataScope?.deniedLabels ?? []);
    for (const l of parent.dataScope.deniedLabels) {
      if (!childDeniedLabels.has(l)) return false;
    }
  }

  return true;
}

/**
 * Glob-match: does `parent` cover `child`?
 *
 * Supports a single leading `*.` wildcard (matches any subdomain), exact
 * match, and `*` for any. No regex parsing; one wildcard per pattern.
 */
export function domainCovers(parent: string, child: string): boolean {
  if (parent === child) return true;
  if (parent === "*") return true;
  if (parent.startsWith("*.")) {
    const suffix = parent.slice(1); // ".x.com"
    return child.endsWith(suffix) && child.length > suffix.length;
  }
  return false;
}

/**
 * Compute the *intersection* of parent and child scopes. Returns the most
 * permissive scope that is still a subset of both. If parent and child are
 * incompatible, the returned scope will never widen `parent` — but callers
 * who want to enforce "child must already be a subset" should call
 * {@link isScopeSubset} first.
 *
 * This is the function to call when an agent presents a desired sub-agent
 * scope: pass the parent scope and the desired child, and use the result
 * as the actual sub-agent scope.
 */
export function mergeScopes(parent: ScopeDeclaration, child: ScopeDeclaration): ScopeDeclaration {
  const parentDenied = new Set(parent.deniedTools ?? []);
  const allowedTools = child.allowedTools.filter(
    (t) => !parentDenied.has(t) && (parent.allowedTools.includes(t) || parent.allowedTools.includes("*")),
  );
  const deniedTools = Array.from(new Set([...(parent.deniedTools ?? []), ...(child.deniedTools ?? [])]));

  const merged: ScopeDeclaration = {
    version: ATP_VERSION,
    allowedTools,
    deniedTools: deniedTools.length ? deniedTools : undefined,
    maxSubAgentDepth: Math.min(parent.maxSubAgentDepth, child.maxSubAgentDepth),
    requireApprovalFor: Array.from(
      new Set([...(parent.requireApprovalFor ?? []), ...(child.requireApprovalFor ?? [])]),
    ),
  };

  if (parent.allowedDomains !== undefined || child.allowedDomains !== undefined) {
    if (parent.allowedDomains === undefined) {
      merged.allowedDomains = child.allowedDomains ? [...child.allowedDomains] : undefined;
    } else if (child.allowedDomains === undefined) {
      merged.allowedDomains = [...parent.allowedDomains];
    } else {
      merged.allowedDomains = child.allowedDomains.filter((d) =>
        parent.allowedDomains!.some((p) => domainCovers(p, d)),
      );
    }
  }

  // Temporal — intersect.
  if (parent.temporalScope || child.temporalScope) {
    const pt = parent.temporalScope ?? {};
    const ct = child.temporalScope ?? {};
    const validFrom = maxDefined(pt.validFrom, ct.validFrom);
    const validUntil = minDefined(pt.validUntil, ct.validUntil);
    let allowedHours: number[] | undefined;
    if (pt.allowedHours && ct.allowedHours) {
      allowedHours = ct.allowedHours.filter((h) => pt.allowedHours!.includes(h));
    } else {
      allowedHours = pt.allowedHours ?? ct.allowedHours;
    }
    merged.temporalScope = { validFrom, validUntil, allowedHours };
  }

  // Data scope — intersect allowed, union denied.
  if (parent.dataScope || child.dataScope) {
    const pa = parent.dataScope?.allowedLabels;
    const ca = child.dataScope?.allowedLabels;
    let allowedLabels: string[] | undefined;
    if (pa && ca) allowedLabels = ca.filter((l) => pa.includes(l));
    else if (pa) allowedLabels = [...pa];
    else if (ca) allowedLabels = [...ca];
    const deniedLabels = Array.from(
      new Set([...(parent.dataScope?.deniedLabels ?? []), ...(child.dataScope?.deniedLabels ?? [])]),
    );
    merged.dataScope = {
      allowedLabels,
      deniedLabels: deniedLabels.length ? deniedLabels : undefined,
    };
  }

  return merged;
}

function maxDefined(a?: number, b?: number): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.max(a, b);
}
function minDefined(a?: number, b?: number): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.min(a, b);
}

// ─── Decision helpers ────────────────────────────────────────────────────────

export interface ToolDecision {
  allowed: boolean;
  requiresApproval: boolean;
  reason?: string;
}

/**
 * Decide whether a given tool invocation is permitted by a scope, ignoring
 * domain/temporal context. Returns whether it's allowed AND whether the
 * scope marks it as requiring human approval before execution.
 */
export function checkToolAllowed(tool: string, scope: ScopeDeclaration): ToolDecision {
  if ((scope.deniedTools ?? []).includes(tool)) {
    return { allowed: false, requiresApproval: false, reason: "denied" };
  }
  const wildcard = scope.allowedTools.includes("*");
  if (!wildcard && !scope.allowedTools.includes(tool)) {
    return { allowed: false, requiresApproval: false, reason: "not in allow-list" };
  }
  const requiresApproval = (scope.requireApprovalFor ?? []).includes(tool);
  return { allowed: true, requiresApproval };
}

/** Check a domain against scope.allowedDomains, returning true if accessible. */
export function checkDomainAllowed(domain: string, scope: ScopeDeclaration): boolean {
  if (!scope.allowedDomains) return true;
  return scope.allowedDomains.some((p) => domainCovers(p, domain));
}

/**
 * Check whether a scope is currently "in window" given the wall-clock time.
 * Pass `now` (Unix ms) for testability; defaults to `Date.now()`.
 */
export function checkTemporallyValid(scope: ScopeDeclaration, now: number = Date.now()): boolean {
  const t = scope.temporalScope;
  if (!t) return true;
  if (t.validFrom !== undefined && now < t.validFrom) return false;
  if (t.validUntil !== undefined && now > t.validUntil) return false;
  if (t.allowedHours && t.allowedHours.length > 0) {
    const hour = new Date(now).getUTCHours();
    if (!t.allowedHours.includes(hour)) return false;
  }
  return true;
}
