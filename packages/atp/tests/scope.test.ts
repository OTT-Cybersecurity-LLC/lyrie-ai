/**
 * Scope / SDL tests — validation, subset, merge, decisions.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  makeScope,
  parseScope,
  validateScope,
  isScopeSubset,
  mergeScopes,
  domainCovers,
  checkToolAllowed,
  checkDomainAllowed,
  checkTemporallyValid,
} from "../src/scope";

describe("scope validation", () => {
  test("accepts a minimal valid scope", () => {
    const s = makeScope({ allowedTools: [], maxSubAgentDepth: 0 });
    expect(validateScope(s).valid).toBe(true);
  });

  test("rejects bad maxSubAgentDepth", () => {
    expect(validateScope(makeScope({ allowedTools: [], maxSubAgentDepth: -1 })).valid).toBe(false);
    expect(validateScope({ ...makeScope({ allowedTools: [], maxSubAgentDepth: 0 }), maxSubAgentDepth: 1.5 }).valid).toBe(false);
  });

  test("rejects bad temporal hours", () => {
    const s = makeScope({ allowedTools: [], maxSubAgentDepth: 0, temporalScope: { allowedHours: [25] } });
    expect(validateScope(s).valid).toBe(false);
  });

  test("rejects validFrom > validUntil", () => {
    const s = makeScope({ allowedTools: [], maxSubAgentDepth: 0, temporalScope: { validFrom: 100, validUntil: 50 } });
    expect(validateScope(s).valid).toBe(false);
  });

  test("parseScope round-trips JSON", () => {
    const s = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 1 });
    const parsed = parseScope(JSON.stringify(s));
    expect(parsed.allowedTools).toEqual(["a"]);
  });

  test("parseScope rejects garbage", () => {
    expect(() => parseScope("{}")).toThrow();
  });
});

describe("scope subset", () => {
  test("identical scopes are subsets of themselves", () => {
    const s = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 2 });
    expect(isScopeSubset(s, s)).toBe(true);
  });

  test("child cannot widen tools", () => {
    const parent = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 1 });
    const child = makeScope({ allowedTools: ["a", "b"], maxSubAgentDepth: 1 });
    expect(isScopeSubset(child, parent)).toBe(false);
    expect(isScopeSubset(parent, child)).toBe(true);
  });

  test("wildcard parent admits any child tool", () => {
    const parent = makeScope({ allowedTools: ["*"], maxSubAgentDepth: 5 });
    const child = makeScope({ allowedTools: ["a", "b"], maxSubAgentDepth: 1 });
    expect(isScopeSubset(child, parent)).toBe(true);
  });

  test("parent denied tool blocks any child claim", () => {
    const parent = makeScope({ allowedTools: ["*"], deniedTools: ["dangerous"], maxSubAgentDepth: 1 });
    const child = makeScope({ allowedTools: ["dangerous"], maxSubAgentDepth: 0 });
    expect(isScopeSubset(child, parent)).toBe(false);
  });

  test("child must inherit parent's deny list", () => {
    const parent = makeScope({ allowedTools: ["*"], deniedTools: ["danger"], maxSubAgentDepth: 1 });
    const childMissing = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 });
    const childKeeps = makeScope({ allowedTools: ["a"], deniedTools: ["danger"], maxSubAgentDepth: 0 });
    expect(isScopeSubset(childMissing, parent)).toBe(false);
    expect(isScopeSubset(childKeeps, parent)).toBe(true);
  });

  test("child cannot increase sub-agent depth", () => {
    const parent = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 1 });
    const child = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 2 });
    expect(isScopeSubset(child, parent)).toBe(false);
  });

  test("scoped parent rejects open-ended child domains", () => {
    const parent = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, allowedDomains: ["*.x.com"] });
    const childOpen = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 });
    const childMatch = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, allowedDomains: ["a.x.com"] });
    const childOff = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, allowedDomains: ["evil.com"] });
    expect(isScopeSubset(childOpen, parent)).toBe(false);
    expect(isScopeSubset(childMatch, parent)).toBe(true);
    expect(isScopeSubset(childOff, parent)).toBe(false);
  });

  test("temporal window must be within parent's", () => {
    const parent = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, temporalScope: { validFrom: 100, validUntil: 200 } });
    const inside = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, temporalScope: { validFrom: 120, validUntil: 180 } });
    const outside = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, temporalScope: { validFrom: 50, validUntil: 180 } });
    expect(isScopeSubset(inside, parent)).toBe(true);
    expect(isScopeSubset(outside, parent)).toBe(false);
  });

  test("data labels must be subset", () => {
    const parent = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, dataScope: { allowedLabels: ["public", "internal"] } });
    const ok = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, dataScope: { allowedLabels: ["public"] } });
    const wider = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, dataScope: { allowedLabels: ["public", "secret"] } });
    expect(isScopeSubset(ok, parent)).toBe(true);
    expect(isScopeSubset(wider, parent)).toBe(false);
  });
});

describe("mergeScopes", () => {
  test("intersection narrows tools", () => {
    const parent = makeScope({ allowedTools: ["a", "b"], maxSubAgentDepth: 5 });
    const child = makeScope({ allowedTools: ["b", "c"], maxSubAgentDepth: 2 });
    const merged = mergeScopes(parent, child);
    expect(merged.allowedTools).toEqual(["b"]);
    expect(merged.maxSubAgentDepth).toBe(2);
    expect(isScopeSubset(merged, parent)).toBe(true);
  });

  test("union of denied tools", () => {
    const parent = makeScope({ allowedTools: ["*"], deniedTools: ["x"], maxSubAgentDepth: 1 });
    const child = makeScope({ allowedTools: ["a"], deniedTools: ["y"], maxSubAgentDepth: 0 });
    const merged = mergeScopes(parent, child);
    expect(merged.deniedTools).toContain("x");
    expect(merged.deniedTools).toContain("y");
  });

  test("temporal intersection", () => {
    const parent = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, temporalScope: { validFrom: 100, validUntil: 500 } });
    const child = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0, temporalScope: { validFrom: 200, validUntil: 700 } });
    const merged = mergeScopes(parent, child);
    expect(merged.temporalScope?.validFrom).toBe(200);
    expect(merged.temporalScope?.validUntil).toBe(500);
  });
});

describe("domain glob", () => {
  test("exact match", () => {
    expect(domainCovers("a.com", "a.com")).toBe(true);
    expect(domainCovers("a.com", "b.com")).toBe(false);
  });
  test("wildcard subdomain", () => {
    expect(domainCovers("*.x.com", "api.x.com")).toBe(true);
    expect(domainCovers("*.x.com", "x.com")).toBe(false);
    expect(domainCovers("*.x.com", "a.b.x.com")).toBe(true);
    expect(domainCovers("*.x.com", "evil.com")).toBe(false);
  });
  test("global wildcard", () => {
    expect(domainCovers("*", "anything.com")).toBe(true);
  });
});

describe("decision helpers", () => {
  const scope = makeScope({
    allowedTools: ["read", "write"],
    deniedTools: ["delete"],
    requireApprovalFor: ["write"],
    allowedDomains: ["*.x.com"],
    maxSubAgentDepth: 0,
    temporalScope: { validFrom: 100, validUntil: 200 },
  });

  test("checkToolAllowed reflects allow / deny / approval", () => {
    expect(checkToolAllowed("read", scope)).toEqual({ allowed: true, requiresApproval: false });
    expect(checkToolAllowed("write", scope)).toEqual({ allowed: true, requiresApproval: true });
    expect(checkToolAllowed("delete", scope).allowed).toBe(false);
    expect(checkToolAllowed("unknown", scope).allowed).toBe(false);
  });

  test("checkDomainAllowed honors globs", () => {
    expect(checkDomainAllowed("api.x.com", scope)).toBe(true);
    expect(checkDomainAllowed("evil.com", scope)).toBe(false);
  });

  test("temporal validity respects window", () => {
    expect(checkTemporallyValid(scope, 50)).toBe(false);
    expect(checkTemporallyValid(scope, 150)).toBe(true);
    expect(checkTemporallyValid(scope, 250)).toBe(false);
  });

  test("checkDomainAllowed defaults open when no allowedDomains", () => {
    const s = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 });
    expect(checkDomainAllowed("anywhere.io", s)).toBe(true);
  });
});
