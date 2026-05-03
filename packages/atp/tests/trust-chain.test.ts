/**
 * Trust Chain tests — the cornerstone privilege-escalation prevention rule.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  issueAic,
  buildTrustChain,
  verifyTrustChain,
  verifyChainTerminatesAt,
  certIdOf,
} from "../src/index";
import { makeScope } from "../src/scope";
import { sha256Hex } from "../src/crypto";

const wide = makeScope({ allowedTools: ["a", "b", "c"], maxSubAgentDepth: 3 });
const narrow = makeScope({ allowedTools: ["a", "b"], maxSubAgentDepth: 2 });
const narrower = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 1 });

const opInput = (scope = wide, parentCertId?: string) => ({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("p"),
  scope,
  operatorId: "guy@lyrie.ai",
  parentCertId,
});

describe("buildTrustChain", () => {
  test("requires at least one cert", () => {
    expect(() => buildTrustChain([])).toThrow();
  });

  test("computes depth correctly", () => {
    const root = issueAic(opInput());
    const chain = buildTrustChain([root.cert]);
    expect(chain.depth).toBe(0);
    expect(chain.rootCertId).toBe(root.certId);
  });
});

describe("verifyTrustChain — happy paths", () => {
  test("single root verifies", () => {
    const root = issueAic(opInput());
    const v = verifyTrustChain(buildTrustChain([root.cert]));
    expect(v.valid).toBe(true);
  });

  test("two-level narrowing chain verifies", () => {
    const root = issueAic(opInput(wide));
    const child = issueAic(opInput(narrow, root.certId));
    const v = verifyTrustChain(buildTrustChain([root.cert, child.cert]));
    expect(v.valid).toBe(true);
  });

  test("three-level monotonically narrowing chain verifies", () => {
    const root = issueAic(opInput(wide));
    const mid = issueAic(opInput(narrow, root.certId));
    const leaf = issueAic(opInput(narrower, mid.certId));
    const v = verifyTrustChain(buildTrustChain([root.cert, mid.cert, leaf.cert]));
    expect(v.valid).toBe(true);
  });
});

describe("verifyTrustChain — invariant enforcement", () => {
  test("rejects scope-widening child (the headline rule)", () => {
    const root = issueAic(opInput(narrow));
    const evil = issueAic(opInput(wide, root.certId));
    const v = verifyTrustChain(buildTrustChain([root.cert, evil.cert]));
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_SCOPE_WIDENING");
  });

  test("rejects broken parent linkage", () => {
    const root = issueAic(opInput(wide));
    const child = issueAic(opInput(narrow, "bogus".repeat(13).slice(0, 64)));
    const v = verifyTrustChain(buildTrustChain([root.cert, child.cert]));
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_CHAIN_BROKEN");
  });

  test("rejects root with parentCertId", () => {
    const fakeParent = "a".repeat(64);
    const root = issueAic(opInput(wide, fakeParent));
    const v = verifyTrustChain(buildTrustChain([root.cert]));
    expect(v.valid).toBe(false);
  });

  test("rejects child issued before parent issuedAt", () => {
    const now = Date.now();
    const root = issueAic({ ...opInput(wide), issuedAt: now });
    const earlyChild = issueAic({ ...opInput(narrow, root.certId), issuedAt: now - 60_000 });
    const v = verifyTrustChain(buildTrustChain([root.cert, earlyChild.cert]));
    expect(v.valid).toBe(false);
  });

  test("rejects child issued after parent expiresAt", () => {
    const root = issueAic({ ...opInput(wide), ttlMs: 100, issuedAt: Date.now() - 10_000 });
    const lateChild = issueAic({ ...opInput(narrow, root.certId), issuedAt: Date.now() });
    const v = verifyTrustChain(buildTrustChain([root.cert, lateChild.cert]), { ignoreExpiry: true });
    expect(v.valid).toBe(false);
  });

  test("global maxDepth is enforced", () => {
    const root = issueAic(opInput(wide));
    const child = issueAic(opInput(narrow, root.certId));
    const v = verifyTrustChain(buildTrustChain([root.cert, child.cert]), { maxDepth: 0 });
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_CHAIN_DEPTH_EXCEEDED");
  });

  test("parent's maxSubAgentDepth caps the chain", () => {
    const tightRoot = issueAic(opInput(makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 })));
    const childScope = makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 });
    const child = issueAic(opInput(childScope, tightRoot.certId));
    const v = verifyTrustChain(buildTrustChain([tightRoot.cert, child.cert]));
    expect(v.valid).toBe(false);
  });

  test("collects multiple errors in details", () => {
    const root = issueAic(opInput(narrow));
    const widening = issueAic(opInput(wide, root.certId));
    const v = verifyTrustChain(buildTrustChain([root.cert, widening.cert]));
    expect(v.valid).toBe(false);
    expect(v.details?.length).toBeGreaterThanOrEqual(1);
  });

  test("rejects empty chain", () => {
    const v = verifyTrustChain({ rootCertId: "x", chain: [], depth: 0 });
    expect(v.valid).toBe(false);
  });

  test("rejects depth/length mismatch", () => {
    const root = issueAic(opInput());
    const v = verifyTrustChain({ rootCertId: root.certId, chain: [root.cert], depth: 5 });
    expect(v.valid).toBe(false);
  });
});

describe("verifyChainTerminatesAt", () => {
  test("matches expected leaf", () => {
    const root = issueAic(opInput(wide));
    const child = issueAic(opInput(narrow, root.certId));
    const chain = buildTrustChain([root.cert, child.cert]);
    expect(verifyChainTerminatesAt(chain, certIdOf(child.cert)).valid).toBe(true);
  });

  test("rejects mismatched leaf", () => {
    const root = issueAic(opInput());
    const chain = buildTrustChain([root.cert]);
    const v = verifyChainTerminatesAt(chain, "z".repeat(64));
    expect(v.valid).toBe(false);
  });
});
