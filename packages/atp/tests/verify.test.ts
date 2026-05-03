/**
 * Cross-primitive verifier + badge tests.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  issueAic,
  signReceipt,
  attestState,
  buildTrustChain,
  verifyArtifact,
  detectArtifactKind,
  generateBadge,
  makeScope,
  canonicalize,
  generateKeyPair,
} from "../src/index";
import { sha256Hex } from "../src/crypto";

const baseInput = () => ({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("p"),
  scope: makeScope({ allowedTools: ["a"], maxSubAgentDepth: 1 }),
  operatorId: "guy@lyrie.ai",
});

describe("verifyArtifact dispatch", () => {
  test("verifies an AIC", () => {
    const r = issueAic(baseInput());
    expect(verifyArtifact({ kind: "aic", cert: r.cert }).valid).toBe(true);
  });

  test("verifies a receipt", () => {
    const r = issueAic(baseInput());
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: { tool: "a", params: {}, timestamp: 1 },
      result: { success: true, summary: "", timestamp: 2 },
    });
    const v = verifyArtifact({ kind: "receipt", receipt }, { kind: "receipt", opts: { cert: r.cert } });
    expect(v.valid).toBe(true);
  });

  test("verifies a trust chain", () => {
    const root = issueAic(baseInput());
    const child = issueAic({ ...baseInput(), parentCertId: root.certId, scope: makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 }) });
    const chain = buildTrustChain([root.cert, child.cert]);
    expect(verifyArtifact({ kind: "trust-chain", chain }).valid).toBe(true);
  });

  test("verifies an attestation", () => {
    const r = issueAic(baseInput());
    const att = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: { systemPromptHash: "a", memoryHash: "b", toolCallHistoryHash: "c" },
    });
    const v = verifyArtifact(
      { kind: "attestation", attestation: att },
      { kind: "attestation", opts: { cert: r.cert } },
    );
    expect(v.valid).toBe(true);
  });

  test("validates a scope artifact", () => {
    const v = verifyArtifact({ kind: "scope", scope: makeScope({ allowedTools: [], maxSubAgentDepth: 0 }) });
    expect(v.valid).toBe(true);
  });

  test("rejects mismatched artifact + context kinds", () => {
    const r = issueAic(baseInput());
    const v = verifyArtifact(
      { kind: "aic", cert: r.cert },
      { kind: "receipt", opts: { cert: r.cert } },
    );
    expect(v.valid).toBe(false);
  });
});

describe("detectArtifactKind", () => {
  test("identifies AIC", () => {
    const r = issueAic(baseInput());
    expect(detectArtifactKind(r.cert)).toBe("aic");
  });

  test("identifies receipt", () => {
    const r = issueAic(baseInput());
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: { tool: "a", params: {}, timestamp: 1 },
      result: { success: true, summary: "", timestamp: 2 },
    });
    expect(detectArtifactKind(receipt)).toBe("receipt");
  });

  test("identifies attestation", () => {
    const r = issueAic(baseInput());
    const att = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: { systemPromptHash: "a", memoryHash: "b", toolCallHistoryHash: "c" },
    });
    expect(detectArtifactKind(att)).toBe("attestation");
  });

  test("returns null for noise", () => {
    expect(detectArtifactKind(null)).toBe(null);
    expect(detectArtifactKind({ unrelated: true })).toBe(null);
  });
});

describe("badge", () => {
  test("ATP-Full when attestation supplied", () => {
    const r = issueAic(baseInput());
    const att = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: { systemPromptHash: "a", memoryHash: "b", toolCallHistoryHash: "c" },
    });
    const badge = generateBadge(r.cert, att);
    expect(badge.json.level).toBe("ATP-Full");
    expect(badge.svg.startsWith("<svg")).toBe(true);
    expect(badge.verifyUrl.startsWith("https://lyrie.ai/verify?cert=")).toBe(true);
    expect(badge.json.cert).toEqual(r.cert);
  });

  test("level override is respected", () => {
    const r = issueAic(baseInput());
    const att = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: { systemPromptHash: "a", memoryHash: "b", toolCallHistoryHash: "c" },
    });
    const badge = generateBadge(r.cert, att, { level: "ATP-Basic", verifyBaseUrl: "https://x.test/v" });
    expect(badge.json.level).toBe("ATP-Basic");
    expect(badge.verifyUrl.startsWith("https://x.test/v?cert=")).toBe(true);
  });
});

describe("canonical JSON", () => {
  test("orders keys lexicographically", () => {
    const a = canonicalize({ b: 1, a: 2, c: { y: 1, x: 2 } });
    expect(a).toBe('{"a":2,"b":1,"c":{"x":2,"y":1}}');
  });

  test("drops undefined values", () => {
    const a = canonicalize({ a: undefined, b: 1 });
    expect(a).toBe('{"b":1}');
  });

  test("rejects functions and bigint", () => {
    expect(() => canonicalize({ f: () => 0 })).toThrow();
    expect(() => canonicalize({ n: 1n })).toThrow();
  });
});

describe("crypto sanity", () => {
  test("generated keys are 32 raw bytes each", () => {
    const kp = generateKeyPair();
    expect(Buffer.from(kp.publicKey, "base64").length).toBe(32);
    expect(Buffer.from(kp.privateKey, "base64").length).toBe(32);
  });
});
