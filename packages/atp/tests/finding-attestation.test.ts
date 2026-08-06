/**
 * Signed Findings (finding-attestation) tests.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  issueAic,
  signFinding,
  verifySignedFinding,
  generateKeyPair,
} from "../src/index";
import { makeScope } from "../src/scope";
import { sha256Hex } from "../src/crypto";

const baseInput = () => ({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("p"),
  scope: makeScope({ allowedTools: ["x"], maxSubAgentDepth: 0 }),
  operatorId: "guy@lyrie.ai",
});

const samplePayload = () => ({
  id: "finding-1",
  title: "SQL injection in user lookup",
  severity: "critical" as const,
  file: "server.js",
  line: 17,
});

describe("signFinding", () => {
  test("round trip: sign then verify succeeds", () => {
    const r = issueAic(baseInput());
    const signed = signFinding({
      payload: samplePayload(),
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
    });
    expect(signed.signature.length).toBe(88);
    expect(signed.agentCertId).toBe(r.certId);
    const v = verifySignedFinding(signed, r.cert);
    expect(v.valid).toBe(true);
  });

  test("uses a fixed signedAt when provided (testability)", () => {
    const r = issueAic(baseInput());
    const signed = signFinding({
      payload: samplePayload(),
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      signedAt: "2026-01-01T00:00:00.000Z",
    });
    expect(signed.signedAt).toBe("2026-01-01T00:00:00.000Z");
    expect(verifySignedFinding(signed, r.cert).valid).toBe(true);
  });

  test("tampering with the payload after signing causes verify to fail", () => {
    const r = issueAic(baseInput());
    const signed = signFinding({
      payload: samplePayload(),
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
    });
    const tampered = { ...signed, payload: { ...signed.payload, severity: "low" as const } };
    const v = verifySignedFinding(tampered, r.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("tampering with signedAt after signing causes verify to fail", () => {
    const r = issueAic(baseInput());
    const signed = signFinding({
      payload: samplePayload(),
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
    });
    const tampered = { ...signed, signedAt: new Date(0).toISOString() };
    const v = verifySignedFinding(tampered, r.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("verifying against a different (wrong) cert fails on agentCertId mismatch", () => {
    const a = issueAic(baseInput());
    const b = issueAic(baseInput());
    const signed = signFinding({
      payload: samplePayload(),
      cert: a.cert,
      privateKey: a.keyPair.privateKey,
    });
    const v = verifySignedFinding(signed, b.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_RECEIPT_AGENT_MISMATCH");
  });

  test("forged signature (different keypair, same claimed certId) fails signature check", () => {
    const r = issueAic(baseInput());
    const forgerKeys = generateKeyPair();
    const signed = signFinding({
      payload: samplePayload(),
      cert: r.cert,
      privateKey: forgerKeys.privateKey, // wrong private key for this cert
    });
    const v = verifySignedFinding(signed, r.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("rejects malformed signed finding", () => {
    const r = issueAic(baseInput());
    expect(verifySignedFinding(null as never, r.cert).valid).toBe(false);
    expect(verifySignedFinding({} as never, r.cert).valid).toBe(false);
  });

  test("works with generic non-object payloads", () => {
    const r = issueAic(baseInput());
    const signed = signFinding({
      payload: ["a", "b", "c"],
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
    });
    expect(verifySignedFinding(signed, r.cert).valid).toBe(true);
  });
});
