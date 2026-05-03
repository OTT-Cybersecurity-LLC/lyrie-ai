/**
 * AIC tests — issuance, identity, signature, expiry, revocation.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  issueAic,
  certIdOf,
  verifyAic,
  RevocationRegistry,
  ATP_VERSION,
} from "../src/index";
import { makeScope } from "../src/scope";
import { sha256Hex } from "../src/crypto";

const baseScope = () =>
  makeScope({ allowedTools: ["read_file", "send_email"], maxSubAgentDepth: 0 });

const baseInput = () => ({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("system prompt"),
  scope: baseScope(),
  operatorId: "guy@lyrie.ai",
});

describe("AIC issuance", () => {
  test("issues a valid certificate with fresh keys", () => {
    const r = issueAic(baseInput());
    expect(r.cert.version).toBe(ATP_VERSION);
    expect(r.cert.agentId).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.cert.publicKey.length).toBe(44);
    expect(r.cert.signature.length).toBe(88);
    expect(r.certId).toMatch(/^[0-9a-f]{64}$/);
    expect(r.keyPair.privateKey.length).toBe(44);
  });

  test("preserves caller-provided agentId and key pair", () => {
    const first = issueAic(baseInput());
    const reissued = issueAic({
      ...baseInput(),
      agentId: first.cert.agentId,
      keyPair: first.keyPair,
    });
    expect(reissued.cert.agentId).toBe(first.cert.agentId);
    expect(reissued.cert.publicKey).toBe(first.cert.publicKey);
  });

  test("CertId is a deterministic SHA-256 of the canonical cert", () => {
    const r = issueAic(baseInput());
    expect(certIdOf(r.cert)).toBe(r.certId);
  });

  test("rejects invalid scope at issue time", () => {
    expect(() =>
      issueAic({
        ...baseInput(),
        scope: { ...baseScope(), maxSubAgentDepth: -1 },
      }),
    ).toThrow();
  });
});

describe("AIC verification", () => {
  test("verifies a freshly issued cert", () => {
    const r = issueAic(baseInput());
    const v = verifyAic(r.cert);
    expect(v.valid).toBe(true);
  });

  test("rejects a tampered scope", () => {
    const r = issueAic(baseInput());
    const tampered = { ...r.cert, scope: { ...r.cert.scope, maxSubAgentDepth: 99 } };
    const v = verifyAic(tampered);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("rejects a tampered model id", () => {
    const r = issueAic(baseInput());
    const tampered = { ...r.cert, modelId: "evil/backdoored-model" };
    expect(verifyAic(tampered).valid).toBe(false);
  });

  test("rejects expired certs", () => {
    const r = issueAic({ ...baseInput(), ttlMs: 10, issuedAt: Date.now() - 1000 });
    const v = verifyAic(r.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_CERT_EXPIRED");
  });

  test("rejects not-yet-valid certs", () => {
    const r = issueAic({ ...baseInput(), issuedAt: Date.now() + 60_000 });
    const v = verifyAic(r.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_CERT_NOT_YET_VALID");
  });

  test("ignoreExpiry skips temporal checks", () => {
    const r = issueAic({ ...baseInput(), ttlMs: 10, issuedAt: Date.now() - 1000 });
    expect(verifyAic(r.cert, { ignoreExpiry: true }).valid).toBe(true);
  });

  test("revocation registry blocks listed certs", () => {
    const r = issueAic(baseInput());
    const reg = new RevocationRegistry();
    expect(verifyAic(r.cert, { isRevoked: reg.isRevoked }).valid).toBe(true);
    reg.revoke(r.certId);
    const v = verifyAic(r.cert, { isRevoked: reg.isRevoked });
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_CERT_REVOKED");
    reg.unrevoke(r.certId);
    expect(verifyAic(r.cert, { isRevoked: reg.isRevoked }).valid).toBe(true);
  });

  test("rejects malformed objects", () => {
    expect(verifyAic(null as never).valid).toBe(false);
    expect(verifyAic({} as never).valid).toBe(false);
    expect(verifyAic({ ...issueAic(baseInput()).cert, version: "0.9" } as never).valid).toBe(false);
  });

  test("rejects bad public key length", () => {
    const r = issueAic(baseInput());
    const tampered = { ...r.cert, publicKey: Buffer.from([1, 2, 3]).toString("base64") };
    const v = verifyAic(tampered);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  test("rejects bad signature length", () => {
    const r = issueAic(baseInput());
    const tampered = { ...r.cert, signature: "shortsig" };
    expect(verifyAic(tampered).valid).toBe(false);
  });
});

describe("AIC parent linkage", () => {
  test("supports parentCertId for sub-agents", () => {
    const root = issueAic(baseInput());
    const child = issueAic({ ...baseInput(), parentCertId: root.certId });
    expect(child.cert.parentCertId).toBe(root.certId);
    expect(verifyAic(child.cert).valid).toBe(true);
  });
});
