/**
 * Breach Attestation tests.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  issueAic,
  attestState,
  verifyAttestation,
  hashAgentState,
  attestationHash,
  verifyAttestationChain,
  addAttestorSignature,
  generateKeyPair,
} from "../src/index";
import { makeScope } from "../src/scope";
import { sha256Hex } from "../src/crypto";

const baseInput = () => ({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("p"),
  scope: makeScope({ allowedTools: ["a"], maxSubAgentDepth: 0 }),
  operatorId: "guy@lyrie.ai",
});

const baseState = () => ({
  systemPromptHash: sha256Hex("p"),
  memoryHash: sha256Hex("memory"),
  toolCallHistoryHash: sha256Hex("history"),
});

describe("hashAgentState", () => {
  test("is deterministic", () => {
    const a = hashAgentState(baseState());
    const b = hashAgentState(baseState());
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  test("changes when any input changes", () => {
    const original = hashAgentState(baseState());
    const drifted = hashAgentState({ ...baseState(), memoryHash: sha256Hex("different") });
    expect(original).not.toBe(drifted);
  });
});

describe("attestState / verifyAttestation", () => {
  test("issues a verifiable attestation", () => {
    const r = issueAic(baseInput());
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    expect(att.signature.length).toBe(88);
    expect(verifyAttestation(att, { cert: r.cert }).valid).toBe(true);
  });

  test("detects state drift when expectedStateHash differs", () => {
    const r = issueAic(baseInput());
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    const v = verifyAttestation(att, { cert: r.cert, expectedStateHash: "0".repeat(64) });
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_ATTESTATION_DRIFT");
  });

  test("matches the expected state hash on the happy path", () => {
    const r = issueAic(baseInput());
    const state = baseState();
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state });
    const v = verifyAttestation(att, { cert: r.cert, expectedStateHash: hashAgentState(state) });
    expect(v.valid).toBe(true);
  });

  test("rejects tampered stateHash", () => {
    const r = issueAic(baseInput());
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    const tampered = { ...att, stateHash: sha256Hex("evil") };
    expect(verifyAttestation(tampered, { cert: r.cert }).valid).toBe(false);
  });

  test("rejects mismatched agentId", () => {
    const r = issueAic(baseInput());
    const other = issueAic(baseInput());
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    expect(verifyAttestation(att, { cert: other.cert }).valid).toBe(false);
  });

  test("rejects malformed object", () => {
    const r = issueAic(baseInput());
    expect(verifyAttestation(null as never, { cert: r.cert }).valid).toBe(false);
  });
});

describe("attestor counter-signature", () => {
  test("verifies with a third-party attestor", () => {
    const r = issueAic(baseInput());
    const attestor = generateKeyPair();
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    const cs = addAttestorSignature(att, "lyrie-verification-service", attestor.privateKey, attestor.publicKey);
    expect(cs.attestorId).toBe("lyrie-verification-service");
    const v = verifyAttestation(cs, { cert: r.cert, requireAttestor: true });
    expect(v.valid).toBe(true);
  });

  test("requireAttestor without one fails", () => {
    const r = issueAic(baseInput());
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    const v = verifyAttestation(att, { cert: r.cert, requireAttestor: true });
    expect(v.valid).toBe(false);
  });

  test("forged attestor signature fails", () => {
    const r = issueAic(baseInput());
    const real = generateKeyPair();
    const fake = generateKeyPair();
    const att = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState() });
    const cs = addAttestorSignature(att, "x", fake.privateKey, real.publicKey);
    expect(verifyAttestation(cs, { cert: r.cert }).valid).toBe(false);
  });
});

describe("attestation chains", () => {
  test("verifies a well-formed chain", () => {
    const r = issueAic(baseInput());
    const a1 = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState(), attestedAt: 100 });
    const a2 = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: baseState(),
      previousHash: attestationHash(a1),
      attestedAt: 200,
    });
    const a3 = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: baseState(),
      previousHash: attestationHash(a2),
      attestedAt: 300,
    });
    const v = verifyAttestationChain([a1, a2, a3], r.cert);
    expect(v.valid).toBe(true);
  });

  test("detects a broken hash link", () => {
    const r = issueAic(baseInput());
    const a1 = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState(), attestedAt: 100 });
    const orphan = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: baseState(),
      previousHash: "0".repeat(64),
      attestedAt: 200,
    });
    const v = verifyAttestationChain([a1, orphan], r.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_ATTESTATION_CHAIN_BROKEN");
  });

  test("detects time going backwards", () => {
    const r = issueAic(baseInput());
    const a1 = attestState({ cert: r.cert, privateKey: r.keyPair.privateKey, state: baseState(), attestedAt: 200 });
    const a2 = attestState({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      state: baseState(),
      previousHash: attestationHash(a1),
      attestedAt: 100,
    });
    const v = verifyAttestationChain([a1, a2], r.cert);
    expect(v.valid).toBe(false);
  });

  test("rejects empty chain", () => {
    const r = issueAic(baseInput());
    expect(verifyAttestationChain([], r.cert).valid).toBe(false);
  });
});
