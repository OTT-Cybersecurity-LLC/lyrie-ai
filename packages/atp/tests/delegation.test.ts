/**
 * delegation.test.ts — createDelegation, verifyDelegation, verifyDelegationChain
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  createDelegation,
  verifyDelegation,
  verifyDelegationChain,
} from "../src/delegation";
import { generateKeyPair } from "../src/crypto";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeParent() {
  const kp = generateKeyPair();
  return { agentId: "parent-agent-001", keyPair: kp };
}

function makeChild() {
  const kp = generateKeyPair();
  return { agentId: "child-agent-001", keyPair: kp };
}

const FULL_SCOPE = ["read_file", "send_email", "web_search"];

// ─── createDelegation ─────────────────────────────────────────────────────────

describe("createDelegation", () => {
  test("produces a valid DelegationCertificate with expected fields", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: FULL_SCOPE,
    });

    expect(cert.id).toMatch(/^atp:del:[0-9a-f-]{36}$/);
    expect(cert.parentAgentId).toBe(parent.agentId);
    expect(cert.childAgentId).toBe(child.agentId);
    expect(cert.delegatedScope).toEqual([...FULL_SCOPE].sort());
    expect(cert.maxDepth).toBe(0); // default
    expect(cert.atpVersion).toBe("2.0");
    expect(cert.parentSignature.length).toBeGreaterThan(0);
    expect(new Date(cert.issuedAt).getTime()).not.toBeNaN();
    expect(new Date(cert.expiresAt).getTime()).not.toBeNaN();
  });

  test("respects custom maxDepth and ttlSeconds", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: ["read_file"],
      maxDepth: 3,
      ttlSeconds: 60,
    });

    expect(cert.maxDepth).toBe(3);
    const diff =
      new Date(cert.expiresAt).getTime() - new Date(cert.issuedAt).getTime();
    expect(diff).toBe(60_000);
  });

  test("sorts delegatedScope lexicographically", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: ["z_tool", "a_tool", "m_tool"],
    });

    expect(cert.delegatedScope).toEqual(["a_tool", "m_tool", "z_tool"]);
  });
});

// ─── verifyDelegation ─────────────────────────────────────────────────────────

describe("verifyDelegation", () => {
  test("verifies a freshly issued certificate", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: FULL_SCOPE,
    });

    const result = verifyDelegation(cert, parent.keyPair.publicKey);
    expect(result.valid).toBe(true);
  });

  test("fails with wrong public key", () => {
    const parent = makeParent();
    const child = makeChild();
    const impostor = generateKeyPair();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: FULL_SCOPE,
    });

    const result = verifyDelegation(cert, impostor.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/parentSignature/);
  });

  test("fails if certificate is expired", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: FULL_SCOPE,
      ttlSeconds: -1, // already expired
    });

    const result = verifyDelegation(cert, parent.keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/);
  });

  test("fails if any field is tampered", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: FULL_SCOPE,
    });

    // Tamper: add an extra scope item
    const tampered = {
      ...cert,
      delegatedScope: [...cert.delegatedScope, "exec_shell"],
    };

    const result = verifyDelegation(tampered, parent.keyPair.publicKey);
    expect(result.valid).toBe(false);
  });
});

// ─── verifyDelegationChain ────────────────────────────────────────────────────

describe("verifyDelegationChain", () => {
  test("verifies a single-cert chain (depth 0)", () => {
    const parent = makeParent();
    const child = makeChild();

    const cert = createDelegation({
      parentKeyPair: parent.keyPair,
      parentAgentId: parent.agentId,
      childAgentId: child.agentId,
      delegatedScope: FULL_SCOPE,
    });

    const result = verifyDelegationChain([cert], parent.keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(0);
  });

  test("rejects empty chain", () => {
    const parent = makeParent();
    const result = verifyDelegationChain([], parent.keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/empty/);
  });

  test("rejects chain with broken linkage", () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();

    const cert1 = createDelegation({
      parentKeyPair: kpA,
      parentAgentId: "agent-A",
      childAgentId: "agent-B",
      delegatedScope: FULL_SCOPE,
      maxDepth: 2,
    });

    // cert2 parentAgentId does NOT match cert1.childAgentId
    const cert2 = createDelegation({
      parentKeyPair: kpB,
      parentAgentId: "agent-WRONG",
      childAgentId: "agent-C",
      delegatedScope: ["read_file"],
    });

    const result = verifyDelegationChain([cert1, cert2], kpA.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/parentAgentId/);
  });

  test("rejects chain that exceeds maxDepth of parent cert", () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();

    // maxDepth=0 means this is terminal — no further delegation allowed
    const cert1 = createDelegation({
      parentKeyPair: kpA,
      parentAgentId: "agent-A",
      childAgentId: "agent-B",
      delegatedScope: FULL_SCOPE,
      maxDepth: 0,
    });

    const cert2 = createDelegation({
      parentKeyPair: kpB,
      parentAgentId: "agent-B",
      childAgentId: "agent-C",
      delegatedScope: ["read_file"],
    });

    const result = verifyDelegationChain([cert1, cert2], kpA.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/maxDepth/);
  });

  test("rejects chain with scope widening", () => {
    const kpA = generateKeyPair();
    const kpB = generateKeyPair();

    const cert1 = createDelegation({
      parentKeyPair: kpA,
      parentAgentId: "agent-A",
      childAgentId: "agent-B",
      delegatedScope: ["read_file"], // restricted scope
      maxDepth: 2,
    });

    const cert2 = createDelegation({
      parentKeyPair: kpB,
      parentAgentId: "agent-B",
      childAgentId: "agent-C",
      delegatedScope: ["read_file", "send_email"], // WIDER — not allowed
    });

    const result = verifyDelegationChain([cert1, cert2], kpA.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/scope widening/);
  });
});
