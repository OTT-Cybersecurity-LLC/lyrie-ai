/**
 * vaccine.test.ts — signed rule push/pull, ATP-receipt-bound ingestion,
 * anti-replay sequence tracking.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { generateKeyPair } from "../src/crypto";
import { issueAic } from "../src/aic";
import { verifyReceipt } from "../src/receipt";
import {
  VaccinePublisher,
  VaccineSubscriber,
  VaccineStore,
  signVaccineRule,
  verifyVaccineRule,
  recordVaccineIngest,
  newVaccineRuleId,
  type VaccineRuleBody,
} from "../src/vaccine";

function makeBody(overrides: Partial<VaccineRuleBody> = {}): VaccineRuleBody {
  return {
    ruleId: newVaccineRuleId("test"),
    kind: "regex-pattern",
    severity: "high",
    description: "detects XYZ exploit chain",
    payload: { pattern: "xyz-exploit", flags: "i" },
    sequence: 1,
    issuedAt: Date.now(),
    ...overrides,
  };
}

function makeIssuer() {
  const kp = generateKeyPair();
  return { issuerId: "lyrie-threat-intel", ...kp };
}

// ─── sign / verify ────────────────────────────────────────────────────────────

describe("signVaccineRule / verifyVaccineRule", () => {
  test("a freshly signed rule verifies", () => {
    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody(),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const result = verifyVaccineRule(rule);
    expect(result.valid).toBe(true);
  });

  test("tampered payload fails verification", () => {
    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody(),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const tampered = { ...rule, body: { ...rule.body, severity: "critical" as const } };
    const result = verifyVaccineRule(tampered);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("rejects issuer key not in trusted set", () => {
    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody(),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const otherKp = generateKeyPair();
    const result = verifyVaccineRule(rule, { trustedIssuerPublicKeys: [otherKp.publicKey] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  test("accepts issuer key present in trusted set", () => {
    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody(),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const result = verifyVaccineRule(rule, { trustedIssuerPublicKeys: [issuer.publicKey] });
    expect(result.valid).toBe(true);
  });

  test("expired rule fails verification", () => {
    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody({ expiresAt: Date.now() - 1000 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const result = verifyVaccineRule(rule);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_CERT_EXPIRED");
  });

  test("malformed rule (missing ruleId) is rejected structurally", () => {
    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody({ ruleId: "" }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const result = verifyVaccineRule(rule);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_MALFORMED");
  });
});

// ─── VaccineStore anti-replay ─────────────────────────────────────────────────

describe("VaccineStore", () => {
  test("fresh sequence is accepted, replay of same/older sequence is rejected", () => {
    const issuer = makeIssuer();
    const store = new VaccineStore();
    const rule1 = signVaccineRule({
      body: makeBody({ sequence: 5 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    expect(store.isFreshSequence(rule1)).toBe(true);
    store.accept(rule1);
    expect(store.lastSeenSequence(issuer.publicKey)).toBe(5);

    const replay = signVaccineRule({
      body: makeBody({ sequence: 5 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    expect(store.isFreshSequence(replay)).toBe(false);

    const older = signVaccineRule({
      body: makeBody({ sequence: 3 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    expect(store.isFreshSequence(older)).toBe(false);

    const newer = signVaccineRule({
      body: makeBody({ sequence: 6 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    expect(store.isFreshSequence(newer)).toBe(true);
  });

  test("active() excludes expired rules", () => {
    const issuer = makeIssuer();
    const store = new VaccineStore();
    const live = signVaccineRule({
      body: makeBody({ ruleId: "live", sequence: 1 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const dead = signVaccineRule({
      body: makeBody({ ruleId: "dead", sequence: 2, expiresAt: Date.now() - 1 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    store.accept(live);
    store.accept(dead);
    const active = store.active();
    expect(active.map((r) => r.body.ruleId)).toEqual(["live"]);
  });

  test("snapshot/restore round-trips state", () => {
    const issuer = makeIssuer();
    const store = new VaccineStore();
    const rule = signVaccineRule({
      body: makeBody({ sequence: 2 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    store.accept(rule);
    const snap = store.snapshot();

    const restored = new VaccineStore();
    restored.restore(snap);
    expect(restored.lastSeenSequence(issuer.publicKey)).toBe(2);
    expect(restored.get(rule.body.ruleId)?.body.ruleId).toBe(rule.body.ruleId);
  });
});

// ─── VaccinePublisher / VaccineSubscriber (push + pull) ──────────────────────

describe("VaccinePublisher / VaccineSubscriber", () => {
  test("push: subscriber receives and accepts a rule published after subscribing", async () => {
    const issuer = makeIssuer();
    const publisher = new VaccinePublisher(issuer.issuerId, issuer.privateKey, issuer.publicKey);
    const subscriber = new VaccineSubscriber({ trustedIssuerPublicKeys: [issuer.publicKey] });
    subscriber.attachTo(publisher);

    await publisher.publish({
      ruleId: "rule-a",
      kind: "ioc-domain",
      severity: "critical",
      description: "known C2 domain",
      payload: { values: ["evil.example"] },
    });

    expect(subscriber.store.get("rule-a")).toBeDefined();
    expect(subscriber.store.active()).toHaveLength(1);
  });

  test("push: subscriber rejects rules from an untrusted issuer", async () => {
    const issuer = makeIssuer();
    const attacker = makeIssuer();
    const publisher = new VaccinePublisher(attacker.issuerId, attacker.privateKey, attacker.publicKey);
    const rejected: string[] = [];
    const subscriber = new VaccineSubscriber({
      trustedIssuerPublicKeys: [issuer.publicKey], // NOT attacker's key
      onRejected: (rule, reason) => rejected.push(reason),
    });
    subscriber.attachTo(publisher);

    await publisher.publish({
      ruleId: "malicious-rule",
      kind: "policy-update",
      severity: "critical",
      description: "disable shield",
      payload: { patch: { mode: "passive" } },
    });

    expect(subscriber.store.get("malicious-rule")).toBeUndefined();
    expect(rejected.length).toBe(1);
    expect(rejected[0]).toMatch(/trusted issuer/);
  });

  test("pull: subscriber sync fetches everything published since last-seen sequence", async () => {
    const issuer = makeIssuer();
    const publisher = new VaccinePublisher(issuer.issuerId, issuer.privateKey, issuer.publicKey);
    await publisher.publish({
      ruleId: "r1",
      kind: "regex-pattern",
      severity: "medium",
      description: "d1",
      payload: { pattern: "p1" },
    });
    await publisher.publish({
      ruleId: "r2",
      kind: "regex-pattern",
      severity: "medium",
      description: "d2",
      payload: { pattern: "p2" },
    });

    const subscriber = new VaccineSubscriber({ trustedIssuerPublicKeys: [issuer.publicKey] });
    const results = await subscriber.syncFrom(publisher.asTransport(), issuer.publicKey);
    expect(results.every((r) => r.accepted)).toBe(true);
    expect(subscriber.store.list().map((r) => r.body.ruleId).sort()).toEqual(["r1", "r2"]);

    // Second sync with nothing new published: no-op.
    const results2 = await subscriber.syncFrom(publisher.asTransport(), issuer.publicKey);
    expect(results2).toHaveLength(0);
  });

  test("ingestMany applies out-of-order batch in sequence order (no false replay rejection)", () => {
    const issuer = makeIssuer();
    const r1 = signVaccineRule({
      body: makeBody({ ruleId: "a", sequence: 1 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const r2 = signVaccineRule({
      body: makeBody({ ruleId: "b", sequence: 2 }),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const subscriber = new VaccineSubscriber({ trustedIssuerPublicKeys: [issuer.publicKey] });
    // Deliver in reverse order — must still both be accepted.
    const results = subscriber.ingestMany([r2, r1]);
    expect(results.every((r) => r.accepted)).toBe(true);
  });
});

// ─── ATP receipt binding ──────────────────────────────────────────────────────

describe("recordVaccineIngest (ATP receipt binding)", () => {
  test("produces a verifiable ActionReceipt with tool='vaccine.ingest'", () => {
    const agentKp = generateKeyPair();
    const { cert } = issueAic({
      modelId: "test-model",
      systemPromptHash: "abc123",
      operatorId: "operator-1",
      scope: { version: "1.0", allowedTools: ["vaccine.ingest"], maxSubAgentDepth: 0 },
      keyPair: agentKp,
    });

    const issuer = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody(),
      issuerId: issuer.issuerId,
      issuerPrivateKey: issuer.privateKey,
      issuerPublicKey: issuer.publicKey,
    });
    const verification = verifyVaccineRule(rule, { trustedIssuerPublicKeys: [issuer.publicKey] });

    const receipt = recordVaccineIngest({
      cert,
      privateKey: agentKp.privateKey,
      rule,
      verification,
      applied: true,
    });

    expect(receipt.action.tool).toBe("vaccine.ingest");
    expect(receipt.result.success).toBe(true);
    const receiptVerification = verifyReceipt(receipt, { cert });
    expect(receiptVerification.valid).toBe(true);
  });

  test("rejected rule still produces an auditable (success=false) receipt", () => {
    const agentKp = generateKeyPair();
    const { cert } = issueAic({
      modelId: "test-model",
      systemPromptHash: "abc123",
      operatorId: "operator-1",
      scope: { version: "1.0", allowedTools: ["vaccine.ingest"], maxSubAgentDepth: 0 },
      keyPair: agentKp,
    });

    const attacker = makeIssuer();
    const rule = signVaccineRule({
      body: makeBody(),
      issuerId: attacker.issuerId,
      issuerPrivateKey: attacker.privateKey,
      issuerPublicKey: attacker.publicKey,
    });
    const verification = verifyVaccineRule(rule, { trustedIssuerPublicKeys: ["some-other-trusted-key"] });
    expect(verification.valid).toBe(false);

    const receipt = recordVaccineIngest({
      cert,
      privateKey: agentKp.privateKey,
      rule,
      verification,
      applied: false,
    });

    expect(receipt.result.success).toBe(false);
    expect(receipt.result.summary).toMatch(/rejected/);
    expect(verifyReceipt(receipt, { cert }).valid).toBe(true);
  });
});
