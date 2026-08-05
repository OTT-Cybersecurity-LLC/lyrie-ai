/**
 * kill-switch.test.ts — signed quarantine broadcast, subscriber enforcement
 * hooks, ATP-receipt-bound enforcement audit trail.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { generateKeyPair } from "../src/crypto";
import { issueAic } from "../src/aic";
import { verifyReceipt } from "../src/receipt";
import {
  KillSwitchBroadcaster,
  KillSwitchEnforcer,
  signKillSwitchOrder,
  verifyKillSwitchOrder,
  recordKillSwitchEnforcement,
  type KillSwitchOrderBody,
} from "../src/kill-switch";

function makeAuthority() {
  const kp = generateKeyPair();
  return { authorityId: "lyrie-security-ops", ...kp };
}

function makeBody(overrides: Partial<KillSwitchOrderBody> = {}): KillSwitchOrderBody {
  return {
    orderId: "order-1",
    action: "quarantine",
    target: { agentId: "rogue-agent-42" },
    reason: "confirmed self-replication attempt via breach attestation drift",
    sequence: 1,
    issuedAt: Date.now(),
    severity: "critical",
    ...overrides,
  };
}

// ─── sign / verify ────────────────────────────────────────────────────────────

describe("signKillSwitchOrder / verifyKillSwitchOrder", () => {
  test("freshly signed order verifies against its authority key", () => {
    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const result = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [authority.publicKey] });
    expect(result.valid).toBe(true);
  });

  test("refuses to verify with an empty trusted-authority list (no implicit trust)", () => {
    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const result = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  test("rejects an order from an untrusted authority", () => {
    const authority = makeAuthority();
    const attacker = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: attacker.authorityId,
      authorityPrivateKey: attacker.privateKey,
      authorityPublicKey: attacker.publicKey,
    });
    const result = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [authority.publicKey] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  test("tampered target fails signature verification", () => {
    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const tampered = { ...order, body: { ...order.body, target: { agentId: "innocent-agent" } } };
    const result = verifyKillSwitchOrder(tampered, { trustedAuthorityPublicKeys: [authority.publicKey] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("rejects malformed action value", () => {
    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      // @ts-expect-error intentional invalid action for the malformed-input test
      body: makeBody({ action: "delete-everything" }),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const result = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [authority.publicKey] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_MALFORMED");
  });

  test("rejects an order with no target fields set", () => {
    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody({ target: {} }),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const result = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [authority.publicKey] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_MALFORMED");
  });

  test("expired order is rejected", () => {
    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody({ expiresAt: Date.now() - 1000 }),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const result = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [authority.publicKey] });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("ATP_CERT_EXPIRED");
  });
});

// ─── KillSwitchEnforcer (subscriber-side hooks + anti-replay) ────────────────

describe("KillSwitchEnforcer", () => {
  test("verified order fans out to all registered hooks; quarantine recorded when any hook applies", async () => {
    const authority = makeAuthority();
    const applied: string[] = [];
    const enforcer = new KillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      hooks: [
        (order) => {
          if (order.body.target.agentId === "rogue-agent-42") {
            applied.push("shield-hook");
            return true;
          }
          return false;
        },
        (order) => {
          applied.push("daemon-hook");
          return false; // this hook observes but doesn't itself "apply" quarantine
        },
      ],
    });

    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });

    const result = await enforcer.enforce(order);
    expect(result.accepted).toBe(true);
    expect(result.hooksApplied).toBe(1);
    expect(applied).toEqual(["shield-hook", "daemon-hook"]);
    expect(enforcer.isQuarantined("order-1")).toBe(true);
  });

  test("a throwing hook does not prevent other hooks from applying", async () => {
    const authority = makeAuthority();
    const enforcer = new KillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      hooks: [
        () => {
          throw new Error("integration exploded");
        },
        () => true,
      ],
    });
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const result = await enforcer.enforce(order);
    expect(result.accepted).toBe(true);
    expect(result.hooksApplied).toBe(1);
  });

  test("rejects untrusted authority and does not fire hooks", async () => {
    const authority = makeAuthority();
    const attacker = makeAuthority();
    let fired = false;
    const enforcer = new KillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      hooks: [
        () => {
          fired = true;
          return true;
        },
      ],
    });
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: attacker.authorityId,
      authorityPrivateKey: attacker.privateKey,
      authorityPublicKey: attacker.publicKey,
    });
    const result = await enforcer.enforce(order);
    expect(result.accepted).toBe(false);
    expect(fired).toBe(false);
    expect(enforcer.isQuarantined("order-1")).toBe(false);
  });

  test("rejects replayed sequence from the same authority", async () => {
    const authority = makeAuthority();
    const enforcer = new KillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      hooks: [() => true],
    });
    const order = signKillSwitchOrder({
      body: makeBody({ sequence: 1 }),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const first = await enforcer.enforce(order);
    expect(first.accepted).toBe(true);

    const replay = signKillSwitchOrder({
      body: makeBody({ sequence: 1 }), // same sequence again
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const second = await enforcer.enforce(replay);
    expect(second.accepted).toBe(false);
    expect(second.reason).toMatch(/replayed|stale/);
  });

  test("lift-quarantine order removes a previously quarantined order id", async () => {
    const authority = makeAuthority();
    const enforcer = new KillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      hooks: [() => true],
    });
    const quarantineOrder = signKillSwitchOrder({
      body: makeBody({ sequence: 1, action: "quarantine" }),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    await enforcer.enforce(quarantineOrder);
    expect(enforcer.isQuarantined("order-1")).toBe(true);

    const liftOrder = signKillSwitchOrder({
      body: makeBody({ sequence: 2, action: "lift-quarantine" }),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    await enforcer.enforce(liftOrder);
    expect(enforcer.isQuarantined("order-1")).toBe(false);
  });
});

// ─── KillSwitchBroadcaster (push + pull) end-to-end ───────────────────────────

describe("KillSwitchBroadcaster", () => {
  test("push: attached enforcer receives and enforces a broadcast order", async () => {
    const authority = makeAuthority();
    const broadcaster = new KillSwitchBroadcaster(authority.authorityId, authority.privateKey, authority.publicKey);
    let quarantinedAgent: string | undefined;
    const enforcer = new KillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      hooks: [
        (order) => {
          quarantinedAgent = order.body.target.agentId;
          return true;
        },
      ],
    });
    enforcer.attachTo(broadcaster);

    await broadcaster.broadcast({
      orderId: "order-live-1",
      action: "quarantine",
      target: { agentId: "rogue-77" },
      reason: "shield rogue-ai detector: critical exfiltration attempt",
      severity: "critical",
    });

    // enforce() inside attachTo is fire-and-forget (void); allow microtask flush.
    await new Promise((r) => setTimeout(r, 0));
    expect(quarantinedAgent).toBe("rogue-77");
    expect(enforcer.isQuarantined("order-live-1")).toBe(true);
  });

  test("pull: catalog exposes broadcast history filterable by sequence", async () => {
    const authority = makeAuthority();
    const broadcaster = new KillSwitchBroadcaster(authority.authorityId, authority.privateKey, authority.publicKey);
    await broadcaster.broadcast({
      orderId: "o1",
      action: "quarantine",
      target: { agentId: "a1" },
      reason: "r1",
      severity: "high",
    });
    await broadcaster.broadcast({
      orderId: "o2",
      action: "halt",
      target: { agentId: "a2" },
      reason: "r2",
      severity: "critical",
    });
    expect(broadcaster.pull().map((o) => o.body.orderId)).toEqual(["o1", "o2"]);
    expect(broadcaster.pull(1).map((o) => o.body.orderId)).toEqual(["o2"]);
  });
});

// ─── ATP receipt binding ──────────────────────────────────────────────────────

describe("recordKillSwitchEnforcement (ATP receipt binding)", () => {
  test("produces a verifiable ActionReceipt with tool='kill_switch.enforce'", () => {
    const agentKp = generateKeyPair();
    const { cert } = issueAic({
      modelId: "test-model",
      systemPromptHash: "abc123",
      operatorId: "operator-1",
      scope: { version: "1.0", allowedTools: ["kill_switch.enforce"], maxSubAgentDepth: 0 },
      keyPair: agentKp,
    });

    const authority = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: authority.authorityId,
      authorityPrivateKey: authority.privateKey,
      authorityPublicKey: authority.publicKey,
    });
    const verification = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: [authority.publicKey] });

    const receipt = recordKillSwitchEnforcement({
      cert,
      privateKey: agentKp.privateKey,
      order,
      verification,
      enforced: true,
      detail: "shield-hook quarantined agent",
    });

    expect(receipt.action.tool).toBe("kill_switch.enforce");
    expect(receipt.result.success).toBe(true);
    expect(verifyReceipt(receipt, { cert }).valid).toBe(true);
  });

  test("rejected order still produces an auditable (success=false) receipt", () => {
    const agentKp = generateKeyPair();
    const { cert } = issueAic({
      modelId: "test-model",
      systemPromptHash: "abc123",
      operatorId: "operator-1",
      scope: { version: "1.0", allowedTools: ["kill_switch.enforce"], maxSubAgentDepth: 0 },
      keyPair: agentKp,
    });

    const attacker = makeAuthority();
    const order = signKillSwitchOrder({
      body: makeBody(),
      authorityId: attacker.authorityId,
      authorityPrivateKey: attacker.privateKey,
      authorityPublicKey: attacker.publicKey,
    });
    const verification = verifyKillSwitchOrder(order, { trustedAuthorityPublicKeys: ["some-other-key"] });
    expect(verification.valid).toBe(false);

    const receipt = recordKillSwitchEnforcement({
      cert,
      privateKey: agentKp.privateKey,
      order,
      verification,
      enforced: false,
    });

    expect(receipt.result.success).toBe(false);
    expect(receipt.result.summary).toMatch(/rejected/);
    expect(verifyReceipt(receipt, { cert }).valid).toBe(true);
  });
});
