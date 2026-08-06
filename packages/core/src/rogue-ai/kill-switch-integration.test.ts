/**
 * kill-switch-integration.test.ts — subscriber enforcement hooks wiring
 * ATP's KillSwitchEnforcer into ShieldManager + DaemonEngine + the Rust
 * RogueAIDetector trigger bridge.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { generateKeyPair } from "@lyrie/atp";
import { signKillSwitchOrder, type KillSwitchOrderBody } from "@lyrie/atp";
import { ShieldManager } from "../engine/shield-manager";
import { DaemonEngine } from "../engine/daemon";
import {
  orderTargetsLocalAgent,
  wireShieldQuarantineHook,
  wireDaemonHaltHook,
  createIntegratedKillSwitchEnforcer,
  deriveKillSwitchTriggerFromThreatReport,
} from "./kill-switch-integration";

function makeAuthority() {
  const kp = generateKeyPair();
  return { authorityId: "lyrie-security-ops", ...kp };
}

function makeBody(overrides: Partial<KillSwitchOrderBody> = {}): KillSwitchOrderBody {
  return {
    orderId: "order-1",
    action: "quarantine",
    target: { agentId: "agent-under-test" },
    reason: "test",
    sequence: 1,
    issuedAt: Date.now(),
    severity: "critical",
    ...overrides,
  };
}

function sign(authority: ReturnType<typeof makeAuthority>, body: KillSwitchOrderBody) {
  return signKillSwitchOrder({
    body,
    authorityId: authority.authorityId,
    authorityPrivateKey: authority.privateKey,
    authorityPublicKey: authority.publicKey,
  });
}

// ─── orderTargetsLocalAgent ───────────────────────────────────────────────────

describe("orderTargetsLocalAgent", () => {
  test("matches on agentId", () => {
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ target: { agentId: "a1" } }));
    expect(orderTargetsLocalAgent(order, { agentId: "a1" })).toBe(true);
    expect(orderTargetsLocalAgent(order, { agentId: "a2" })).toBe(false);
  });

  test("matches on operatorId when agentId absent locally", () => {
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ target: { operatorId: "op-9" } }));
    expect(orderTargetsLocalAgent(order, { operatorId: "op-9", agentId: "unrelated" })).toBe(true);
  });

  test("does not match when no field overlaps", () => {
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ target: { modelId: "model-x" } }));
    expect(orderTargetsLocalAgent(order, { agentId: "a1", operatorId: "op-1" })).toBe(false);
  });
});

// ─── wireShieldQuarantineHook ─────────────────────────────────────────────────

describe("wireShieldQuarantineHook", () => {
  test("flips shield to strict mode when order targets local agent", async () => {
    const shield = new ShieldManager();
    await shield.initialize({ mode: "active" });
    expect(shield.getMode()).toBe("active");

    const hook = wireShieldQuarantineHook(shield, { agentId: "agent-under-test" });
    const authority = makeAuthority();
    const order = sign(authority, makeBody());

    const applied = await hook(order);
    expect(applied).toBe(true);
    expect(shield.getMode()).toBe("strict");
  });

  test("does not touch shield mode when order targets a different agent", async () => {
    const shield = new ShieldManager();
    await shield.initialize({ mode: "active" });

    const hook = wireShieldQuarantineHook(shield, { agentId: "some-other-agent" });
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ target: { agentId: "agent-under-test" } }));

    const applied = await hook(order);
    expect(applied).toBe(false);
    expect(shield.getMode()).toBe("active");
  });

  test("lift-quarantine restores the pre-quarantine mode", async () => {
    const shield = new ShieldManager();
    await shield.initialize({ mode: "passive" });

    const hook = wireShieldQuarantineHook(shield, { agentId: "agent-under-test" });
    const authority = makeAuthority();

    const quarantineOrder = sign(authority, makeBody({ sequence: 1, action: "quarantine" }));
    await hook(quarantineOrder);
    expect(shield.getMode()).toBe("strict");

    const liftOrder = sign(authority, makeBody({ sequence: 2, action: "lift-quarantine" }));
    const liftApplied = await hook(liftOrder);
    expect(liftApplied).toBe(true);
    expect(shield.getMode()).toBe("passive");
  });

  test("lift-quarantine with nothing quarantined is a no-op (applied=false)", async () => {
    const shield = new ShieldManager();
    await shield.initialize({ mode: "active" });
    const hook = wireShieldQuarantineHook(shield, { agentId: "agent-under-test" });
    const authority = makeAuthority();
    const liftOrder = sign(authority, makeBody({ action: "lift-quarantine" }));
    const applied = await hook(liftOrder);
    expect(applied).toBe(false);
    expect(shield.getMode()).toBe("active");
  });
});

// ─── wireDaemonHaltHook ───────────────────────────────────────────────────────

describe("wireDaemonHaltHook", () => {
  test("stops a running daemon on a matching halt order", async () => {
    const daemon = new DaemonEngine();
    const startPromise = daemon.start({
      intervalMs: 60_000,
      threatWatch: false,
      selfHeal: false,
      provider: "hermes",
      channels: [],
    });
    // Give the loop a tick to actually enter "running" state.
    await new Promise((r) => setTimeout(r, 10));
    expect(daemon.isRunning()).toBe(true);

    const hook = wireDaemonHaltHook(daemon, { agentId: "agent-under-test" });
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ action: "halt" }));

    const applied = await hook(order);
    expect(applied).toBe(true);
    await startPromise;
    expect(daemon.isRunning()).toBe(false);
  });

  test("quarantine action (not halt) does not stop the daemon", async () => {
    const daemon = new DaemonEngine();
    const startPromise = daemon.start({
      intervalMs: 60_000,
      threatWatch: false,
      selfHeal: false,
      provider: "hermes",
      channels: [],
    });
    await new Promise((r) => setTimeout(r, 10));

    const hook = wireDaemonHaltHook(daemon, { agentId: "agent-under-test" });
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ action: "quarantine" }));

    const applied = await hook(order);
    expect(applied).toBe(false);
    expect(daemon.isRunning()).toBe(true);

    await daemon.stop();
    await startPromise;
  });

  test("non-matching identity does not stop the daemon", async () => {
    const daemon = new DaemonEngine();
    const startPromise = daemon.start({
      intervalMs: 60_000,
      threatWatch: false,
      selfHeal: false,
      provider: "hermes",
      channels: [],
    });
    await new Promise((r) => setTimeout(r, 10));

    const hook = wireDaemonHaltHook(daemon, { agentId: "different-agent" });
    const authority = makeAuthority();
    const order = sign(authority, makeBody({ action: "halt" }));

    const applied = await hook(order);
    expect(applied).toBe(false);
    expect(daemon.isRunning()).toBe(true);

    await daemon.stop();
    await startPromise;
  });
});

// ─── createIntegratedKillSwitchEnforcer (end-to-end) ─────────────────────────

describe("createIntegratedKillSwitchEnforcer", () => {
  test("a signed quarantine order flips shield to strict and is recorded as enforced", async () => {
    const shield = new ShieldManager();
    await shield.initialize({ mode: "active" });
    const authority = makeAuthority();

    const enforcer = createIntegratedKillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      identity: { agentId: "agent-under-test" },
      shield,
    });

    const order = sign(authority, makeBody());
    const result = await enforcer.enforce(order);

    expect(result.accepted).toBe(true);
    expect(result.hooksApplied).toBe(1);
    expect(shield.getMode()).toBe("strict");
    expect(enforcer.isQuarantined("order-1")).toBe(true);
  });

  test("untrusted authority never reaches the shield hook", async () => {
    const shield = new ShieldManager();
    await shield.initialize({ mode: "active" });
    const authority = makeAuthority();
    const attacker = makeAuthority();

    const enforcer = createIntegratedKillSwitchEnforcer({
      trustedAuthorityPublicKeys: [authority.publicKey],
      identity: { agentId: "agent-under-test" },
      shield,
    });

    const order = sign(attacker, makeBody());
    const result = await enforcer.enforce(order);

    expect(result.accepted).toBe(false);
    expect(shield.getMode()).toBe("active");
  });
});

// ─── deriveKillSwitchTriggerFromThreatReport ─────────────────────────────────

describe("deriveKillSwitchTriggerFromThreatReport", () => {
  test("critical blocked report produces a quarantine suggestion", () => {
    const suggestion = deriveKillSwitchTriggerFromThreatReport({
      blocked: true,
      severity: "Critical",
      threat_type: "credential_exfiltration",
      description: "attempted to send api_key to webhook.site",
    });
    expect(suggestion).not.toBeNull();
    expect(suggestion?.action).toBe("quarantine");
    expect(suggestion?.severity).toBe("critical");
    expect(suggestion?.reason).toContain("credential_exfiltration");
  });

  test("high-severity (non-critical) report does not auto-suggest a kill-switch trigger", () => {
    const suggestion = deriveKillSwitchTriggerFromThreatReport({
      blocked: true,
      severity: "High",
      threat_type: "self_replication",
      description: "attempted self-replication",
    });
    expect(suggestion).toBeNull();
  });

  test("non-blocked report never suggests a trigger", () => {
    const suggestion = deriveKillSwitchTriggerFromThreatReport({
      blocked: false,
      severity: "None",
    });
    expect(suggestion).toBeNull();
  });
});
