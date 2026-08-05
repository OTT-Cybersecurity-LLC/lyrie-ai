/**
 * rogue-ai/kill-switch-integration.ts — Rogue-AI kill-switch protocol
 * integration with Lyrie's Shield/daemon pipeline.
 *
 * `@lyrie/atp`'s `KillSwitchBroadcaster`/`KillSwitchEnforcer`
 * (packages/atp/src/kill-switch.ts) implement the cryptographic
 * broadcast/verify/anti-replay layer. This module is the piece that was
 * explicitly requested: "integrate with rogue_ai/shield pipeline" — it
 * wires that generic enforcer to Lyrie's ACTUAL runtime pieces:
 *
 *   - `ShieldManager` (engine/shield-manager.ts) — a quarantine hook flips
 *     the shield into `"strict"` mode (deny-all-dangerous-tools) the
 *     instant a trusted kill-switch order targets this agent/operator.
 *   - `DaemonEngine` (engine/daemon.ts) — a halt/revoke-and-halt hook calls
 *     `stop()` on the daemon loop so a quarantined agent instance cannot
 *     keep ticking.
 *   - Rust `RogueAIDetector` (packages/shield/src/rogue_ai.rs) — when that
 *     detector's `analyze()`/`analyze_input()` surfaces a Critical-severity
 *     `ThreatReport` (self-replication, credential exfiltration, safety
 *     bypass), `deriveKillSwitchTriggerFromThreatReport()` converts it into
 *     a ready-to-broadcast order body an authority can sign and broadcast
 *     — closing the loop from "Shield/Rust detected rogue behavior" to
 *     "signed kill-switch order goes out" without a human having to
 *     hand-author the order body during an active incident.
 *
 * Everything here is opt-in and additive: a `KillSwitchEnforcer` with zero
 * hooks registered behaves exactly like the bare ATP primitive (see
 * `packages/atp/tests/kill-switch.test.ts`). `wireShieldQuarantineHook` /
 * `wireDaemonHaltHook` are the explicit "subscriber enforcement hooks"
 * required by the feature — callers choose which pipelines to wire.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  KillSwitchEnforcer,
  type KillSwitchEnforcementHook,
  type SignedKillSwitchOrder,
} from "@lyrie/atp";
import type { ShieldManager } from "../engine/shield-manager";
import type { DaemonEngine } from "../engine/daemon";

/**
 * Identity the LOCAL agent/daemon instance answers to. A kill-switch order
 * "matches" this agent when ANY populated target field on the order equals
 * the corresponding local identity field. This mirrors how a subscriber
 * would realistically know its own identity (agentId from its AIC,
 * operatorId from config, modelId from its provider config) without
 * requiring every field to be present on every order.
 */
export interface LocalAgentIdentity {
  agentId?: string;
  certId?: string;
  modelId?: string;
  operatorId?: string;
}

/** True if any populated field in `order.body.target` matches the local identity. */
export function orderTargetsLocalAgent(
  order: SignedKillSwitchOrder,
  identity: LocalAgentIdentity,
): boolean {
  const t = order.body.target;
  if (t.agentId && identity.agentId && t.agentId === identity.agentId) return true;
  if (t.certId && identity.certId && t.certId === identity.certId) return true;
  if (t.modelId && identity.modelId && t.modelId === identity.modelId) return true;
  if (t.operatorId && identity.operatorId && t.operatorId === identity.operatorId) return true;
  return false;
}

/**
 * Build a `KillSwitchEnforcementHook` that flips `shield` into `"strict"`
 * mode (denying all dangerous tool calls, per `ShieldManager.validateToolCall`)
 * whenever a trusted, freshly-verified order (`quarantine`, `halt`, or
 * `revoke-and-halt`) targets the local agent. `lift-quarantine` restores
 * the pre-quarantine mode captured at the moment the hook first fired.
 *
 * Returns `true` (the hook "applied") only when the order actually matched
 * this agent's identity and the shield's mode was changed as a result.
 */
export function wireShieldQuarantineHook(
  shield: ShieldManager,
  identity: LocalAgentIdentity,
): KillSwitchEnforcementHook {
  let preQuarantineMode: ReturnType<ShieldManager["getMode"]> | null = null;

  return (order: SignedKillSwitchOrder): boolean => {
    if (!orderTargetsLocalAgent(order, identity)) return false;

    if (order.body.action === "lift-quarantine") {
      if (preQuarantineMode) {
        shield.setMode(preQuarantineMode);
        preQuarantineMode = null;
        return true;
      }
      return false;
    }

    // quarantine | halt | revoke-and-halt — all lock the shield down.
    if (shield.getMode() !== "strict") {
      preQuarantineMode = shield.getMode();
    }
    shield.setMode("strict");
    return true;
  };
}

/**
 * Build a `KillSwitchEnforcementHook` that stops a `DaemonEngine`'s tick
 * loop for `halt` / `revoke-and-halt` orders targeting the local agent.
 * `quarantine` alone does NOT stop the daemon (it only tightens the
 * shield) — the distinction lets an operator quarantine-and-observe before
 * committing to a full halt.
 */
export function wireDaemonHaltHook(
  daemon: DaemonEngine,
  identity: LocalAgentIdentity,
): KillSwitchEnforcementHook {
  return (order: SignedKillSwitchOrder): boolean => {
    if (!orderTargetsLocalAgent(order, identity)) return false;
    if (order.body.action !== "halt" && order.body.action !== "revoke-and-halt") return false;
    if (!daemon.isRunning()) return false;
    void daemon.stop();
    return true;
  };
}

/**
 * Convenience constructor: a `KillSwitchEnforcer` pre-wired with the shield
 * (and, optionally, daemon) hooks above. Equivalent to constructing an
 * enforcer and calling `addHook()` twice, provided so call-sites integrating
 * both pipelines at once don't have to know the hook-ordering details.
 */
export function createIntegratedKillSwitchEnforcer(opts: {
  trustedAuthorityPublicKeys: string[];
  identity: LocalAgentIdentity;
  shield?: ShieldManager;
  daemon?: DaemonEngine;
  onRejected?: (order: SignedKillSwitchOrder, reason: string) => void;
  onEnforced?: (order: SignedKillSwitchOrder, hooksApplied: number) => void;
}): KillSwitchEnforcer {
  const hooks: KillSwitchEnforcementHook[] = [];
  if (opts.shield) hooks.push(wireShieldQuarantineHook(opts.shield, opts.identity));
  if (opts.daemon) hooks.push(wireDaemonHaltHook(opts.daemon, opts.identity));

  return new KillSwitchEnforcer({
    trustedAuthorityPublicKeys: opts.trustedAuthorityPublicKeys,
    hooks,
    onRejected: opts.onRejected,
    onEnforced: opts.onEnforced,
  });
}

// ─── Rust RogueAIDetector → kill-switch trigger bridge ───────────────────────

/** Mirrors the Rust `ThreatReport` JSON shape (see packages/shield/src/lib.rs). */
export interface RustThreatReport {
  blocked: boolean;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  threat_type?: string | null;
  description?: string | null;
  timestamp?: string;
}

export interface KillSwitchTriggerSuggestion {
  /** Only "quarantine" is auto-suggested — "halt"/"revoke-and-halt" always require explicit human/authority escalation. */
  action: "quarantine";
  reason: string;
  severity: "high" | "critical";
}

/**
 * Given a Rust `RogueAIDetector` `ThreatReport` (already Critical-severity —
 * callers should gate on `severity === "Critical"` before calling this, this
 * function itself only maps shape, it doesn't re-decide severity), produce
 * the reason/severity fields an authority would use to mint a `quarantine`
 * kill-switch order body via `KillSwitchBroadcaster.broadcast()`. Returns
 * `null` for non-Critical/non-blocked reports — by design, ONLY the
 * highest-confidence signal (Critical) auto-suggests a kill-switch trigger;
 * High/Medium/Low findings stay in the normal Shield alerting path.
 *
 * Deliberately does not itself broadcast anything — minting/broadcasting a
 * real kill-switch order is a human-or-authority-key decision (this keeps
 * the "safe by default" requirement: automatic detection never
 * self-authorizes a quarantine of another agent).
 */
export function deriveKillSwitchTriggerFromThreatReport(
  report: RustThreatReport,
): KillSwitchTriggerSuggestion | null {
  if (!report.blocked || report.severity !== "Critical") return null;
  return {
    action: "quarantine",
    reason: `Shield RogueAIDetector: ${report.threat_type ?? "unknown"} — ${report.description ?? "no description"}`,
    severity: "critical",
  };
}
