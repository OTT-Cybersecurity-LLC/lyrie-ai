/**
 * kill-switch.ts — Rogue-AI kill-switch protocol.
 *
 * A signed, broadcastable order that tells every subscribing daemon/agent
 * instance to immediately quarantine (or fully halt) a specific agent
 * identity, model, or operator — e.g. because a Breach Attestation, a
 * Rogue-AI Shield detection, or a human operator has determined an agent
 * is compromised or behaving adversarially.
 *
 * Design goals (mirrors `vaccine.ts`'s trust model deliberately — same
 * primitives, same anti-replay strategy, so operators only have to reason
 * about ATP crypto once):
 *   - `KillSwitchOrder` is Ed25519-signed by an authority key. Only orders
 *     signed by a subscriber's configured trusted-authority key(s) are
 *     ever enforced — a malicious or spoofed broadcaster cannot quarantine
 *     anything.
 *   - Orders carry a monotonic `sequence` per authority to block replay,
 *     exactly like `VaccineStore`.
 *   - Enforcement is a *local* decision: `KillSwitchEnforcer` verifies the
 *     order then calls out to injected `KillSwitchEnforcementHook`s (the
 *     "subscriber enforcement hooks" requirement) — e.g. one hook flips
 *     `ShieldManager` into `"strict"`/deny-all mode, another hook stops a
 *     `DaemonEngine` loop. This module owns verification + fan-out, not the
 *     mechanics of any specific pipeline's shutdown.
 *   - Every enforcement decision (applied or refused) is recorded as an ATP
 *     `ActionReceipt` (`action.tool = "kill_switch.enforce"`), so
 *     "did this agent actually quarantine X?" has the same cryptographic
 *     answer any other ATP-covered action does.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { verifyCanonical, signCanonical } from "./crypto";
import { signReceipt, type SignReceiptInput } from "./receipt";
import type { ActionReceipt, AgentIdentityCertificate, VerificationResult } from "./types";
import { ATP_VERSION } from "./types";

// ─── Order shape ─────────────────────────────────────────────────────────────

export type KillSwitchAction = "quarantine" | "halt" | "revoke-and-halt" | "lift-quarantine";

export interface KillSwitchOrderBody {
  /** Stable order id. */
  orderId: string;
  action: KillSwitchAction;
  /**
   * What this order targets. At least one of these should be set;
   * enforcement hooks decide how to match against locally-known identity.
   */
  target: {
    agentId?: string;
    certId?: string;
    modelId?: string;
    operatorId?: string;
  };
  /** Human-readable justification (e.g. "breach attestation drift confirmed"). */
  reason: string;
  /** Monotonic per-authority counter. Subscribers reject sequence <= last-seen. */
  sequence: number;
  /** Unix ms — when the authority issued the order. */
  issuedAt: number;
  /** Unix ms — optional expiry (mainly relevant for "lift-quarantine" TTL semantics). */
  expiresAt?: number;
  /** Free-form severity for prioritisation/logging. */
  severity: "high" | "critical";
}

export interface SignedKillSwitchOrder {
  version: typeof ATP_VERSION;
  body: KillSwitchOrderBody;
  /** Human-readable authority id (e.g. "lyrie-security-ops"). */
  authorityId: string;
  /** Ed25519 public key (base64) of the authority. */
  authorityPublicKey: string;
  /** Ed25519 signature (base64) over canonicalize(body). */
  signature: string;
}

export const KILL_SWITCH_VERSION = "lyrie-kill-switch-1.0.0";

// ─── Sign / verify ───────────────────────────────────────────────────────────

export interface SignKillSwitchOrderInput {
  body: KillSwitchOrderBody;
  authorityId: string;
  authorityPrivateKey: string;
  authorityPublicKey: string;
}

export function signKillSwitchOrder(input: SignKillSwitchOrderInput): SignedKillSwitchOrder {
  const signature = signCanonical(input.body, input.authorityPrivateKey);
  return {
    version: ATP_VERSION,
    body: input.body,
    authorityId: input.authorityId,
    authorityPublicKey: input.authorityPublicKey,
    signature,
  };
}

export interface VerifyKillSwitchOrderOptions {
  /** Only enforce orders signed by one of these authority public keys (base64). REQUIRED in production — pass explicitly, no implicit trust-the-embedded-key fallback. */
  trustedAuthorityPublicKeys: string[];
  now?: number;
}

export function verifyKillSwitchOrder(
  order: SignedKillSwitchOrder,
  opts: VerifyKillSwitchOrderOptions,
): VerificationResult {
  if (!order || typeof order !== "object" || !order.body || typeof order.body !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "order/body must be objects" };
  }
  if (order.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  const b = order.body;
  if (typeof b.orderId !== "string" || !b.orderId) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.orderId required" };
  }
  const validActions: KillSwitchAction[] = ["quarantine", "halt", "revoke-and-halt", "lift-quarantine"];
  if (!validActions.includes(b.action)) {
    return { valid: false, code: "ATP_MALFORMED", reason: `body.action must be one of ${validActions.join(", ")}` };
  }
  if (!b.target || typeof b.target !== "object" || Object.values(b.target).every((v) => !v)) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.target must identify at least one field" };
  }
  if (typeof b.sequence !== "number" || !Number.isFinite(b.sequence)) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.sequence must be a finite number" };
  }
  if (typeof b.issuedAt !== "number") {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.issuedAt must be a number" };
  }

  if (!opts.trustedAuthorityPublicKeys || opts.trustedAuthorityPublicKeys.length === 0) {
    return {
      valid: false,
      code: "ATP_PUBLIC_KEY_INVALID",
      reason: "verifyKillSwitchOrder requires a non-empty trustedAuthorityPublicKeys list — refuses to trust an unpinned authority",
    };
  }
  if (!opts.trustedAuthorityPublicKeys.includes(order.authorityPublicKey)) {
    return {
      valid: false,
      code: "ATP_PUBLIC_KEY_INVALID",
      reason: `authority public key ${order.authorityPublicKey} is not a trusted kill-switch authority`,
    };
  }

  if (!verifyCanonical(order.body, order.authorityPublicKey, order.signature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "kill-switch order signature did not verify" };
  }

  const now = opts.now ?? Date.now();
  if (typeof b.expiresAt === "number" && now > b.expiresAt) {
    return { valid: false, code: "ATP_CERT_EXPIRED", reason: `order expired at ${b.expiresAt}` };
  }

  return { valid: true };
}

// ─── ATP receipt binding ─────────────────────────────────────────────────────

export interface RecordKillSwitchEnforcementInput {
  cert: AgentIdentityCertificate;
  privateKey: string;
  order: SignedKillSwitchOrder;
  verification: VerificationResult;
  /** True if local enforcement hooks actually ran and reported success. */
  enforced: boolean;
  /** Optional free-form detail (e.g. which hooks fired) — no secrets. */
  detail?: string;
}

export function recordKillSwitchEnforcement(input: RecordKillSwitchEnforcementInput): ActionReceipt {
  const signInput: SignReceiptInput = {
    cert: input.cert,
    privateKey: input.privateKey,
    action: {
      tool: "kill_switch.enforce",
      params: {
        orderId: input.order.body.orderId,
        action: input.order.body.action,
        target: input.order.body.target,
        authorityId: input.order.authorityId,
        sequence: input.order.body.sequence,
      },
      timestamp: Date.now(),
    },
    result: {
      success: input.verification.valid && input.enforced,
      summary: input.verification.valid
        ? input.enforced
          ? `enforced kill-switch order ${input.order.body.orderId} (${input.order.body.action}) from ${input.order.authorityId}${input.detail ? `: ${input.detail}` : ""}`
          : `verified but did not enforce kill-switch order ${input.order.body.orderId} (no hook applied it)`
        : `rejected kill-switch order ${input.order.body.orderId}: ${input.verification.reason ?? input.verification.code}`,
      timestamp: Date.now(),
    },
  };
  return signReceipt(signInput);
}

// ─── Broadcaster (authority side) ────────────────────────────────────────────

export type KillSwitchListener = (order: SignedKillSwitchOrder) => void | Promise<void>;

/**
 * KillSwitchBroadcaster — the authority side. Mints signed orders and fans
 * them out to every registered listener (push). A `pull()` catalog is also
 * kept so late-joining subscribers can catch up on missed orders — same
 * dual push/pull shape as `VaccinePublisher`.
 */
export class KillSwitchBroadcaster {
  private catalog: SignedKillSwitchOrder[] = [];
  private listeners: KillSwitchListener[] = [];
  private sequenceCounter = 0;

  constructor(
    private readonly authorityId: string,
    private readonly authorityPrivateKey: string,
    private readonly authorityPublicKey: string,
  ) {}

  subscribe(listener: KillSwitchListener): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  async broadcast(
    body: Omit<KillSwitchOrderBody, "sequence" | "issuedAt"> & { sequence?: number; issuedAt?: number },
  ): Promise<SignedKillSwitchOrder> {
    this.sequenceCounter = Math.max(this.sequenceCounter + 1, (body.sequence ?? 0) + 1);
    const fullBody: KillSwitchOrderBody = {
      ...body,
      sequence: body.sequence ?? this.sequenceCounter,
      issuedAt: body.issuedAt ?? Date.now(),
    };
    const order = signKillSwitchOrder({
      body: fullBody,
      authorityId: this.authorityId,
      authorityPrivateKey: this.authorityPrivateKey,
      authorityPublicKey: this.authorityPublicKey,
    });
    this.catalog.push(order);
    for (const listener of this.listeners) {
      await listener(order);
    }
    return order;
  }

  pull(sinceSequence = -1): SignedKillSwitchOrder[] {
    return this.catalog.filter((o) => o.body.sequence > sinceSequence);
  }

  publicKey(): string {
    return this.authorityPublicKey;
  }
}

// ─── Enforcer (subscriber side) ──────────────────────────────────────────────

/**
 * A hook invoked for every *verified, fresh* kill-switch order. Hooks
 * decide locally whether `order.body.target` matches something they own
 * (agent id, cert id, model id, operator id) and, if so, perform the
 * quarantine/halt action. Hooks must not throw — the enforcer treats a
 * thrown hook as "did not apply" and continues to the next hook so one
 * broken integration cannot mask another's successful quarantine.
 *
 * Returns `true` if this hook took quarantine/halt action for the order.
 */
export type KillSwitchEnforcementHook = (order: SignedKillSwitchOrder) => boolean | Promise<boolean>;

export interface KillSwitchEnforcerOptions {
  trustedAuthorityPublicKeys: string[];
  hooks?: KillSwitchEnforcementHook[];
  onRejected?: (order: SignedKillSwitchOrder, reason: string) => void;
  onEnforced?: (order: SignedKillSwitchOrder, hooksApplied: number) => void;
}

export interface KillSwitchEnforceResult {
  accepted: boolean;
  reason?: string;
  order: SignedKillSwitchOrder;
  hooksApplied: number;
}

/**
 * KillSwitchEnforcer — subscriber-side verification + hook fan-out, with
 * the same per-authority anti-replay sequence tracking as `VaccineStore`.
 */
export class KillSwitchEnforcer {
  private lastSequence = new Map<string, number>();
  private appliedOrders = new Map<string, SignedKillSwitchOrder>();
  private hooks: KillSwitchEnforcementHook[];
  private opts: KillSwitchEnforcerOptions;

  constructor(opts: KillSwitchEnforcerOptions) {
    this.opts = opts;
    this.hooks = opts.hooks ?? [];
  }

  addHook(hook: KillSwitchEnforcementHook): () => void {
    this.hooks.push(hook);
    return () => {
      this.hooks = this.hooks.filter((h) => h !== hook);
    };
  }

  lastSeenSequence(authorityPublicKey: string): number {
    return this.lastSequence.get(authorityPublicKey) ?? -1;
  }

  /** Orders that have been accepted and enforced (>=1 hook applied), keyed by orderId. */
  quarantined(): SignedKillSwitchOrder[] {
    return Array.from(this.appliedOrders.values());
  }

  isQuarantined(orderId: string): boolean {
    return this.appliedOrders.has(orderId);
  }

  async enforce(order: SignedKillSwitchOrder): Promise<KillSwitchEnforceResult> {
    const verification = verifyKillSwitchOrder(order, {
      trustedAuthorityPublicKeys: this.opts.trustedAuthorityPublicKeys,
    });
    if (!verification.valid) {
      const reason = verification.reason ?? verification.code ?? "invalid";
      this.opts.onRejected?.(order, reason);
      return { accepted: false, reason, order, hooksApplied: 0 };
    }
    const prevSeq = this.lastSeenSequence(order.authorityPublicKey);
    if (order.body.sequence <= prevSeq) {
      const reason = `replayed/stale sequence ${order.body.sequence} (last seen ${prevSeq})`;
      this.opts.onRejected?.(order, reason);
      return { accepted: false, reason, order, hooksApplied: 0 };
    }
    this.lastSequence.set(order.authorityPublicKey, order.body.sequence);

    let hooksApplied = 0;
    for (const hook of this.hooks) {
      try {
        const applied = await hook(order);
        if (applied) hooksApplied++;
      } catch {
        // A misbehaving hook must never block other hooks or crash the enforcer.
      }
    }

    if (order.body.action === "lift-quarantine") {
      this.appliedOrders.delete(order.body.orderId);
    } else if (hooksApplied > 0) {
      this.appliedOrders.set(order.body.orderId, order);
    }

    this.opts.onEnforced?.(order, hooksApplied);
    return { accepted: true, order, hooksApplied };
  }

  /** Register this enforcer to receive live broadcasts from an authority. */
  attachTo(broadcaster: KillSwitchBroadcaster): () => void {
    return broadcaster.subscribe((order) => {
      void this.enforce(order);
    });
  }
}
