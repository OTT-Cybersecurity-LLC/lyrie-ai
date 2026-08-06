/**
 * vaccine.ts — Cross-agent vaccine propagation.
 *
 * "Vaccine" here means a signed, distributable defensive rule: a pattern,
 * signature, or policy update that lets a Lyrie Shield/daemon instance
 * detect (or block) a threat it has never seen locally, because a peer
 * agent (or the central Lyrie threat-intel service) already encountered it
 * and pushed the rule out.
 *
 * This module implements the *transport + trust* layer:
 *   - `VaccineRule` — the payload (detector pattern + metadata).
 *   - `signVaccineRule` / `verifyVaccineRule` — Ed25519 signing over the
 *     canonical rule body, reusing ATP's existing crypto primitives (no new
 *     crypto surface).
 *   - `createVaccineReceipt` — every rule ingested by a daemon is wrapped in
 *     an ATP `ActionReceipt` (`action.tool = "vaccine.ingest"`), so rule
 *     application is itself an auditable, non-repudiable agent action using
 *     the SAME receipt primitive the rest of ATP uses for tool calls. This
 *     is the "using ATP receipts" requirement — propagation piggybacks on
 *     the receipt log rather than inventing a parallel audit trail.
 *   - `VaccinePublisher` / `VaccineSubscriber` — an in-process pub/sub layer
 *     (push) plus a pull/poll API, both signature-checked before rules are
 *     considered "verified". Real network transport (HTTP push, message
 *     bus) is intentionally left as an injectable `transport` — this module
 *     owns trust, not sockets.
 *
 * Threat model: a compromised or malicious publisher cannot get a rule
 * applied without the subscriber's configured trusted-issuer public key
 * signing it. Replay of an old rule is caught via monotonic `sequence` +
 * `issuedAt`; a subscriber tracks the highest sequence number seen per
 * issuer and rejects anything at or below it (see `VaccineStore`).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { canonicalize, newUuid, signCanonical, verifyCanonical } from "./crypto";
import { signReceipt, verifyReceipt, type SignReceiptInput } from "./receipt";
import type { ActionReceipt, AgentIdentityCertificate, VerificationResult } from "./types";
import { ATP_VERSION } from "./types";

// ─── Rule shape ──────────────────────────────────────────────────────────────

export type VaccineRuleKind =
  | "regex-pattern"
  | "ioc-domain"
  | "ioc-hash"
  | "ioc-ip"
  | "behavioral-signature"
  | "policy-update";

export type VaccineSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface VaccineRuleBody {
  /** Stable rule id, chosen by the publisher (e.g. "CVE-2026-XXXX-detector"). */
  ruleId: string;
  kind: VaccineRuleKind;
  severity: VaccineSeverity;
  /** Human-readable summary — never contains secrets/PII. */
  description: string;
  /**
   * The actual detection payload. Shape depends on `kind`:
   *   - regex-pattern / behavioral-signature: { pattern: string, flags?: string }
   *   - ioc-domain / ioc-hash / ioc-ip: { values: string[] }
   *   - policy-update: { patch: Record<string, unknown> } (opaque to this layer)
   */
  payload: Record<string, unknown>;
  /** Monotonic per-issuer counter. Subscribers reject sequence <= last-seen. */
  sequence: number;
  /** Unix ms — when the publisher minted this rule. */
  issuedAt: number;
  /** Unix ms — optional expiry; expired rules are not applied. */
  expiresAt?: number;
  /** Free-form provenance tags (e.g. ["lyrie-threat-intel", "cve-watch"]). */
  tags?: string[];
}

/** A rule ready to distribute — body + issuer identity + signature. */
export interface SignedVaccineRule {
  version: typeof ATP_VERSION;
  body: VaccineRuleBody;
  /** Agent/operator id of the issuer (human-readable, not a crypto identity). */
  issuerId: string;
  /** Ed25519 public key (base64) of the issuer. */
  issuerPublicKey: string;
  /** Ed25519 signature (base64) over canonicalize(body). */
  signature: string;
}

export const VACCINE_VERSION = "lyrie-vaccine-1.0.0";

// ─── Sign / verify ───────────────────────────────────────────────────────────

export interface SignVaccineRuleInput {
  body: VaccineRuleBody;
  issuerId: string;
  issuerPrivateKey: string;
  issuerPublicKey: string;
}

/** Sign a vaccine rule body, producing a distributable `SignedVaccineRule`. */
export function signVaccineRule(input: SignVaccineRuleInput): SignedVaccineRule {
  const signature = signCanonical(input.body, input.issuerPrivateKey);
  return {
    version: ATP_VERSION,
    body: input.body,
    issuerId: input.issuerId,
    issuerPublicKey: input.issuerPublicKey,
    signature,
  };
}

export interface VerifyVaccineRuleOptions {
  /** Only accept rules signed by one of these public keys (base64). Empty/undefined = trust the embedded key (NOT recommended for untrusted transports). */
  trustedIssuerPublicKeys?: string[];
  /** Wall-clock for expiry checks. Default `Date.now()`. */
  now?: number;
}

/**
 * Verify a signed vaccine rule:
 *   1. Structural well-formedness.
 *   2. Signature is valid over the canonical body.
 *   3. Issuer public key is in the trusted set (if one was supplied).
 *   4. Rule has not expired.
 */
export function verifyVaccineRule(
  rule: SignedVaccineRule,
  opts: VerifyVaccineRuleOptions = {},
): VerificationResult {
  if (!rule || typeof rule !== "object" || !rule.body || typeof rule.body !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "rule/body must be objects" };
  }
  if (rule.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  const b = rule.body;
  if (typeof b.ruleId !== "string" || !b.ruleId) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.ruleId required" };
  }
  if (typeof b.sequence !== "number" || !Number.isFinite(b.sequence)) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.sequence must be a finite number" };
  }
  if (typeof b.issuedAt !== "number") {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.issuedAt must be a number" };
  }
  if (typeof rule.signature !== "string" || !rule.signature) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "signature missing" };
  }

  if (opts.trustedIssuerPublicKeys && opts.trustedIssuerPublicKeys.length > 0) {
    if (!opts.trustedIssuerPublicKeys.includes(rule.issuerPublicKey)) {
      return {
        valid: false,
        code: "ATP_PUBLIC_KEY_INVALID",
        reason: `issuer public key ${rule.issuerPublicKey} is not in the trusted issuer set`,
      };
    }
  }

  if (!verifyCanonical(rule.body, rule.issuerPublicKey, rule.signature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "vaccine rule signature did not verify" };
  }

  const now = opts.now ?? Date.now();
  if (typeof b.expiresAt === "number" && now > b.expiresAt) {
    return { valid: false, code: "ATP_CERT_EXPIRED", reason: `rule expired at ${b.expiresAt}` };
  }

  return { valid: true };
}

// ─── ATP receipt binding ─────────────────────────────────────────────────────

/**
 * Wrap the ingestion of a vaccine rule by a daemon/agent in a standard ATP
 * `ActionReceipt` (`action.tool = "vaccine.ingest"`). This is what makes
 * rule propagation "use ATP receipts": every daemon that pulls/applies a
 * rule produces the same tamper-evident audit artifact any other tool call
 * would, filterable via `receiptsForCert()` alongside the rest of an
 * agent's action log.
 *
 * `result.success` reflects whether the rule passed `verifyVaccineRule()`
 * AND (if `applied` is supplied) was actually applied locally — a receipt
 * is emitted either way so rejected rules are auditable too.
 */
export interface RecordVaccineIngestInput {
  /** AIC + private key of the ingesting agent (the receipt signer). */
  cert: AgentIdentityCertificate;
  privateKey: string;
  rule: SignedVaccineRule;
  verification: VerificationResult;
  /** True if the rule was actually loaded into the local detector after verification. */
  applied: boolean;
}

export function recordVaccineIngest(input: RecordVaccineIngestInput): ActionReceipt {
  const signInput: SignReceiptInput = {
    cert: input.cert,
    privateKey: input.privateKey,
    action: {
      tool: "vaccine.ingest",
      params: {
        ruleId: input.rule.body.ruleId,
        kind: input.rule.body.kind,
        severity: input.rule.body.severity,
        issuerId: input.rule.issuerId,
        sequence: input.rule.body.sequence,
      },
      timestamp: Date.now(),
    },
    result: {
      success: input.verification.valid && input.applied,
      summary: input.verification.valid
        ? input.applied
          ? `applied vaccine rule ${input.rule.body.ruleId} from ${input.rule.issuerId}`
          : `verified but did not apply vaccine rule ${input.rule.body.ruleId} (policy declined)`
        : `rejected vaccine rule ${input.rule.body.ruleId}: ${input.verification.reason ?? input.verification.code}`,
      timestamp: Date.now(),
    },
  };
  return signReceipt(signInput);
}

/** Convenience re-export so callers verifying vaccine-ingest receipts don't need a second import. */
export { verifyReceipt };

// ─── Store: sequence tracking (anti-replay) ──────────────────────────────────

/**
 * VaccineStore — tracks the highest accepted `sequence` per issuer so a
 * captured-and-replayed old rule (even if validly signed) cannot be
 * re-applied to roll a subscriber's ruleset backward.
 *
 * Pure in-memory reference implementation; callers needing durability
 * should persist `snapshot()`/restore via `restore()`.
 */
export class VaccineStore {
  private lastSequence = new Map<string, number>();
  private rules = new Map<string, SignedVaccineRule>();

  /** Highest sequence number accepted so far for `issuerPublicKey`. -1 if none. */
  lastSeenSequence(issuerPublicKey: string): number {
    return this.lastSequence.get(issuerPublicKey) ?? -1;
  }

  /** True if `rule` is a fresh (non-replayed) sequence for its issuer. */
  isFreshSequence(rule: SignedVaccineRule): boolean {
    return rule.body.sequence > this.lastSeenSequence(rule.issuerPublicKey);
  }

  /**
   * Record a rule as accepted: bump the issuer's sequence high-water-mark
   * and store the rule keyed by ruleId (last-write-wins per ruleId).
   * Callers MUST have already verified the rule + checked `isFreshSequence`.
   */
  accept(rule: SignedVaccineRule): void {
    const prev = this.lastSeenSequence(rule.issuerPublicKey);
    if (rule.body.sequence > prev) {
      this.lastSequence.set(rule.issuerPublicKey, rule.body.sequence);
    }
    this.rules.set(rule.body.ruleId, rule);
  }

  get(ruleId: string): SignedVaccineRule | undefined {
    return this.rules.get(ruleId);
  }

  list(): SignedVaccineRule[] {
    return Array.from(this.rules.values());
  }

  /** Rules that are not expired as of `now` (default Date.now()). */
  active(now: number = Date.now()): SignedVaccineRule[] {
    return this.list().filter((r) => typeof r.body.expiresAt !== "number" || now <= r.body.expiresAt);
  }

  snapshot(): { lastSequence: Array<[string, number]>; rules: SignedVaccineRule[] } {
    return { lastSequence: Array.from(this.lastSequence.entries()), rules: this.list() };
  }

  restore(snap: { lastSequence: Array<[string, number]>; rules: SignedVaccineRule[] }): void {
    this.lastSequence = new Map(snap.lastSequence);
    this.rules = new Map(snap.rules.map((r) => [r.body.ruleId, r]));
  }
}

// ─── Publisher / Subscriber (push + pull) ────────────────────────────────────

/** Injectable transport — real deployments wire this to HTTP/webhook/message-bus. */
export interface VaccineTransport {
  /** Push a signed rule to all currently-registered subscriber callbacks. */
  push(rule: SignedVaccineRule): Promise<void>;
  /** Pull the current catalog of rules the publisher currently holds. */
  pull(sinceSequence?: number): Promise<SignedVaccineRule[]>;
}

export type VaccineSubscriberHandler = (rule: SignedVaccineRule) => void | Promise<void>;

/**
 * VaccinePublisher — mints and distributes signed vaccine rules.
 *
 * `publish()` signs the rule body under the publisher's key and hands it to
 * every registered subscriber callback (push model) as well as appending it
 * to an internal catalog subscribers can `pull()` on reconnect/poll (pull
 * model) — see `asTransport()`.
 */
export class VaccinePublisher {
  private catalog: SignedVaccineRule[] = [];
  private subscribers: VaccineSubscriberHandler[] = [];
  private sequenceCounter = 0;

  constructor(
    private readonly issuerId: string,
    private readonly issuerPrivateKey: string,
    private readonly issuerPublicKey: string,
  ) {}

  /** Register a push subscriber. Returns an unsubscribe function. */
  subscribe(handler: VaccineSubscriberHandler): () => void {
    this.subscribers.push(handler);
    return () => {
      this.subscribers = this.subscribers.filter((h) => h !== handler);
    };
  }

  /**
   * Mint + sign + distribute a new rule. `sequence` is auto-assigned
   * (monotonic per publisher instance) unless explicitly overridden —
   * override only for tests/replay simulations.
   */
  async publish(
    body: Omit<VaccineRuleBody, "sequence" | "issuedAt"> & { sequence?: number; issuedAt?: number },
  ): Promise<SignedVaccineRule> {
    this.sequenceCounter = Math.max(this.sequenceCounter + 1, (body.sequence ?? 0) + 1);
    const fullBody: VaccineRuleBody = {
      ...body,
      sequence: body.sequence ?? this.sequenceCounter,
      issuedAt: body.issuedAt ?? Date.now(),
    };
    const rule = signVaccineRule({
      body: fullBody,
      issuerId: this.issuerId,
      issuerPrivateKey: this.issuerPrivateKey,
      issuerPublicKey: this.issuerPublicKey,
    });
    this.catalog.push(rule);
    for (const sub of this.subscribers) {
      await sub(rule);
    }
    return rule;
  }

  /** Full rule catalog, optionally filtered to sequence > `sinceSequence`. */
  pull(sinceSequence = -1): SignedVaccineRule[] {
    return this.catalog.filter((r) => r.body.sequence > sinceSequence);
  }

  publicKey(): string {
    return this.issuerPublicKey;
  }

  /** Adapt this publisher to the generic `VaccineTransport` interface. */
  asTransport(): VaccineTransport {
    return {
      push: async (rule) => {
        for (const sub of this.subscribers) await sub(rule);
      },
      pull: async (sinceSequence) => this.pull(sinceSequence),
    };
  }
}

export interface VaccineSubscriberOptions {
  trustedIssuerPublicKeys: string[];
  store?: VaccineStore;
  /** Called for every rule that fails verification/replay — never throws. */
  onRejected?: (rule: SignedVaccineRule, reason: string) => void;
  /** Called for every rule that verified AND was fresh (post-accept). */
  onAccepted?: (rule: SignedVaccineRule) => void;
}

export interface VaccineIngestResult {
  accepted: boolean;
  reason?: string;
  rule: SignedVaccineRule;
}

/**
 * VaccineSubscriber — the daemon/agent-side consumer.
 *
 * `ingest()` is the single choke point every rule (whether arriving via
 * push callback or pull poll) passes through: verify signature → check
 * trusted-issuer set → check anti-replay sequence → accept into the store.
 * Nothing is ever "applied" without passing all three gates.
 */
export class VaccineSubscriber {
  readonly store: VaccineStore;
  private opts: VaccineSubscriberOptions;

  constructor(opts: VaccineSubscriberOptions) {
    this.opts = opts;
    this.store = opts.store ?? new VaccineStore();
  }

  /** Verify + anti-replay-check + (if valid) accept a single rule. */
  ingest(rule: SignedVaccineRule): VaccineIngestResult {
    const verification = verifyVaccineRule(rule, {
      trustedIssuerPublicKeys: this.opts.trustedIssuerPublicKeys,
    });
    if (!verification.valid) {
      const reason = verification.reason ?? verification.code ?? "invalid";
      this.opts.onRejected?.(rule, reason);
      return { accepted: false, reason, rule };
    }
    if (!this.store.isFreshSequence(rule)) {
      const reason = `replayed/stale sequence ${rule.body.sequence} (last seen ${this.store.lastSeenSequence(rule.issuerPublicKey)})`;
      this.opts.onRejected?.(rule, reason);
      return { accepted: false, reason, rule };
    }
    this.store.accept(rule);
    this.opts.onAccepted?.(rule);
    return { accepted: true, rule };
  }

  /** Bulk-ingest, e.g. after a `transport.pull()` catalog fetch. */
  ingestMany(rules: SignedVaccineRule[]): VaccineIngestResult[] {
    // Sort by sequence ascending so a batch pull always applies in order —
    // otherwise a higher-sequence rule processed first would make every
    // earlier (still-valid, still-unseen) rule look like a replay.
    const sorted = [...rules].sort((a, b) => a.body.sequence - b.body.sequence);
    return sorted.map((r) => this.ingest(r));
  }

  /** Pull-mode sync: fetch anything new from `transport` and ingest it. */
  async syncFrom(transport: VaccineTransport, issuerPublicKey: string): Promise<VaccineIngestResult[]> {
    const since = this.store.lastSeenSequence(issuerPublicKey);
    const fresh = await transport.pull(since);
    return this.ingestMany(fresh);
  }

  /** Register this subscriber to receive live pushes from a publisher. */
  attachTo(publisher: VaccinePublisher): () => void {
    return publisher.subscribe((rule) => {
      this.ingest(rule);
    });
  }
}

/** Convenience: mint a fresh ruleId when the caller doesn't want to choose one. */
export function newVaccineRuleId(prefix = "vaccine"): string {
  return `${prefix}-${newUuid()}`;
}
