/**
 * DM Pairing Policy
 *
 * Inspired by OpenClaw's `dmPolicy = "pairing"` model. When enabled, unknown
 * senders on a DM-capable channel receive a one-time pairing code instead of
 * being forwarded to the agent. An operator approves the code via:
 *
 *   lyrie pairing approve <channel> <code>
 *
 * Approved senders are added to a local allowlist and treated as known on
 * every subsequent message.
 *
 * Policies (per channel):
 *   - "open"     — anyone can DM (existing behavior, current default)
 *   - "pairing"  — unknown DMs receive a code, operator approves
 *   - "closed"   — DMs only from explicit `allowedUsers` lists
 *
 * This module is purely additive. If a channel does not set `dmPolicy`, it
 * behaves exactly as before. Existing `allowedUsers` lists are honored on top
 * of (not instead of) the pairing flow.
 *
 * Storage: simple JSON file under `~/.lyrie/pairing.json`. We avoid SQLite
 * here so the gateway has no native deps in v0.1.x.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";

import type { ChannelType, UnifiedMessage, UnifiedResponse } from "../common/types";

// ─── Types ──────────────────────────────────────────────────────────────────────

export type DmPolicy = "open" | "pairing" | "closed";

export interface PairingRecord {
  channel: ChannelType;
  senderId: string;
  /** Display name at the time of pairing */
  senderName?: string;
  /** Pairing code (unset once approved) */
  code?: string;
  /** Set when an operator approves the pairing */
  approvedAt?: string;
  /** When the pairing was first requested */
  requestedAt: string;
}

export interface PairingStore {
  pending: PairingRecord[];
  approved: PairingRecord[];
}

// ─── Storage ────────────────────────────────────────────────────────────────────

function defaultPath(): string {
  return join(homedir(), ".lyrie", "pairing.json");
}

function ensureDir(file: string) {
  const dir = dirname(file);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function loadStore(file: string): PairingStore {
  if (!existsSync(file)) return { pending: [], approved: [] };
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    return {
      pending: Array.isArray(data.pending) ? data.pending : [],
      approved: Array.isArray(data.approved) ? data.approved : [],
    };
  } catch {
    return { pending: [], approved: [] };
  }
}

function saveStore(file: string, store: PairingStore) {
  ensureDir(file);
  writeFileSync(file, JSON.stringify(store, null, 2), { mode: 0o600 });
}

// ─── Code Generation ────────────────────────────────────────────────────────────

/** Short, human-friendly pairing code (8 chars, A-Z 2-9 minus look-alikes). */
function generatePairingCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(8);
  let out = "";
  for (let i = 0; i < 8; i++) out += alphabet[bytes[i] % alphabet.length];
  return out.replace(/(.{4})(.{4})/, "$1-$2");
}

// ─── Manager ────────────────────────────────────────────────────────────────────

export interface DmPairingOptions {
  /** Path to the pairing JSON store. Defaults to ~/.lyrie/pairing.json */
  storePath?: string;
  /** Operator-facing message shown when an unknown sender is gated. */
  greeting?: (record: PairingRecord) => string;
}

export class DmPairingManager {
  private store: PairingStore;
  private path: string;
  private greeting: (record: PairingRecord) => string;

  constructor(opts: DmPairingOptions = {}) {
    this.path = opts.storePath ?? defaultPath();
    this.store = loadStore(this.path);
    this.greeting = opts.greeting ?? defaultGreeting;
  }

  /** Returns true if the sender is already approved for this channel. */
  isApproved(channel: ChannelType, senderId: string): boolean {
    return this.store.approved.some(
      (r) => r.channel === channel && r.senderId === senderId,
    );
  }

  /** Returns the existing pending record if any, or null. */
  pending(channel: ChannelType, senderId: string): PairingRecord | null {
    return (
      this.store.pending.find(
        (r) => r.channel === channel && r.senderId === senderId,
      ) ?? null
    );
  }

  /**
   * Idempotently produce/refresh a pairing record for an unknown sender and
   * return the operator-facing greeting (to relay back to the sender).
   */
  greet(message: UnifiedMessage): UnifiedResponse {
    const existing = this.pending(message.channel, message.senderId);
    if (existing) return { text: this.greeting(existing) };

    const record: PairingRecord = {
      channel: message.channel,
      senderId: message.senderId,
      senderName: message.senderName,
      code: generatePairingCode(),
      requestedAt: new Date().toISOString(),
    };
    this.store.pending.push(record);
    saveStore(this.path, this.store);

    // Surface to the operator's main channel via stderr (gateway picks this up
    // in logs; companion CLI tail-watches the file).
    console.warn(
      `[dm-pairing] new pairing request channel=${record.channel} ` +
        `sender=${record.senderId} (${record.senderName ?? "unknown"}) ` +
        `code=${record.code}`,
    );

    return { text: this.greeting(record) };
  }

  /** Approve a pending pairing by code. Used by `lyrie pairing approve`. */
  approve(channel: ChannelType, code: string): PairingRecord | null {
    const idx = this.store.pending.findIndex(
      (r) => r.channel === channel && r.code === code,
    );
    if (idx === -1) return null;
    const [record] = this.store.pending.splice(idx, 1);
    record.approvedAt = new Date().toISOString();
    delete record.code;
    this.store.approved.push(record);
    saveStore(this.path, this.store);
    return record;
  }

  /** Revoke a previously approved sender. */
  revoke(channel: ChannelType, senderId: string): boolean {
    const before = this.store.approved.length;
    this.store.approved = this.store.approved.filter(
      (r) => !(r.channel === channel && r.senderId === senderId),
    );
    if (this.store.approved.length === before) return false;
    saveStore(this.path, this.store);
    return true;
  }

  list(): PairingStore {
    // Return a deep copy so callers can't mutate our internal state
    return JSON.parse(JSON.stringify(this.store));
  }
}

// ─── Default greeting ───────────────────────────────────────────────────────────

function defaultGreeting(record: PairingRecord): string {
  const name = record.senderName ? `, ${record.senderName}` : "";
  return [
    `🛡️  Hi${name} — this is Lyrie.`,
    "",
    "Direct messages on this channel require pairing approval.",
    "Ask the operator to run:",
    "",
    `\`lyrie pairing approve ${record.channel} ${record.code}\``,
    "",
    "Once approved, you can chat normally.",
  ].join("\n");
}

// ─── Policy gate ────────────────────────────────────────────────────────────────

export interface PolicyContext {
  /** Per-channel resolved DM policy. Defaults to "open" for back-compat. */
  policy: DmPolicy;
  /** Optional explicit allowlist (senderId values) that bypass pairing. */
  allowedUsers?: string[];
  /** Optional chat-level allowlist (chatId values). */
  allowedChats?: string[];
}

/**
 * Decide whether a message should reach the engine. Returns either a response
 * to send back instead (gating message) or `null` to allow through.
 *
 * Pure function over its inputs — easy to unit test. The router calls this on
 * every inbound message and short-circuits when a response is returned.
 */
export function evaluateDmPolicy(
  message: UnifiedMessage,
  ctx: PolicyContext,
  manager: DmPairingManager,
): UnifiedResponse | null {
  // Closed: only explicit allowlist matches allowed
  if (ctx.policy === "closed") {
    if (ctx.allowedUsers?.includes(message.senderId)) return null;
    if (ctx.allowedChats?.includes(message.chatId)) return null;
    return {
      text:
        "🚫 This Lyrie deployment is locked down to its operator. " +
        "Your message was not delivered.",
    };
  }

  // Open: legacy behavior, allow everything (existing allowedUsers still
  // enforced at the channel level upstream — we don't change that).
  if (ctx.policy === "open") return null;

  // Pairing
  if (ctx.policy === "pairing") {
    if (ctx.allowedUsers?.includes(message.senderId)) return null;
    if (ctx.allowedChats?.includes(message.chatId)) return null;
    if (manager.isApproved(message.channel, message.senderId)) return null;
    return manager.greet(message);
  }

  // Unknown policy: fail closed but with a clear message (defensive)
  return {
    text:
      "⚠️ Unknown DM policy configured for this channel. " +
      "Ask the operator to set a valid policy (open|pairing|closed).",
  };
}

// ─── Singleton helper (optional) ────────────────────────────────────────────────

let _manager: DmPairingManager | null = null;
export function defaultPairingManager(): DmPairingManager {
  if (!_manager) _manager = new DmPairingManager();
  return _manager;
}
