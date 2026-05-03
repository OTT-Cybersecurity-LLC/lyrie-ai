/**
 * crypto.ts — Internal helpers for ATP crypto + canonical encoding.
 *
 * Why a private module?
 *   The ATP wire format is a contract; implementation choices (Ed25519 via
 *   Node's built-in `crypto.sign`, JCS-style canonical JSON, raw 32-byte key
 *   exchange) are not. Centralising them here means callers never reach for
 *   `node:crypto` directly and we can swap libsodium / WebCrypto later
 *   without churning every primitive file.
 *
 * No external dependencies — everything in this file uses Node 20+ built-ins.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

import type { AtpKeyPair } from "./types";

// ─── UUIDs ───────────────────────────────────────────────────────────────────

/** Stable wrapper so call-sites don't import node:crypto directly. */
export function newUuid(): string {
  return randomUUID();
}

// ─── Hashing ─────────────────────────────────────────────────────────────────

/** SHA-256 of a UTF-8 string, hex-encoded (lowercase). */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** SHA-256 of raw bytes, hex-encoded. */
export function sha256BytesHex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// ─── Canonical JSON (subset of RFC 8785 / JCS) ───────────────────────────────

/**
 * Canonicalise a JSON-compatible value:
 *   - object keys sorted lexicographically (UTF-16 code-unit order, like JS sort)
 *   - no insignificant whitespace
 *   - undefined values dropped
 *   - functions / symbols rejected
 *
 * Numbers are serialised via `JSON.stringify`. ATP timestamps are integers,
 * which JSON.stringify renders deterministically; we forbid floats in the
 * wire format precisely so we never depend on float canonicalisation.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(stableClone(value));
}

function stableClone(v: unknown): unknown {
  if (v === null) return null;
  if (typeof v === "undefined") return undefined;
  if (typeof v === "function" || typeof v === "symbol" || typeof v === "bigint") {
    throw new TypeError(`ATP canonical JSON cannot encode ${typeof v}`);
  }
  if (Array.isArray(v)) return v.map(stableClone);
  if (typeof v === "object") {
    const out: Record<string, unknown> = {};
    const keys = Object.keys(v as Record<string, unknown>).sort();
    for (const k of keys) {
      const child = stableClone((v as Record<string, unknown>)[k]);
      if (typeof child === "undefined") continue;
      out[k] = child;
    }
    return out;
  }
  return v;
}

// ─── Ed25519 keys ────────────────────────────────────────────────────────────

/**
 * Generate a fresh Ed25519 key pair. Both halves are exposed as raw 32-byte
 * payloads, base64-standard encoded.
 *
 * Why raw + base64 (not PEM)?
 *   Cross-language friendliness. Python (PyNaCl), Go (crypto/ed25519), Rust
 *   (ed25519-dalek), and browser WebCrypto all speak raw 32-byte keys. PEM
 *   adds a parser dependency for no benefit at our scale.
 */
export function generateKeyPair(): AtpKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  // Export to DER (SubjectPublicKeyInfo / PKCS#8) and slice the raw 32 bytes.
  // Ed25519 SPKI = 12-byte ASN.1 prefix + 32 raw bytes.
  // Ed25519 PKCS#8 = 16-byte prefix + 32 raw bytes.
  const pubDer = publicKey.export({ format: "der", type: "spki" });
  const privDer = privateKey.export({ format: "der", type: "pkcs8" });

  const pubRaw = pubDer.subarray(pubDer.length - 32);
  const privRaw = privDer.subarray(privDer.length - 32);

  return {
    publicKey: Buffer.from(pubRaw).toString("base64"),
    privateKey: Buffer.from(privRaw).toString("base64"),
  };
}

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const ED25519_PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function publicKeyObjectFromBase64(b64: string) {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) throw new Error(`ATP: invalid Ed25519 public key length (${raw.length})`);
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function privateKeyObjectFromBase64(b64: string) {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) throw new Error(`ATP: invalid Ed25519 private key length (${raw.length})`);
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, raw]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

// ─── Sign / verify ───────────────────────────────────────────────────────────

/**
 * Sign the canonical JSON of `value` with `privateKey`.
 * Returns base64-standard signature (64 raw bytes → 88 chars).
 */
export function signCanonical(value: unknown, privateKeyB64: string): string {
  const message = Buffer.from(canonicalize(value), "utf8");
  const key = privateKeyObjectFromBase64(privateKeyB64);
  // Ed25519 in Node uses algorithm = null.
  const sig = nodeSign(null, message, key);
  return sig.toString("base64");
}

/**
 * Verify an Ed25519 signature over the canonical JSON of `value`.
 * Returns false on any decode error — never throws.
 */
export function verifyCanonical(
  value: unknown,
  publicKeyB64: string,
  signatureB64: string,
): boolean {
  try {
    const message = Buffer.from(canonicalize(value), "utf8");
    const key = publicKeyObjectFromBase64(publicKeyB64);
    const sig = Buffer.from(signatureB64, "base64");
    if (sig.length !== 64) return false;
    return nodeVerify(null, message, key, sig);
  } catch {
    return false;
  }
}

/** True iff `b64` decodes to exactly `expected` bytes. */
export function isBase64Bytes(b64: string, expected: number): boolean {
  try {
    return Buffer.from(b64, "base64").length === expected;
  } catch {
    return false;
  }
}
