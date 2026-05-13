import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "node:crypto";

const VERSION = 0x01;
const NONCE_BYTES = 24;
const KEY_BYTES = 32;
const PREFIX = "enc:v1:";

export class MemoryEncryptionError extends Error {
  readonly code: string;
  constructor(message: string, code: string = "MEM_ENCRYPT_ERR") {
    super(message);
    this.name = "MemoryEncryptionError";
    this.code = code;
  }
}

export interface MemoryEncryptionOptions {
  /** 32-byte key, base64 encoded. */
  keyBase64: string;
  /** Optional associated-data prefix added to every ciphertext (use for namespacing). */
  associatedData?: Uint8Array;
}

/**
 * AEAD wrapper for MemoryCore. Stateless and reusable across a process.
 */
export class MemoryEncryption {
  private readonly key: Uint8Array;
  private readonly aad?: Uint8Array;

  constructor(opts: MemoryEncryptionOptions) {
    const raw = decodeBase64(opts.keyBase64);
    if (raw.length !== KEY_BYTES) {
      throw new MemoryEncryptionError(
        `MemoryEncryption: key must be exactly ${KEY_BYTES} bytes (got ${raw.length}). Generate a key with MemoryEncryption.generateKey().`,
        "INVALID_KEY",
      );
    }
    this.key = raw;
    this.aad = opts.associatedData;
  }

  /** Generate a fresh 32-byte key as base64 — store it in `LYRIE_MEMORY_KEY`. */
  static generateKey(): string {
    return Buffer.from(randomBytes(KEY_BYTES)).toString("base64");
  }

  /** Returns true if the supplied string looks like a Lyrie-encrypted blob. */
  static isEncrypted(text: string | undefined | null): boolean {
    return typeof text === "string" && text.startsWith(PREFIX);
  }

  /**
   * Encrypt a UTF-8 string. Returns the prefixed `enc:v1:<base64>` form.
   * Pass-through if the input is already encrypted or empty.
   */
  encrypt(plaintext: string): string {
    if (!plaintext) return plaintext;
    if (MemoryEncryption.isEncrypted(plaintext)) return plaintext;

    const nonce = randomBytes(NONCE_BYTES);
    const cipher = xchacha20poly1305(this.key, nonce, this.aad);
    const ct = cipher.encrypt(new TextEncoder().encode(plaintext));

    const payload = new Uint8Array(1 + nonce.length + ct.length);
    payload[0] = VERSION;
    payload.set(nonce, 1);
    payload.set(ct, 1 + nonce.length);
    return PREFIX + Buffer.from(payload).toString("base64");
  }

  /**
   * Decrypt a `enc:v1:<base64>` string. Pass-through if the input is not
   * recognised as ciphertext (so callers can safely run cleartext through
   * `decrypt()` without branching).
   */
  decrypt(value: string | undefined | null): string {
    if (!value) return value ?? "";
    if (!MemoryEncryption.isEncrypted(value)) return value;
    const raw = decodeBase64(value.slice(PREFIX.length));
    if (raw.length < 1 + NONCE_BYTES + 16) {
      throw new MemoryEncryptionError("ciphertext too short", "MALFORMED");
    }
    if (raw[0] !== VERSION) {
      throw new MemoryEncryptionError(
        `unsupported ciphertext version: 0x${raw[0].toString(16)}`,
        "VERSION_MISMATCH",
      );
    }
    const nonce = raw.slice(1, 1 + NONCE_BYTES);
    const ct = raw.slice(1 + NONCE_BYTES);
    const cipher = xchacha20poly1305(this.key, nonce, this.aad);
    let pt: Uint8Array;
    try {
      pt = cipher.decrypt(ct);
    } catch (err: any) {
      throw new MemoryEncryptionError(
        `decrypt failed (wrong key, tampered, or AAD mismatch): ${err.message ?? err}`,
        "AUTH_FAIL",
      );
    }
    return new TextDecoder().decode(pt);
  }
}

function decodeBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}
