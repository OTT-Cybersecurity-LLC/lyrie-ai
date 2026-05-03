/**
 * aic.ts — Agent Identity Certificate.
 *
 * The AIC is the first ATP primitive: a self-signed Ed25519 certificate that
 * binds an agent instance to:
 *   - a model identity (and optional weight hash)
 *   - a system-prompt hash
 *   - an authorisation scope (SDL)
 *   - an operator (human accountability anchor)
 *   - a validity window
 *   - optionally, a parent certificate (for sub-agents)
 *
 * Possession of the matching private key IS the agent. The certificate is
 * cryptographically what the agent presents to any tool, peer, or audit log.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  canonicalize,
  generateKeyPair,
  isBase64Bytes,
  newUuid,
  sha256Hex,
  signCanonical,
  verifyCanonical,
} from "./crypto";
import type {
  AgentIdentityCertificate,
  AtpKeyPair,
  CertId,
  ScopeDeclaration,
  VerificationResult,
} from "./types";
import { ATP_VERSION } from "./types";
import { validateScope } from "./scope";

// ─── Issuance ────────────────────────────────────────────────────────────────

export interface IssueAicInput {
  modelId: string;
  modelHash?: string;
  systemPromptHash: string;
  scope: ScopeDeclaration;
  operatorId: string;
  /** Validity window length in ms. Default 24h. */
  ttlMs?: number;
  /** Override `issuedAt` (Unix ms) for testability. */
  issuedAt?: number;
  /** If present, this AIC is a sub-agent certificate. */
  parentCertId?: CertId;
  /** Pre-existing key pair (e.g. when the agent persists keys). Generated if absent. */
  keyPair?: AtpKeyPair;
  /** Pre-assigned agentId (UUID). Generated if absent. */
  agentId?: string;
}

export interface IssueAicResult {
  cert: AgentIdentityCertificate;
  certId: CertId;
  keyPair: AtpKeyPair;
}

/**
 * Issue (self-sign) a new Agent Identity Certificate. Generates a fresh
 * Ed25519 key pair unless one is provided. Returns the cert, its stable
 * CertId (SHA-256 over canonical signed form), and the key pair.
 *
 * Caller is responsible for storing the private key securely. ATP itself
 * is key-storage-agnostic.
 */
export function issueAic(input: IssueAicInput): IssueAicResult {
  const scopeCheck = validateScope(input.scope);
  if (!scopeCheck.valid) {
    throw new Error(`ATP: cannot issue AIC with invalid scope: ${scopeCheck.reason}`);
  }
  const keyPair = input.keyPair ?? generateKeyPair();
  const issuedAt = input.issuedAt ?? Date.now();
  const ttl = input.ttlMs ?? 24 * 60 * 60 * 1000;

  const unsigned: Omit<AgentIdentityCertificate, "signature"> = {
    version: ATP_VERSION,
    agentId: input.agentId ?? newUuid(),
    modelId: input.modelId,
    modelHash: input.modelHash,
    systemPromptHash: input.systemPromptHash,
    scope: input.scope,
    operatorId: input.operatorId,
    issuedAt,
    expiresAt: issuedAt + ttl,
    publicKey: keyPair.publicKey,
    parentCertId: input.parentCertId,
  };

  const signature = signCanonical(unsigned, keyPair.privateKey);
  const cert: AgentIdentityCertificate = { ...unsigned, signature };
  return { cert, certId: certIdOf(cert), keyPair };
}

// ─── Identifier ──────────────────────────────────────────────────────────────

/**
 * Stable AIC identifier — SHA-256 (hex) over the canonical signed form.
 * Two equal certs always produce the same CertId; any mutation changes it.
 */
export function certIdOf(cert: AgentIdentityCertificate): CertId {
  return sha256Hex(canonicalize(cert));
}

// ─── Verification ────────────────────────────────────────────────────────────

export interface VerifyAicOptions {
  /** Wall-clock used for expiry checks. Default `Date.now()`. */
  now?: number;
  /** Optional revocation check — returns true to mark a CertId as revoked. */
  isRevoked?: (certId: CertId) => boolean;
  /** Skip the expiry check. Default false. */
  ignoreExpiry?: boolean;
}

/**
 * Verify an Agent Identity Certificate end-to-end:
 *   1. Structural well-formedness (version, types, key/sig lengths).
 *   2. Embedded scope validates.
 *   3. Self-signature is valid.
 *   4. Currently within validity window (unless `ignoreExpiry`).
 *   5. Not in the revocation set, if one is provided.
 */
export function verifyAic(
  cert: AgentIdentityCertificate,
  opts: VerifyAicOptions = {},
): VerificationResult {
  if (!cert || typeof cert !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "cert must be object" };
  }
  if (cert.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  for (const k of ["agentId", "modelId", "systemPromptHash", "operatorId", "publicKey", "signature"] as const) {
    if (typeof cert[k] !== "string" || cert[k].length === 0) {
      return { valid: false, code: "ATP_MALFORMED", reason: `${k} must be non-empty string` };
    }
  }
  if (typeof cert.issuedAt !== "number" || typeof cert.expiresAt !== "number") {
    return { valid: false, code: "ATP_MALFORMED", reason: "issuedAt / expiresAt must be numbers" };
  }
  if (cert.expiresAt <= cert.issuedAt) {
    return { valid: false, code: "ATP_MALFORMED", reason: "expiresAt must be > issuedAt" };
  }
  if (!isBase64Bytes(cert.publicKey, 32)) {
    return { valid: false, code: "ATP_PUBLIC_KEY_INVALID", reason: "publicKey not 32 raw bytes" };
  }
  if (!isBase64Bytes(cert.signature, 64)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "signature not 64 raw bytes" };
  }

  const scopeCheck = validateScope(cert.scope);
  if (!scopeCheck.valid) return scopeCheck;

  // Re-build the unsigned form and verify.
  const { signature, ...unsigned } = cert;
  if (!verifyCanonical(unsigned, cert.publicKey, signature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "self-signature did not verify" };
  }

  if (!opts.ignoreExpiry) {
    const now = opts.now ?? Date.now();
    if (now < cert.issuedAt) {
      return { valid: false, code: "ATP_CERT_NOT_YET_VALID", reason: `now (${now}) < issuedAt (${cert.issuedAt})` };
    }
    if (now > cert.expiresAt) {
      return { valid: false, code: "ATP_CERT_EXPIRED", reason: `now (${now}) > expiresAt (${cert.expiresAt})` };
    }
  }

  if (opts.isRevoked && opts.isRevoked(certIdOf(cert))) {
    return { valid: false, code: "ATP_CERT_REVOKED", reason: "cert is revoked" };
  }

  return { valid: true };
}

// ─── Revocation registry (in-memory reference impl) ──────────────────────────

/**
 * RevocationRegistry — minimal in-memory revocation list.
 *
 * Production deployments will plug a persistent store (DB, distributed log)
 * behind the same interface. The reference implementation is enough to
 * exercise the verifier and to back unit tests.
 */
export class RevocationRegistry {
  private readonly revoked = new Set<CertId>();

  revoke(certId: CertId): void {
    this.revoked.add(certId);
  }

  unrevoke(certId: CertId): void {
    this.revoked.delete(certId);
  }

  isRevoked = (certId: CertId): boolean => {
    return this.revoked.has(certId);
  };

  list(): CertId[] {
    return Array.from(this.revoked);
  }
}
