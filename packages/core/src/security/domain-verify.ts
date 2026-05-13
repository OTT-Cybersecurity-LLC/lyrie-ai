import { createHash, createHmac, randomBytes } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const TXT_PREFIX = "_lyrie-verify.";
const TXT_VALUE_PREFIX = "lyrie-domain-verify=";
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const PROOF_VERSION = "v1";

export interface DomainVerifyResult {
  verified: boolean;
  domain: string;
  method: "dns-txt" | "allowlist" | "local-target" | "skip";
  reason?: string;
  verifiedAt?: number;
}

export interface ScanProof {
  version: typeof PROOF_VERSION;
  domain: string;
  verifiedAt: number;
  expiresAt: number;
  hmac: string;
}

// ─── Verification cache ─────────────────────────────────────────────────────

const verifiedCache = new Map<string, { expiresAt: number; result: DomainVerifyResult }>();

// ─── Secret resolution ──────────────────────────────────────────────────────

function resolveSecret(): string {
  const env = process.env.LYRIE_VERIFY_SECRET;
  if (env) return env;

  const configPath = join(homedir(), ".lyrie", "config.json");
  if (existsSync(configPath)) {
    try {
      const cfg = JSON.parse(readFileSync(configPath, "utf8"));
      if (typeof cfg.verifySecret === "string" && cfg.verifySecret.length > 0) {
        return cfg.verifySecret;
      }
    } catch { /* corrupt config */ }
  }

  return "lyrie-default-salt-change-me";
}

// ─── Token generation ───────────────────────────────────────────────────────

export function generateVerifyToken(domain: string, secret?: string): string {
  const s = secret ?? resolveSecret();
  return createHash("sha256").update(`${domain.toLowerCase()}:${s}`).digest("hex");
}

// ─── Local target detection ─────────────────────────────────────────────────

const PRIVATE_IP_RE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.|169\.254\.|::1|\[::1\]|fc00:|fd[0-9a-f]{2}:)/i;

export function isLocalTarget(target: string): boolean {
  if (!target) return false;
  if (target.startsWith(".") || target.startsWith("/") || target.startsWith("~")) return true;
  if (/^[a-zA-Z]:\\/.test(target)) return true; // Windows path

  try {
    const url = new URL(target.startsWith("http") ? target : `https://${target}`);
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]") return true;
    if (PRIVATE_IP_RE.test(host)) return true;
  } catch { /* not a URL */ }

  return false;
}

// ─── DNS TXT verification ───────────────────────────────────────────────────

export function extractDomain(target: string): string | null {
  try {
    const url = new URL(target.startsWith("http") ? target : `https://${target}`);
    return url.hostname.toLowerCase();
  } catch {
    return null;
  }
}

async function lookupTxtRecord(domain: string): Promise<string | null> {
  const fqdn = `${TXT_PREFIX}${domain}`;
  try {
    const records = await resolveTxt(fqdn);
    for (const txtArray of records) {
      const txt = txtArray.join("");
      if (txt.startsWith(TXT_VALUE_PREFIX)) {
        return txt.slice(TXT_VALUE_PREFIX.length).trim();
      }
    }
  } catch { /* NXDOMAIN or timeout */ }
  return null;
}

// ─── Allowlist ──────────────────────────────────────────────────────────────

function getAllowlist(): Set<string> {
  const env = process.env.LYRIE_VERIFIED_DOMAINS;
  if (!env) return new Set();
  return new Set(env.split(",").map((d) => d.trim().toLowerCase()).filter(Boolean));
}

// ─── Main verification function ─────────────────────────────────────────────

export async function verifyDomainOwnership(
  target: string,
  opts: { secret?: string; skipCache?: boolean } = {},
): Promise<DomainVerifyResult> {
  if (isLocalTarget(target)) {
    return { verified: true, domain: target, method: "local-target", verifiedAt: Date.now() };
  }

  const domain = extractDomain(target);
  if (!domain) {
    return { verified: false, domain: target, method: "dns-txt", reason: "Could not extract domain from target" };
  }

  // Check cache
  if (!opts.skipCache) {
    const cached = verifiedCache.get(domain);
    if (cached && cached.expiresAt > Date.now()) return cached.result;
  }

  // Check allowlist
  const allowlist = getAllowlist();
  if (allowlist.has(domain)) {
    const result: DomainVerifyResult = { verified: true, domain, method: "allowlist", verifiedAt: Date.now() };
    verifiedCache.set(domain, { expiresAt: Date.now() + CACHE_TTL_MS, result });
    return result;
  }

  // DNS TXT lookup
  const secret = opts.secret ?? resolveSecret();
  const expectedToken = generateVerifyToken(domain, secret);
  const actualToken = await lookupTxtRecord(domain);

  if (!actualToken) {
    const result: DomainVerifyResult = {
      verified: false,
      domain,
      method: "dns-txt",
      reason: `No TXT record found at ${TXT_PREFIX}${domain}. Add this DNS record:\n\n` +
        `  ${TXT_PREFIX}${domain}  TXT  "${TXT_VALUE_PREFIX}${expectedToken}"\n\n` +
        `Generate your token: lyrie verify --domain ${domain}`,
    };
    return result;
  }

  if (actualToken !== expectedToken) {
    const result: DomainVerifyResult = {
      verified: false,
      domain,
      method: "dns-txt",
      reason: `TXT record found but token mismatch. Expected:\n` +
        `  ${TXT_VALUE_PREFIX}${expectedToken}\n` +
        `Got:\n  ${TXT_VALUE_PREFIX}${actualToken}\n\n` +
        `Regenerate: lyrie verify --domain ${domain}`,
    };
    return result;
  }

  const result: DomainVerifyResult = { verified: true, domain, method: "dns-txt", verifiedAt: Date.now() };
  verifiedCache.set(domain, { expiresAt: Date.now() + CACHE_TTL_MS, result });
  return result;
}

// ─── Scan proof (threaded through the pipeline) ─────────────────────────────

export function createScanProof(domain: string, verifiedAt: number, secret?: string): ScanProof {
  const s = secret ?? resolveSecret();
  const expiresAt = verifiedAt + CACHE_TTL_MS;
  const payload = `${PROOF_VERSION}:${domain}:${verifiedAt}:${expiresAt}`;
  const hmac = createHmac("sha256", s).update(payload).digest("hex");
  return { version: PROOF_VERSION, domain, verifiedAt, expiresAt, hmac };
}

export function verifyScanProof(proof: ScanProof | undefined | null, secret?: string): boolean {
  if (!proof || proof.version !== PROOF_VERSION) return false;
  if (proof.expiresAt < Date.now()) return false;
  const s = secret ?? resolveSecret();
  const payload = `${proof.version}:${proof.domain}:${proof.verifiedAt}:${proof.expiresAt}`;
  const expected = createHmac("sha256", s).update(payload).digest("hex");
  if (expected.length !== proof.hmac.length) return false;
  const { timingSafeEqual } = require("node:crypto");
  return timingSafeEqual(Buffer.from(expected), Buffer.from(proof.hmac));
}

// ─── Verification instructions (user-facing) ────────────────────────────────

export function getVerifyInstructions(domain: string, secret?: string): string {
  const token = generateVerifyToken(domain, secret);
  return [
    `Domain Ownership Verification for: ${domain}`,
    ``,
    `Add this DNS TXT record to your domain:`,
    ``,
    `  Name:  ${TXT_PREFIX}${domain}`,
    `  Type:  TXT`,
    `  Value: ${TXT_VALUE_PREFIX}${token}`,
    ``,
    `Then verify:`,
    `  lyrie verify --check ${domain}`,
    ``,
    `Or via dig:`,
    `  dig TXT ${TXT_PREFIX}${domain}`,
  ].join("\n");
}

// ─── Gate function (one-liner for scan entry points) ────────────────────────

export async function requireDomainVerification(
  target: string,
  opts: { secret?: string; allowSkip?: boolean } = {},
): Promise<{ ok: true; proof: ScanProof } | { ok: false; error: string }> {
  const result = await verifyDomainOwnership(target, opts);
  if (result.verified) {
    const proof = createScanProof(result.domain, result.verifiedAt ?? Date.now(), opts.secret);
    return { ok: true, proof };
  }
  return { ok: false, error: result.reason ?? `Domain ${result.domain} not verified.` };
}

export function clearVerificationCache(): void {
  verifiedCache.clear();
}
