/**
 * zk-attestation.test.ts — Threshold Trust Attestation (commitment-based
 * privacy-preserving trust-score claims).
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { generateKeyPair } from "../src/crypto";
import {
  commitFindings,
  verifyCommitment,
  createTrustScoreAttestation,
  verifyTrustScoreAttestation,
} from "../src/zk-attestation";

const SAMPLE_FINDINGS = [
  { id: "f1", category: "sql-injection", severity: "critical", file: "src/db.ts" },
  { id: "f2", category: "xss", severity: "medium", file: "src/render.ts" },
];

function makeAttester() {
  const kp = generateKeyPair();
  return { attesterId: "lyrie-hack-pipeline", ...kp };
}

// ─── Commitment primitives ────────────────────────────────────────────────────

describe("commitFindings / verifyCommitment", () => {
  test("same findings + same salt produce the same commitment", () => {
    const { commitment: c1, salt } = commitFindings(SAMPLE_FINDINGS, "fixed-salt");
    const { commitment: c2 } = commitFindings(SAMPLE_FINDINGS, salt);
    expect(c1).toBe(c2);
  });

  test("different salts produce different commitments for identical findings (hiding property)", () => {
    const { commitment: c1 } = commitFindings(SAMPLE_FINDINGS);
    const { commitment: c2 } = commitFindings(SAMPLE_FINDINGS);
    expect(c1).not.toBe(c2);
  });

  test("verifyCommitment succeeds for the correct (findings, salt) pair", () => {
    const { commitment, salt } = commitFindings(SAMPLE_FINDINGS);
    expect(verifyCommitment(commitment, SAMPLE_FINDINGS, salt)).toBe(true);
  });

  test("verifyCommitment fails if findings are altered", () => {
    const { commitment, salt } = commitFindings(SAMPLE_FINDINGS);
    const altered = [...SAMPLE_FINDINGS, { id: "f3", category: "ssrf", severity: "high", file: "x.ts" }];
    expect(verifyCommitment(commitment, altered, salt)).toBe(false);
  });

  test("verifyCommitment fails with wrong salt", () => {
    const { commitment } = commitFindings(SAMPLE_FINDINGS, "salt-a");
    expect(verifyCommitment(commitment, SAMPLE_FINDINGS, "salt-b")).toBe(false);
  });
});

// ─── createTrustScoreAttestation ──────────────────────────────────────────────

describe("createTrustScoreAttestation", () => {
  test("issues a valid attestation when actualScore meets threshold", () => {
    const attester = makeAttester();
    const result = createTrustScoreAttestation({
      findings: SAMPLE_FINDINGS,
      actualScore: 82,
      threshold: 70,
      subject: "github.com/acme/widget@deadbeef",
      attesterId: attester.attesterId,
      attesterPrivateKey: attester.privateKey,
      attesterPublicKey: attester.publicKey,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.attestation.body.threshold).toBe(70);
      expect(result.attestation.body.meetsThreshold).toBe(true);
      // Must NOT leak the actual score or findings anywhere in the serialized attestation.
      const serialized = JSON.stringify(result.attestation);
      expect(serialized).not.toContain("82");
      expect(serialized).not.toContain("sql-injection");
      expect(serialized).not.toContain("src/db.ts");
    }
  });

  test("refuses to issue an attestation when actualScore is below threshold (cannot sign a false claim)", () => {
    const attester = makeAttester();
    const result = createTrustScoreAttestation({
      findings: SAMPLE_FINDINGS,
      actualScore: 40,
      threshold: 70,
      subject: "github.com/acme/widget@deadbeef",
      attesterId: attester.attesterId,
      attesterPrivateKey: attester.privateKey,
      attesterPublicKey: attester.publicKey,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/does not meet threshold/);
    }
  });

  test("rejects out-of-range threshold", () => {
    const attester = makeAttester();
    const result = createTrustScoreAttestation({
      findings: SAMPLE_FINDINGS,
      actualScore: 95,
      threshold: 150,
      subject: "s",
      attesterId: attester.attesterId,
      attesterPrivateKey: attester.privateKey,
      attesterPublicKey: attester.publicKey,
    });
    expect(result.ok).toBe(false);
  });
});

// ─── verifyTrustScoreAttestation ──────────────────────────────────────────────

describe("verifyTrustScoreAttestation", () => {
  function issue(overrides: Partial<Parameters<typeof createTrustScoreAttestation>[0]> = {}) {
    const attester = makeAttester();
    const result = createTrustScoreAttestation({
      findings: SAMPLE_FINDINGS,
      actualScore: 85,
      threshold: 70,
      subject: "domain:example.com",
      attesterId: attester.attesterId,
      attesterPrivateKey: attester.privateKey,
      attesterPublicKey: attester.publicKey,
      ...overrides,
    });
    if (!result.ok) throw new Error("test setup failed: " + result.reason);
    return { attester, attestation: result.attestation };
  }

  test("valid attestation from a trusted attester verifies and echoes the claim only", () => {
    const { attester, attestation } = issue();
    const verification = verifyTrustScoreAttestation(attestation, {
      trustedAttesterPublicKeys: [attester.publicKey],
    });
    expect(verification.valid).toBe(true);
    expect(verification.claim).toEqual({ subject: "domain:example.com", threshold: 70 });
  });

  test("rejects attestation from an untrusted attester key", () => {
    const { attestation } = issue();
    const otherKp = generateKeyPair();
    const verification = verifyTrustScoreAttestation(attestation, {
      trustedAttesterPublicKeys: [otherKp.publicKey],
    });
    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  test("refuses to verify with an empty trusted-attester list", () => {
    const { attestation } = issue();
    const verification = verifyTrustScoreAttestation(attestation, { trustedAttesterPublicKeys: [] });
    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  test("tampering with the claimed threshold invalidates the signature", () => {
    const { attester, attestation } = issue();
    const tampered = { ...attestation, body: { ...attestation.body, threshold: 20 } };
    const verification = verifyTrustScoreAttestation(tampered, {
      trustedAttesterPublicKeys: [attester.publicKey],
    });
    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("enforces a verifier-side minimum threshold requirement", () => {
    const { attester, attestation } = issue({ threshold: 70 });
    const tooStrict = verifyTrustScoreAttestation(attestation, {
      trustedAttesterPublicKeys: [attester.publicKey],
      minimumThreshold: 90,
    });
    expect(tooStrict.valid).toBe(false);
    expect(tooStrict.code).toBe("ATP_SCOPE_INVALID");

    const satisfied = verifyTrustScoreAttestation(attestation, {
      trustedAttesterPublicKeys: [attester.publicKey],
      minimumThreshold: 50,
    });
    expect(satisfied.valid).toBe(true);
  });

  test("expired attestation is rejected", () => {
    const { attester, attestation } = issue({ expiresAt: Date.now() - 1000 });
    const verification = verifyTrustScoreAttestation(attestation, {
      trustedAttesterPublicKeys: [attester.publicKey],
    });
    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("ATP_CERT_EXPIRED");
  });

  test("verification never requires or accepts the original findings", () => {
    const { attester, attestation } = issue();
    // Sanity: verifyTrustScoreAttestation's signature takes only (attestation, opts) —
    // there is no parameter through which findings could even be passed.
    const verification = verifyTrustScoreAttestation(attestation, {
      trustedAttesterPublicKeys: [attester.publicKey],
    });
    expect(verification.valid).toBe(true);
    expect(JSON.stringify(verification)).not.toContain("sql-injection");
  });
});
