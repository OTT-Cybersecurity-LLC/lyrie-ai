/**
 * revocation.test.ts — createRevocationList, isRevoked, addRevocation
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  createRevocationList,
  isRevoked,
  addRevocation,
} from "../src/revocation";
import { generateKeyPair } from "../src/crypto";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeIssuer() {
  const kp = generateKeyPair();
  return { issuerAgentId: "crl-issuer-001", keyPair: kp };
}

// ─── createRevocationList ─────────────────────────────────────────────────────

describe("createRevocationList", () => {
  test("creates an empty CRL with valid structure", () => {
    const issuer = makeIssuer();
    const crl = createRevocationList([], {
      privateKey: issuer.keyPair.privateKey,
      issuerAgentId: issuer.issuerAgentId,
    });

    expect(crl.issuer).toBe(issuer.issuerAgentId);
    expect(crl.entries).toHaveLength(0);
    expect(typeof crl.signature).toBe("string");
    expect(crl.signature.length).toBeGreaterThan(0);
    expect(new Date(crl.issuedAt).getTime()).not.toBeNaN();
  });

  test("creates a CRL with initial entries, each stamped with revokedAt", () => {
    const issuer = makeIssuer();
    const beforeCreate = Date.now();

    const crl = createRevocationList(
      [
        { certId: "cert-001", reason: "key_compromise", revokedBy: "admin" },
        { certId: "cert-002", reason: "agent_compromised", revokedBy: "admin" },
      ],
      { privateKey: issuer.keyPair.privateKey, issuerAgentId: issuer.issuerAgentId },
    );

    expect(crl.entries).toHaveLength(2);
    for (const entry of crl.entries) {
      const ts = new Date(entry.revokedAt).getTime();
      expect(ts).not.toBeNaN();
      expect(ts).toBeGreaterThanOrEqual(beforeCreate);
    }
  });

  test("defaults issuer to 'unknown' when not supplied", () => {
    const kp = generateKeyPair();
    const crl = createRevocationList([], { privateKey: kp.privateKey });
    expect(crl.issuer).toBe("unknown");
  });
});

// ─── isRevoked ────────────────────────────────────────────────────────────────

describe("isRevoked", () => {
  test("returns false for empty CRL", () => {
    const issuer = makeIssuer();
    const crl = createRevocationList([], {
      privateKey: issuer.keyPair.privateKey,
      issuerAgentId: issuer.issuerAgentId,
    });
    expect(isRevoked("any-cert-id", crl)).toBe(false);
  });

  test("returns true for a cert that is in the CRL", () => {
    const issuer = makeIssuer();
    const crl = createRevocationList(
      [{ certId: "target-cert", reason: "unspecified", revokedBy: "admin" }],
      { privateKey: issuer.keyPair.privateKey, issuerAgentId: issuer.issuerAgentId },
    );
    expect(isRevoked("target-cert", crl)).toBe(true);
  });

  test("returns false for a cert that is NOT in the CRL", () => {
    const issuer = makeIssuer();
    const crl = createRevocationList(
      [{ certId: "some-other-cert", reason: "expired", revokedBy: "admin" }],
      { privateKey: issuer.keyPair.privateKey, issuerAgentId: issuer.issuerAgentId },
    );
    expect(isRevoked("different-cert", crl)).toBe(false);
  });
});

// ─── addRevocation ────────────────────────────────────────────────────────────

describe("addRevocation", () => {
  test("appends an entry and does not mutate the original CRL", () => {
    const issuer = makeIssuer();
    const crl = createRevocationList([], {
      privateKey: issuer.keyPair.privateKey,
      issuerAgentId: issuer.issuerAgentId,
    });

    const updated = addRevocation(
      crl,
      { certId: "new-cert", reason: "scope_violation", revokedBy: "auditor" },
      { privateKey: issuer.keyPair.privateKey, issuerAgentId: issuer.issuerAgentId },
    );

    // Original unchanged.
    expect(crl.entries).toHaveLength(0);
    // Updated has the new entry.
    expect(updated.entries).toHaveLength(1);
    expect(updated.entries[0].certId).toBe("new-cert");
    expect(updated.entries[0].reason).toBe("scope_violation");
  });

  test("updated CRL signature is freshly generated (different from original)", () => {
    const issuer = makeIssuer();
    const crl = createRevocationList([], {
      privateKey: issuer.keyPair.privateKey,
      issuerAgentId: issuer.issuerAgentId,
    });

    const updated = addRevocation(
      crl,
      { certId: "cert-X", reason: "superseded", revokedBy: "admin" },
      { privateKey: issuer.keyPair.privateKey, issuerAgentId: issuer.issuerAgentId },
    );

    // Signatures must differ because the signed payload (entries) changed.
    expect(updated.signature).not.toBe(crl.signature);
  });

  test("chains multiple revocations correctly", () => {
    const issuer = makeIssuer();
    let crl = createRevocationList([], {
      privateKey: issuer.keyPair.privateKey,
      issuerAgentId: issuer.issuerAgentId,
    });

    crl = addRevocation(
      crl,
      { certId: "c1", reason: "key_compromise", revokedBy: "admin" },
      { privateKey: issuer.keyPair.privateKey },
    );
    crl = addRevocation(
      crl,
      { certId: "c2", reason: "agent_compromised", revokedBy: "admin" },
      { privateKey: issuer.keyPair.privateKey },
    );

    expect(crl.entries).toHaveLength(2);
    expect(isRevoked("c1", crl)).toBe(true);
    expect(isRevoked("c2", crl)).toBe(true);
    expect(isRevoked("c3", crl)).toBe(false);
  });

  test("all RevocationReason values are accepted", () => {
    const issuer = makeIssuer();
    const reasons = [
      "key_compromise",
      "agent_compromised",
      "scope_violation",
      "expired",
      "superseded",
      "unspecified",
    ] as const;

    let crl = createRevocationList([], {
      privateKey: issuer.keyPair.privateKey,
      issuerAgentId: issuer.issuerAgentId,
    });

    for (const reason of reasons) {
      crl = addRevocation(
        crl,
        { certId: `cert-${reason}`, reason, revokedBy: "tester" },
        { privateKey: issuer.keyPair.privateKey },
      );
    }

    expect(crl.entries).toHaveLength(reasons.length);
  });
});
