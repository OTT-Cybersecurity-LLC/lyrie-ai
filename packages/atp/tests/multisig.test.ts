/**
 * multisig.test.ts — createMultiSigRequest, addSignature, isAuthorized
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  createMultiSigRequest,
  addSignature,
  isAuthorized,
} from "../src/multisig";
import { generateKeyPair } from "../src/crypto";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const PAYLOAD = { action: "deploy_contract", target: "prod-cluster", version: "3.1.4" };

function makeSigners(n: number) {
  return Array.from({ length: n }, (_, i) => ({
    id: `signer-${String(i + 1).padStart(3, "0")}`,
    keyPair: generateKeyPair(),
  }));
}

// ─── createMultiSigRequest ────────────────────────────────────────────────────

describe("createMultiSigRequest", () => {
  test("creates a request with no signatures", () => {
    const signers = makeSigners(3);
    const req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      2,
    );

    expect(typeof req.id).toBe("string");
    expect(req.id.length).toBeGreaterThan(0);
    expect(req.payload).toEqual(PAYLOAD);
    expect(req.requiredSigners).toBe(2);
    expect(req.signers).toHaveLength(3);
    expect(req.signatures).toHaveLength(0);
    expect(new Date(req.createdAt).getTime()).not.toBeNaN();
  });

  test("deduplicates signer IDs", () => {
    const req = createMultiSigRequest(PAYLOAD, ["alice", "alice", "bob"], 1);
    expect(req.signers).toEqual(["alice", "bob"]);
  });

  test("throws if requiredSigners > signers.length", () => {
    expect(() => createMultiSigRequest(PAYLOAD, ["alice", "bob"], 3)).toThrow(
      /requiredSigners .* exceeds signers count/,
    );
  });

  test("throws if requiredSigners < 1", () => {
    expect(() => createMultiSigRequest(PAYLOAD, ["alice"], 0)).toThrow(
      /requiredSigners must be >= 1/,
    );
  });

  test("throws if signers list is empty", () => {
    expect(() => createMultiSigRequest(PAYLOAD, [], 1)).toThrow(/empty/);
  });

  test("1-of-1 is valid", () => {
    const [signer] = makeSigners(1);
    const req = createMultiSigRequest(PAYLOAD, [signer.id], 1);
    expect(req.requiredSigners).toBe(1);
  });
});

// ─── addSignature ─────────────────────────────────────────────────────────────

describe("addSignature", () => {
  test("adds a signature without mutating the original request", () => {
    const [s1] = makeSigners(3);
    const req = createMultiSigRequest(PAYLOAD, makeSigners(3).map((s) => s.id), 2);
    // Re-create with actual signer ids
    const signers = makeSigners(3);
    const req2 = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      2,
    );

    const updated = addSignature(req2, signers[0].id, signers[0].keyPair);

    // Original untouched.
    expect(req2.signatures).toHaveLength(0);
    // Updated has 1 sig.
    expect(updated.signatures).toHaveLength(1);
    expect(updated.signatures[0].signerId).toBe(signers[0].id);
    expect(updated.signatures[0].signature.length).toBeGreaterThan(0);
    expect(new Date(updated.signatures[0].signedAt).getTime()).not.toBeNaN();
  });

  test("replaces an existing signature from the same signer", () => {
    const [signer] = makeSigners(1);
    const req = createMultiSigRequest(PAYLOAD, [signer.id], 1);

    const first = addSignature(req, signer.id, signer.keyPair);
    const second = addSignature(first, signer.id, signer.keyPair);

    // Should still be 1 entry.
    expect(second.signatures).toHaveLength(1);
  });

  test("throws if signerId not in authorized list", () => {
    const [authorized] = makeSigners(1);
    const req = createMultiSigRequest(PAYLOAD, [authorized.id], 1);
    const impostor = generateKeyPair();

    expect(() => addSignature(req, "impostor-999", impostor)).toThrow(
      /not in the authorized signers/,
    );
  });
});

// ─── isAuthorized ─────────────────────────────────────────────────────────────

describe("isAuthorized", () => {
  test("authorized when enough valid sigs collected (2-of-3)", () => {
    const signers = makeSigners(3);
    let req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      2,
    );

    req = addSignature(req, signers[0].id, signers[0].keyPair);
    req = addSignature(req, signers[1].id, signers[1].keyPair);

    const pubKeys = new Map(signers.map((s) => [s.id, s.keyPair.publicKey]));
    const result = isAuthorized(req, pubKeys);

    expect(result.authorized).toBe(true);
    expect(result.signaturesCollected).toBe(2);
    expect(result.required).toBe(2);
  });

  test("not authorized when fewer sigs than required", () => {
    const signers = makeSigners(3);
    let req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      2,
    );
    req = addSignature(req, signers[0].id, signers[0].keyPair);

    const pubKeys = new Map(signers.map((s) => [s.id, s.keyPair.publicKey]));
    const result = isAuthorized(req, pubKeys);

    expect(result.authorized).toBe(false);
    expect(result.signaturesCollected).toBe(1);
    expect(result.required).toBe(2);
  });

  test("not authorized when no signatures", () => {
    const signers = makeSigners(2);
    const req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      1,
    );

    const pubKeys = new Map(signers.map((s) => [s.id, s.keyPair.publicKey]));
    const result = isAuthorized(req, pubKeys);

    expect(result.authorized).toBe(false);
    expect(result.signaturesCollected).toBe(0);
  });

  test("rejects signature verified against wrong public key", () => {
    const signers = makeSigners(2);
    let req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      2,
    );
    req = addSignature(req, signers[0].id, signers[0].keyPair);
    req = addSignature(req, signers[1].id, signers[1].keyPair);

    // Supply wrong keys (swapped).
    const wrongKeys = new Map([
      [signers[0].id, signers[1].keyPair.publicKey], // swapped
      [signers[1].id, signers[0].keyPair.publicKey], // swapped
    ]);

    const result = isAuthorized(req, wrongKeys);
    expect(result.authorized).toBe(false);
    expect(result.signaturesCollected).toBe(0);
  });

  test("rejects signer not in pubKey map (sig not counted)", () => {
    const signers = makeSigners(2);
    let req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      2,
    );
    req = addSignature(req, signers[0].id, signers[0].keyPair);
    req = addSignature(req, signers[1].id, signers[1].keyPair);

    // Only supply one public key.
    const partialKeys = new Map([[signers[0].id, signers[0].keyPair.publicKey]]);
    const result = isAuthorized(req, partialKeys);

    expect(result.authorized).toBe(false);
    expect(result.signaturesCollected).toBe(1);
  });

  test("3-of-3 all sign — authorized", () => {
    const signers = makeSigners(3);
    let req = createMultiSigRequest(
      PAYLOAD,
      signers.map((s) => s.id),
      3,
    );
    for (const s of signers) {
      req = addSignature(req, s.id, s.keyPair);
    }

    const pubKeys = new Map(signers.map((s) => [s.id, s.keyPair.publicKey]));
    const result = isAuthorized(req, pubKeys);

    expect(result.authorized).toBe(true);
    expect(result.signaturesCollected).toBe(3);
  });
});
