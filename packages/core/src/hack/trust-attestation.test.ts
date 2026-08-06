/**
 * Lyrie Hack — Trust Attestation integration tests.
 *
 * Covers the wiring between `@lyrie/atp`'s Threshold Trust Attestation (TTA)
 * primitives and Lyrie Hack's `HackReport` / `TrustScoreBreakdown`.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, expect, it } from "bun:test";
import { generateKeyPair, issueAic, makeScope } from "@lyrie/atp";
import {
  attestTrustThreshold,
  revealTrustCommitment,
  verifyTrustAttestation,
} from "./trust-attestation";
import { computeTrustScore } from "./trust-score";
import { REPORT_ENGINE_VERSION, type HackReport, type Severity } from "./report-engine";

function emptyCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function baseReport(over: Partial<HackReport> = {}): HackReport {
  return {
    target: "/tmp/x",
    runId: "hack-test",
    mode: "standard",
    startedAt: "2026-07-25T00:00:00.000Z",
    finishedAt: "2026-07-25T00:00:01.000Z",
    durationMs: 1000,
    threatMatches: [],
    validatedFindings: [],
    secretFindings: [],
    remediations: [],
    counts: emptyCounts(),
    totalFindings: 0,
    aavRan: false,
    selfScanRan: false,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
    reporterVersion: REPORT_ENGINE_VERSION,
    ...over,
  };
}

function validatedFinding(severity: Severity, confirmed = true) {
  return {
    finding: {
      id: `f-${severity}-${Math.random()}`,
      title: `${severity} test finding`,
      severity,
      description: "test",
      category: "other" as const,
      evidence: "",
    },
    confirmed,
    stages: [],
    confidence: confirmed ? 0.9 : 0.2,
    signature: "Lyrie.ai by OTT Cybersecurity LLC" as const,
  };
}

function secretFinding(severity: Severity) {
  return {
    id: `s-${severity}-${Math.random()}`,
    type: "generic-high-entropy" as const,
    severity,
    file: "config.js",
    line: 1,
    redactedSample: "AAAA***ZZ",
    length: 20,
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC" as const,
  };
}

/** Build a self-signed AIC + key pair for use as the attester. */
function makeAttester(agentId?: string) {
  const { cert, keyPair } = issueAic({
    modelId: "lyrie-hack-pipeline",
    systemPromptHash: "0".repeat(64),
    scope: makeScope({ allowedTools: ["*"], allowedDomains: ["*"], maxSubAgentDepth: 0 }),
    operatorId: "ott-cybersecurity",
    agentId,
  });
  return { cert, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

describe("attestTrustThreshold", () => {
  it("succeeds and verifies correctly when the report clears the threshold", () => {
    const attester = makeAttester();
    const report = baseReport({
      target: "clean-repo",
      validatedFindings: [validatedFinding("low")],
    });
    const breakdown = computeTrustScore(report);
    expect(breakdown.score).toBeGreaterThanOrEqual(70);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 70,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.attestation.attesterPublicKey).toBe(attester.cert.publicKey);
    expect(result.attestation.body.threshold).toBe(70);
    expect(result.attestation.body.subject).toBe("clean-repo");
    // The output must never contain the actual score or any finding data —
    // only the fixed set of body keys the ATP primitive defines.
    expect(Object.keys(result.attestation.body).sort()).toEqual(
      ["expiresAt", "findingsCommitment", "issuedAt", "meetsThreshold", "metadata", "subject", "threshold"]
        .filter((k) => k in result.attestation.body)
        .sort(),
    );
    expect(JSON.stringify(result.attestation)).not.toContain("\"low\"");
    expect((result.attestation.body as Record<string, unknown>).actualScore).toBeUndefined();
    expect((result.attestation.body as Record<string, unknown>).score).toBeUndefined();

    const verification = verifyTrustAttestation(result.attestation, attester.publicKey);
    expect(verification.valid).toBe(true);
    expect(verification.claim).toEqual({ subject: "clean-repo", threshold: 70 });
  });

  it("rejects attesting a report that does NOT clear the threshold (never issues a false claim)", () => {
    const attester = makeAttester();
    const report = baseReport({
      target: "vulnerable-repo",
      validatedFindings: [validatedFinding("critical"), validatedFinding("critical")],
    });
    const breakdown = computeTrustScore(report);
    expect(breakdown.score).toBeLessThan(70);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 70,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });

    // THIS is the test that proves false-claim generation is blocked:
    // score (50) < threshold (70) must never produce a signed attestation.
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain("does not meet threshold");
    expect(result.reason).toContain("vulnerable-repo");
  });

  it("verification fails if a wrong public key is used", () => {
    const attester = makeAttester();
    const impostor = makeAttester();
    const report = baseReport({ target: "clean-repo-2" });
    const breakdown = computeTrustScore(report);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 90,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const verification = verifyTrustAttestation(result.attestation, impostor.publicKey);
    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("ATP_PUBLIC_KEY_INVALID");
  });

  it("verification fails if the signed body is tampered with (wrong key rejects tampered claims too)", () => {
    const attester = makeAttester();
    const report = baseReport({ target: "clean-repo-3" });
    const breakdown = computeTrustScore(report);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 90,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const tampered = {
      ...result.attestation,
      body: { ...result.attestation.body, threshold: 10 },
    };
    const verification = verifyTrustAttestation(tampered, attester.publicKey);
    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("ATP_SIGNATURE_INVALID");
  });
});

describe("revealTrustCommitment", () => {
  it("validates a matching finding set against the published commitment", () => {
    const attester = makeAttester();
    const report = baseReport({
      target: "reveal-repo",
      validatedFindings: [validatedFinding("medium")],
      secretFindings: [secretFinding("low")],
    });
    const breakdown = computeTrustScore(report);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 50,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const matches = revealTrustCommitment({
      report,
      commitment: result.attestation.body.findingsCommitment,
      salt: result.salt,
    });
    expect(matches).toBe(true);
  });

  it("rejects a tampered finding set (does not match the original commitment)", () => {
    const attester = makeAttester();
    const report = baseReport({
      target: "reveal-repo-2",
      validatedFindings: [validatedFinding("medium")],
    });
    const breakdown = computeTrustScore(report);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 50,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const tamperedReport: HackReport = {
      ...report,
      validatedFindings: [...report.validatedFindings, validatedFinding("critical")],
    };

    const matches = revealTrustCommitment({
      report: tamperedReport,
      commitment: result.attestation.body.findingsCommitment,
      salt: result.salt,
    });
    expect(matches).toBe(false);
  });

  it("rejects when the wrong salt is supplied", () => {
    const attester = makeAttester();
    const report = baseReport({ target: "reveal-repo-3" });
    const breakdown = computeTrustScore(report);

    const result = attestTrustThreshold({
      report,
      breakdown,
      threshold: 50,
      cert: attester.cert,
      privateKey: attester.privateKey,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const matches = revealTrustCommitment({
      report,
      commitment: result.attestation.body.findingsCommitment,
      salt: "wrong-salt",
    });
    expect(matches).toBe(false);
  });
});
