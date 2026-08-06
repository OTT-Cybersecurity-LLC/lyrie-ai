/**
 * Lyrie Hack — Signed Findings integration tests.
 *
 * Covers the wiring between `@lyrie/atp`'s generic `signFinding` /
 * `verifySignedFinding` primitives and Lyrie Hack's `HackReport`.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, expect, it } from "bun:test";
import { issueAic, makeScope, sha256Hex, verifySignedFinding } from "@lyrie/atp";
import { signHackReport } from "./signed-findings";
import { REPORT_ENGINE_VERSION, type HackReport, type Severity } from "./report-engine";

function emptyCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function baseCertInput() {
  return {
    modelId: "anthropic/claude-sonnet-4-6",
    systemPromptHash: sha256Hex("p"),
    scope: makeScope({ allowedTools: ["hack"], maxSubAgentDepth: 0 }),
    operatorId: "guy@lyrie.ai",
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
    length: 32,
    confidence: 0.8,
    signature: "Lyrie.ai by OTT Cybersecurity LLC" as const,
  };
}

function baseReport(over: Partial<HackReport> = {}): HackReport {
  return {
    target: "/tmp/x",
    runId: "hack-test",
    mode: "standard",
    startedAt: "2026-08-07T00:00:00.000Z",
    finishedAt: "2026-08-07T00:00:01.000Z",
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

describe("signHackReport", () => {
  it("signs exactly one SignedFinding per validated finding and per secret finding", () => {
    const { cert, keyPair } = issueAic(baseCertInput());
    const report = baseReport({
      validatedFindings: [
        validatedFinding("critical"),
        validatedFinding("high"),
        validatedFinding("low", false),
      ],
      secretFindings: [secretFinding("high"), secretFinding("medium")],
    });

    const result = signHackReport(report, cert, keyPair.privateKey);

    expect(result.report).toBe(report);
    expect(result.signedFindings).toHaveLength(3);
    expect(result.signedSecrets).toHaveLength(2);
  });

  it("produces signed findings that each verify correctly against the signing cert", () => {
    const { cert, keyPair } = issueAic(baseCertInput());
    const report = baseReport({
      validatedFindings: [validatedFinding("critical"), validatedFinding("medium")],
      secretFindings: [secretFinding("critical")],
    });

    const { signedFindings, signedSecrets } = signHackReport(report, cert, keyPair.privateKey);

    for (const sf of signedFindings) {
      expect(verifySignedFinding(sf, cert).valid).toBe(true);
    }
    for (const ss of signedSecrets) {
      expect(verifySignedFinding(ss, cert).valid).toBe(true);
    }
  });

  it("preserves the original finding payloads unmodified inside the signed wrapper", () => {
    const { cert, keyPair } = issueAic(baseCertInput());
    const vf = validatedFinding("high");
    const sf = secretFinding("high");
    const report = baseReport({ validatedFindings: [vf], secretFindings: [sf] });

    const result = signHackReport(report, cert, keyPair.privateKey);

    expect(result.signedFindings[0]!.payload).toEqual(vf);
    expect(result.signedSecrets[0]!.payload).toEqual(sf);
  });

  it("fails verification against a different agent's cert (wrong signer)", () => {
    const { cert, keyPair } = issueAic(baseCertInput());
    const other = issueAic(baseCertInput());
    const report = baseReport({ validatedFindings: [validatedFinding("critical")] });

    const { signedFindings } = signHackReport(report, cert, keyPair.privateKey);

    const v = verifySignedFinding(signedFindings[0]!, other.cert);
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_RECEIPT_AGENT_MISMATCH");
  });

  it("handles an empty report (zero findings, zero secrets)", () => {
    const { cert, keyPair } = issueAic(baseCertInput());
    const report = baseReport();

    const result = signHackReport(report, cert, keyPair.privateKey);

    expect(result.signedFindings).toHaveLength(0);
    expect(result.signedSecrets).toHaveLength(0);
  });
});
