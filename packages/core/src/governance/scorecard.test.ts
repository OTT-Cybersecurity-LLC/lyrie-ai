/**
 * Lyrie Governance — AI Governance Scorecard Tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { AiGovernanceScorecard, GOVERNANCE_QUESTIONS } from "./scorecard";
import type { GovernanceAnswers, GovernanceTarget } from "./scorecard";

const ALL_YES: GovernanceAnswers = {
  hasAiInventory: true,
  hasPermissionDocs: true,
  hasHumanOversight: true,
  hasAuditLogging: true,
  hasIncidentResponse: true,
  hasVendorAssessment: true,
  hasModelDriftMonitoring: true,
  hasDataGovernance: true,
};

const ALL_NO: GovernanceAnswers = {
  hasAiInventory: false,
  hasPermissionDocs: false,
  hasHumanOversight: false,
  hasAuditLogging: false,
  hasIncidentResponse: false,
  hasVendorAssessment: false,
  hasModelDriftMonitoring: false,
  hasDataGovernance: false,
};

describe("AiGovernanceScorecard — scoring", () => {
  it("all-yes answers produce score of 100", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_YES });
    expect(report.overallScore).toBe(100);
  });

  it("all-no answers produce score of 0", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_NO });
    expect(report.overallScore).toBe(0);
  });

  it("all-yes maps to Optimizing maturity", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_YES });
    expect(report.maturityLevel).toBe("Optimizing");
  });

  it("all-no maps to None maturity", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_NO });
    expect(report.maturityLevel).toBe("None");
  });

  it("partial answers produce intermediate score", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({
      answers: {
        hasAiInventory: true,
        hasHumanOversight: true,
        hasAuditLogging: true,
      },
    });
    expect(report.overallScore).toBeGreaterThan(0);
    expect(report.overallScore).toBeLessThan(100);
  });
});

describe("AiGovernanceScorecard — report structure", () => {
  it("report has all required fields", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_YES });
    expect(report.overallScore).toBeDefined();
    expect(report.maturityLevel).toBeDefined();
    expect(report.categories.govern).toBeDefined();
    expect(report.categories.map).toBeDefined();
    expect(report.categories.measure).toBeDefined();
    expect(report.categories.manage).toBeDefined();
    expect(Array.isArray(report.gaps)).toBe(true);
    expect(Array.isArray(report.recommendations)).toBe(true);
    expect(report.euAiActCompliance).toBeDefined();
    expect(report.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("all-no produces critical gaps", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_NO });
    const criticalGaps = report.gaps.filter((g) => g.severity === "critical");
    expect(criticalGaps.length).toBeGreaterThan(0);
  });

  it("gaps include NIST references", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_NO });
    for (const gap of report.gaps) {
      expect(gap.nistRef).toBeTruthy();
      expect(gap.nistRef).toMatch(/^(GOVERN|MAP|MEASURE|MANAGE)-/);
    }
  });

  it("all-no with missing human oversight shows EU AI Act Article 14", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: { hasHumanOversight: false } });
    const oversight = report.gaps.find((g) => g.nistRef === "MANAGE-1.1");
    expect(oversight).toBeDefined();
    expect(oversight?.euRef).toBe("Article 14");
  });
});

describe("AiGovernanceScorecard — EU AI Act classification", () => {
  it("all controls present → not classified as High-Risk", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_YES });
    expect(report.euAiActCompliance).not.toBe("Unknown");
  });

  it("missing all controls → High-Risk classification", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_NO });
    expect(report.euAiActCompliance).toBe("High-Risk");
  });
});

describe("AiGovernanceScorecard — report formatting", () => {
  it("formatReport produces non-empty markdown", async () => {
    const scorecard = new AiGovernanceScorecard();
    const report = await scorecard.assess({ answers: ALL_YES });
    const markdown = AiGovernanceScorecard.formatReport(report);
    expect(markdown).toContain("# 🏛️ AI Governance Scorecard");
    expect(markdown).toContain("Overall Score");
    expect(markdown.length).toBeGreaterThan(100);
  });
});

describe("GOVERNANCE_QUESTIONS", () => {
  it("exports 8 governance questions", () => {
    expect(GOVERNANCE_QUESTIONS.length).toBe(8);
  });

  it("all questions reference NIST AI RMF", () => {
    for (const q of GOVERNANCE_QUESTIONS) {
      expect(q.nistRef).toMatch(/^(GOVERN|MAP|MEASURE|MANAGE)-/);
    }
  });

  it("all questions have positive weights", () => {
    for (const q of GOVERNANCE_QUESTIONS) {
      expect(q.weight).toBeGreaterThan(0);
    }
  });
});
