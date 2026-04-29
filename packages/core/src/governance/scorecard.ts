/**
 * Lyrie Governance — AI Governance Scorecard
 *
 * Assesses AI deployments against the NIST AI Risk Management Framework (AI RMF)
 * and EU AI Act compliance requirements.
 *
 * CLI: lyrie governance assess [--config <path>] [--interactive] [--out report.json]
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import * as readline from "node:readline";
import * as fs from "node:fs";

// ─── Types ────────────────────────────────────────────────────────────────────

export type MaturityLevel =
  | "None"
  | "Initial"
  | "Developing"
  | "Defined"
  | "Managed"
  | "Optimizing";

export type EuAiActRisk =
  | "High-Risk"
  | "Limited-Risk"
  | "Minimal-Risk"
  | "Unknown";

export interface CategoryScore {
  /** NIST AI RMF function name */
  name: string;
  /** Score 0–100 */
  score: number;
  /** Maximum possible score */
  maxScore: number;
  /** Answered questions count */
  answeredCount: number;
  /** Key findings for this category */
  findings: string[];
}

export interface GovernanceGap {
  /** NIST AI RMF reference (e.g. "GOVERN-1.1") */
  nistRef: string;
  /** EU AI Act reference (e.g. "Article 9") */
  euRef?: string;
  /** Gap description */
  description: string;
  /** Severity: critical | high | medium | low */
  severity: "critical" | "high" | "medium" | "low";
  /** Recommended remediation */
  recommendation: string;
}

export interface GovernanceAnswers {
  /** GOVERN-1.1: Does the org maintain an AI inventory? */
  hasAiInventory?: boolean;
  /** GOVERN-2.2: Are AI agent permissions documented and scoped? */
  hasPermissionDocs?: boolean;
  /** MANAGE-1.1: Is there human oversight on high-stakes decisions? */
  hasHumanOversight?: boolean;
  /** MEASURE-2.5: Are AI agent actions logged and auditable? */
  hasAuditLogging?: boolean;
  /** MANAGE-4.1: Is there an AI incident response plan? */
  hasIncidentResponse?: boolean;
  /** MAP-5.1: Are AI vendors assessed for security? */
  hasVendorAssessment?: boolean;
  /** MEASURE-2.9: Is model drift monitored? */
  hasModelDriftMonitoring?: boolean;
  /** MAP-3.5: Are there data governance controls? */
  hasDataGovernance?: boolean;
}

export interface GovernanceTarget {
  /** Optional: live agent endpoint to probe */
  agentEndpoint?: string;
  /** Optional: path to agent config files */
  configPath?: string;
  /** Optional: manual questionnaire answers */
  answers?: GovernanceAnswers;
}

export interface GovernanceReport {
  /** 0–100 composite score */
  overallScore: number;
  /** NIST AI RMF maturity tier */
  maturityLevel: MaturityLevel;
  /** Scores by NIST AI RMF function */
  categories: {
    govern: CategoryScore;
    map: CategoryScore;
    measure: CategoryScore;
    manage: CategoryScore;
  };
  /** Identified gaps with remediation guidance */
  gaps: GovernanceGap[];
  /** Prioritized recommendations */
  recommendations: string[];
  /** EU AI Act risk classification */
  euAiActCompliance: EuAiActRisk;
  /** ISO 8601 timestamp */
  generatedAt: string;
  /** Target info (sanitized) */
  target: { endpoint?: string; configPath?: string };
}

// ─── Question Definitions ─────────────────────────────────────────────────────

interface GovernanceQuestion {
  key: keyof GovernanceAnswers;
  text: string;
  nistRef: string;
  euRef?: string;
  category: "govern" | "map" | "measure" | "manage";
  weight: number; // points awarded when true
  gapIfFalse: Omit<GovernanceGap, "nistRef" | "euRef">;
}

const QUESTIONS: GovernanceQuestion[] = [
  {
    key: "hasAiInventory",
    text: "Does your organization maintain a complete inventory of all AI systems and agents deployed?",
    nistRef: "GOVERN-1.1",
    euRef: "Article 9",
    category: "govern",
    weight: 15,
    gapIfFalse: {
      description: "No AI inventory found — deployed AI systems and agents are not tracked.",
      severity: "critical",
      recommendation:
        "Create and maintain an AI system register. Document every deployed model, agent, " +
        "its purpose, data sources, and risk level. Review quarterly.",
    },
  },
  {
    key: "hasPermissionDocs",
    text: "Are AI agent tool permissions documented, scoped to least privilege, and regularly reviewed?",
    nistRef: "GOVERN-2.2",
    euRef: "Article 9",
    category: "govern",
    weight: 15,
    gapIfFalse: {
      description: "AI agent permissions are not documented or scoped to least privilege.",
      severity: "critical",
      recommendation:
        "Document all tools available to each AI agent. Apply least-privilege scoping. " +
        "Review and certify permissions quarterly. Revoke unused permissions.",
    },
  },
  {
    key: "hasHumanOversight",
    text: "Is there mandatory human oversight (approval gates) for high-stakes AI decisions (financial, medical, legal)?",
    nistRef: "MANAGE-1.1",
    euRef: "Article 14",
    category: "manage",
    weight: 20,
    gapIfFalse: {
      description: "No human oversight mechanism exists for high-stakes AI decisions.",
      severity: "critical",
      recommendation:
        "Implement human-in-the-loop approval workflows for irreversible or high-impact actions. " +
        "Define which decision categories require human sign-off. Log all approvals.",
    },
  },
  {
    key: "hasAuditLogging",
    text: "Are all AI agent actions comprehensively logged with sufficient detail for security audits?",
    nistRef: "MEASURE-2.5",
    euRef: "Article 12",
    category: "measure",
    weight: 15,
    gapIfFalse: {
      description: "AI agent actions are not fully logged — audit trail is incomplete.",
      severity: "critical",
      recommendation:
        "Implement structured logging for every agent action: input, output, tools called, " +
        "decisions made, timestamp, user/session. Retain logs per your data retention policy. " +
        "Ensure logs are tamper-evident.",
    },
  },
  {
    key: "hasIncidentResponse",
    text: "Does your organization have a documented AI-specific incident response plan?",
    nistRef: "MANAGE-4.1",
    euRef: "Article 9",
    category: "manage",
    weight: 10,
    gapIfFalse: {
      description: "No AI-specific incident response plan exists.",
      severity: "high",
      recommendation:
        "Develop an AI incident response playbook covering: model compromise, data exfiltration, " +
        "prompt injection attacks, agent misuse. Include AI-specific containment procedures and " +
        "escalation paths. Test annually.",
    },
  },
  {
    key: "hasVendorAssessment",
    text: "Are all AI vendors and third-party models assessed for security and compliance before deployment?",
    nistRef: "MAP-5.1",
    euRef: "Article 28",
    category: "map",
    weight: 10,
    gapIfFalse: {
      description: "AI vendor security assessments are not being conducted.",
      severity: "high",
      recommendation:
        "Establish a vendor security assessment process for all AI providers. " +
        "Review SOC 2 reports, conduct questionnaires, verify data processing agreements. " +
        "Reassess annually or on major model updates.",
    },
  },
  {
    key: "hasModelDriftMonitoring",
    text: "Is model performance and behavioral drift actively monitored in production?",
    nistRef: "MEASURE-2.9",
    euRef: "Article 9",
    category: "measure",
    weight: 10,
    gapIfFalse: {
      description: "Model drift is not monitored — behavioral changes may go undetected.",
      severity: "medium",
      recommendation:
        "Implement automated monitoring for model output quality, safety policy adherence, " +
        "and behavioral drift. Set alert thresholds. Schedule regular red-team evaluations " +
        "after model updates.",
    },
  },
  {
    key: "hasDataGovernance",
    text: "Are there data governance controls governing what data AI agents can access and process?",
    nistRef: "MAP-3.5",
    euRef: "Article 10",
    category: "map",
    weight: 5,
    gapIfFalse: {
      description: "No data governance controls govern AI agent data access.",
      severity: "medium",
      recommendation:
        "Define data classification policies for AI systems. Restrict agent access to " +
        "only necessary data. Implement data minimization. Document data flows and " +
        "ensure GDPR/data protection compliance.",
    },
  },
];

// ─── Scoring Logic ────────────────────────────────────────────────────────────

function computeMaturityLevel(score: number): MaturityLevel {
  if (score >= 90) return "Optimizing";
  if (score >= 75) return "Managed";
  if (score >= 60) return "Defined";
  if (score >= 40) return "Developing";
  if (score >= 20) return "Initial";
  return "None";
}

function computeEuAiActCompliance(answers: GovernanceAnswers): EuAiActRisk {
  const criticalPassed =
    answers.hasAiInventory &&
    answers.hasPermissionDocs &&
    answers.hasHumanOversight &&
    answers.hasAuditLogging;

  const allPassed = criticalPassed && answers.hasIncidentResponse && answers.hasDataGovernance;

  if (allPassed) return "Limited-Risk";
  if (criticalPassed) return "Limited-Risk";

  const somePassed = [
    answers.hasAiInventory,
    answers.hasPermissionDocs,
    answers.hasHumanOversight,
    answers.hasAuditLogging,
  ].filter(Boolean).length;

  if (somePassed >= 2) return "High-Risk";
  return "High-Risk";
}

function buildCategoryScore(
  name: string,
  questions: GovernanceQuestion[],
  answers: GovernanceAnswers,
): CategoryScore {
  let score = 0;
  let maxScore = 0;
  let answeredCount = 0;
  const findings: string[] = [];

  for (const q of questions) {
    maxScore += q.weight;
    const answer = answers[q.key];
    if (answer !== undefined) {
      answeredCount++;
      if (answer) {
        score += q.weight;
        findings.push(`✅ ${q.nistRef}: ${q.text.substring(0, 60)}...`);
      } else {
        findings.push(`❌ ${q.nistRef}: Gap identified — ${q.gapIfFalse.description.substring(0, 60)}...`);
      }
    } else {
      findings.push(`⚠️  ${q.nistRef}: Not assessed`);
    }
  }

  const normalizedScore = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;

  return {
    name,
    score: normalizedScore,
    maxScore: 100,
    answeredCount,
    findings,
  };
}

// ─── Config parser ────────────────────────────────────────────────────────────

/**
 * Parse agent config file(s) and infer governance answers where possible.
 */
function parseConfigAnswers(configPath: string): Partial<GovernanceAnswers> {
  const inferred: Partial<GovernanceAnswers> = {};

  try {
    const stat = fs.statSync(configPath);
    const files = stat.isDirectory()
      ? fs.readdirSync(configPath).map((f) => `${configPath}/${f}`)
      : [configPath];

    for (const file of files) {
      if (!file.endsWith(".json") && !file.endsWith(".yaml") && !file.endsWith(".yml") && !file.endsWith(".ts")) {
        continue;
      }
      try {
        const content = fs.readFileSync(file, "utf-8").toLowerCase();
        // Heuristic inference from config content
        if (content.includes("audit") || content.includes("logging") || content.includes("log_level")) {
          inferred.hasAuditLogging = true;
        }
        if (content.includes("human_approval") || content.includes("require_approval") || content.includes("human_in_loop")) {
          inferred.hasHumanOversight = true;
        }
        if (content.includes("permissions") || content.includes("scopes") || content.includes("allowed_tools")) {
          inferred.hasPermissionDocs = true;
        }
        if (content.includes("data_governance") || content.includes("data_classification") || content.includes("pii")) {
          inferred.hasDataGovernance = true;
        }
        if (content.includes("drift") || content.includes("monitor")) {
          inferred.hasModelDriftMonitoring = true;
        }
      } catch {
        // skip unreadable files
      }
    }
  } catch {
    // configPath doesn't exist or can't be read
  }

  return inferred;
}

// ─── AiGovernanceScorecard ────────────────────────────────────────────────────

export class AiGovernanceScorecard {
  /**
   * Assess an AI deployment and produce a governance report.
   *
   * @param target - Target description (endpoint, config, or answers)
   * @returns GovernanceReport
   */
  async assess(target: GovernanceTarget): Promise<GovernanceReport> {
    // Merge answers from multiple sources (config parse + manual)
    let answers: GovernanceAnswers = {};

    if (target.configPath) {
      const inferred = parseConfigAnswers(target.configPath);
      answers = { ...answers, ...inferred };
    }

    if (target.answers) {
      answers = { ...answers, ...target.answers };
    }

    // Build category scores
    const governQuestions = QUESTIONS.filter((q) => q.category === "govern");
    const mapQuestions = QUESTIONS.filter((q) => q.category === "map");
    const measureQuestions = QUESTIONS.filter((q) => q.category === "measure");
    const manageQuestions = QUESTIONS.filter((q) => q.category === "manage");

    const govern = buildCategoryScore("GOVERN", governQuestions, answers);
    const map = buildCategoryScore("MAP", mapQuestions, answers);
    const measure = buildCategoryScore("MEASURE", measureQuestions, answers);
    const manage = buildCategoryScore("MANAGE", manageQuestions, answers);

    // Compute overall score (weighted average of categories)
    const totalWeight = QUESTIONS.reduce((sum, q) => sum + q.weight, 0);
    let totalScore = 0;
    for (const q of QUESTIONS) {
      const answer = answers[q.key];
      if (answer === true) totalScore += q.weight;
    }
    const overallScore = totalWeight > 0 ? Math.round((totalScore / totalWeight) * 100) : 0;

    // Compute gaps
    const gaps: GovernanceGap[] = QUESTIONS.filter(
      (q) => answers[q.key] === false || answers[q.key] === undefined,
    ).map((q) => ({
      nistRef: q.nistRef,
      euRef: q.euRef,
      description: q.gapIfFalse.description,
      severity: answers[q.key] === undefined ? ("medium" as const) : q.gapIfFalse.severity,
      recommendation: q.gapIfFalse.recommendation,
    }));

    // Sort gaps by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    gaps.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    // Build recommendations
    const recommendations = gaps
      .filter((g) => g.severity === "critical" || g.severity === "high")
      .slice(0, 5)
      .map((g, i) => `${i + 1}. [${g.nistRef}] ${g.recommendation.split(".")[0]}.`);

    if (recommendations.length === 0) {
      recommendations.push("Governance posture is strong. Schedule next assessment in 6 months.");
    }

    return {
      overallScore,
      maturityLevel: computeMaturityLevel(overallScore),
      categories: { govern, map, measure, manage },
      gaps,
      recommendations,
      euAiActCompliance: computeEuAiActCompliance(answers),
      generatedAt: new Date().toISOString(),
      target: {
        endpoint: target.agentEndpoint,
        configPath: target.configPath,
      },
    };
  }

  /**
   * Run an interactive questionnaire and return answers.
   */
  static async runInteractive(): Promise<GovernanceAnswers> {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const askYesNo = (question: string): Promise<boolean> =>
      new Promise((resolve) => {
        rl.question(`\n${question}\n[y/n] > `, (answer) => {
          resolve(answer.trim().toLowerCase().startsWith("y"));
        });
      });

    console.log("\n🏛️  Lyrie AI Governance Questionnaire");
    console.log("   NIST AI RMF + EU AI Act Assessment\n");
    console.log("─────────────────────────────────────────────────────────────");
    console.log("Answer each question with y (yes) or n (no).\n");

    const answers: GovernanceAnswers = {};

    for (const q of QUESTIONS) {
      const label = `[${q.nistRef}] ${q.text}`;
      answers[q.key] = await askYesNo(label);
    }

    rl.close();
    return answers;
  }

  /**
   * Format a governance report as human-readable markdown.
   */
  static formatReport(report: GovernanceReport): string {
    const lines: string[] = [
      "# 🏛️ AI Governance Scorecard",
      "",
      `**Generated:** ${report.generatedAt}`,
      `**Overall Score:** ${report.overallScore}/100`,
      `**Maturity Level:** ${report.maturityLevel}`,
      `**EU AI Act Classification:** ${report.euAiActCompliance}`,
      "",
      "## Category Scores",
      "",
      `| Function | Score | Answered |`,
      `|----------|-------|----------|`,
      `| GOVERN   | ${report.categories.govern.score}/100 | ${report.categories.govern.answeredCount} questions |`,
      `| MAP      | ${report.categories.map.score}/100 | ${report.categories.map.answeredCount} questions |`,
      `| MEASURE  | ${report.categories.measure.score}/100 | ${report.categories.measure.answeredCount} questions |`,
      `| MANAGE   | ${report.categories.manage.score}/100 | ${report.categories.manage.answeredCount} questions |`,
      "",
      "## Critical Gaps",
      "",
    ];

    const criticalGaps = report.gaps.filter((g) => g.severity === "critical" || g.severity === "high");
    if (criticalGaps.length === 0) {
      lines.push("✅ No critical gaps identified.");
    } else {
      for (const gap of criticalGaps) {
        lines.push(`### ⚠️  [${gap.nistRef}] ${gap.description}`);
        lines.push(`**Severity:** ${gap.severity.toUpperCase()}`);
        if (gap.euRef) lines.push(`**EU AI Act:** ${gap.euRef}`);
        lines.push(`**Recommendation:** ${gap.recommendation}`);
        lines.push("");
      }
    }

    lines.push("## Top Recommendations", "");
    report.recommendations.forEach((r) => lines.push(r));
    lines.push("");

    return lines.join("\n");
  }
}

export { QUESTIONS as GOVERNANCE_QUESTIONS };
