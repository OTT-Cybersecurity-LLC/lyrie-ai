/**
 * Lyrie Governance — Agent Permission Analyzer
 *
 * Scans an AI agent's tool manifest and configuration to identify
 * permission risks, missing controls, and compliance violations.
 *
 * CLI: lyrie governance permissions <path-to-agent-config>
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import * as fs from "node:fs";
import * as path from "node:path";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ToolDefinitionEntry {
  /** Tool name (e.g. "read_file", "send_email", "execute_sql") */
  name: string;
  /** Optional description */
  description?: string;
  /** Optional parameters */
  parameters?: Record<string, unknown>;
  /** Optional declared scopes */
  scopes?: string[];
  /** Whether audit logging is declared */
  auditLog?: boolean;
  /** Whether rate limiting is configured */
  rateLimited?: boolean;
  /** Whether human approval is required */
  requiresApproval?: boolean;
}

export interface ToolManifest {
  /** List of tools the agent has access to */
  tools: ToolDefinitionEntry[];
  /** Agent name or ID */
  agentId?: string;
  /** Agent version */
  version?: string;
}

export interface PermissionFinding {
  /** Tool name that triggered this finding */
  tool: string;
  /** Risk level */
  severity: "critical" | "high" | "medium" | "low";
  /** Finding description */
  description: string;
  /** NIST AI RMF reference */
  nistRef: string;
  /** EU AI Act reference */
  euActRef?: string;
  /** Specific recommendation for this finding */
  recommendation: string;
}

export interface PermissionReport {
  /** 0–100 risk score (higher = riskier) */
  riskScore: number;
  /** Risk level label */
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL";
  /** Tools identified as having excessive permissions */
  excessivePermissions: string[];
  /** Missing security controls */
  missingControls: string[];
  /** Actionable recommendations */
  recommendations: string[];
  /** NIST AI RMF + EU AI Act compliance flags */
  complianceFlags: string[];
  /** Detailed findings */
  findings: PermissionFinding[];
  /** Analyzed tool count */
  toolCount: number;
  /** ISO 8601 timestamp */
  analyzedAt: string;
}

// ─── Tool Risk Patterns ───────────────────────────────────────────────────────

interface ToolRiskRule {
  /** Regex patterns to match tool names */
  patterns: RegExp[];
  /** Base risk level */
  severity: "critical" | "high" | "medium" | "low";
  /** Risk description */
  description: string;
  /** NIST reference */
  nistRef: string;
  /** EU AI Act reference */
  euActRef?: string;
  /** Required mitigations — if absent, elevate risk */
  requiredControls: Array<keyof ToolDefinitionEntry>;
  /** Recommendation when controls are missing */
  recommendation: string;
}

const TOOL_RISK_RULES: ToolRiskRule[] = [
  // File system write access
  {
    patterns: [/write_file/i, /save_file/i, /delete_file/i, /modify_file/i, /fs_write/i, /file_write/i],
    severity: "high",
    description: "File system write access — agent can modify or delete files on the host.",
    nistRef: "GOVERN-2.2",
    euActRef: "Article 9",
    requiredControls: ["scopes", "auditLog", "requiresApproval"],
    recommendation:
      "Restrict file write access to a specific directory scope. " +
      "Require human approval for destructive operations (delete, overwrite). " +
      "Enable audit logging for all file operations.",
  },
  // Email / messaging
  {
    patterns: [/send_email/i, /send_message/i, /email/i, /smtp/i, /slack_post/i, /teams_message/i, /notify/i],
    severity: "medium",
    description: "Outbound communication tool — agent can send messages or emails to external parties.",
    nistRef: "GOVERN-2.2",
    euActRef: "Article 9",
    requiredControls: ["rateLimited", "auditLog"],
    recommendation:
      "Apply rate limiting to prevent bulk messaging abuse. " +
      "Log all outbound communications. " +
      "Consider allowlisting permitted recipient domains.",
  },
  // Database write
  {
    patterns: [/db_write/i, /sql_write/i, /execute_sql/i, /database_write/i, /insert_record/i, /update_record/i, /delete_record/i],
    severity: "critical",
    description: "Database write access — agent can modify or delete production data.",
    nistRef: "GOVERN-2.2",
    euActRef: "Article 9",
    requiredControls: ["requiresApproval", "auditLog", "scopes"],
    recommendation:
      "CRITICAL: Database write operations must require explicit human approval. " +
      "Scope to read-only unless write is essential. " +
      "Enable comprehensive audit logging with query capture. " +
      "Implement transaction rollback capability.",
  },
  // External API calls
  {
    patterns: [/http_request/i, /web_request/i, /api_call/i, /fetch_url/i, /curl/i, /webhook/i, /external_api/i],
    severity: "medium",
    description: "External API access — agent can make arbitrary outbound HTTP requests.",
    nistRef: "MAP-5.1",
    euActRef: "Article 9",
    requiredControls: ["scopes"],
    recommendation:
      "Implement an allowlist of permitted external domains/APIs. " +
      "Block requests to internal network ranges (169.254.x.x, 10.x.x.x, 172.16.x.x). " +
      "Log all external requests with full URL and response code.",
  },
  // PII / personal data
  {
    patterns: [/read_pii/i, /access_pii/i, /user_data/i, /personal_data/i, /customer_data/i, /gdpr/i],
    severity: "high",
    description: "PII data access — agent processes personal or sensitive data.",
    nistRef: "MAP-3.5",
    euActRef: "Article 10",
    requiredControls: ["auditLog", "scopes"],
    recommendation:
      "Apply data minimization — only access PII fields required for the task. " +
      "Mask or redact sensitive fields in logs. " +
      "Ensure GDPR lawful basis documentation. " +
      "Implement data retention limits.",
  },
  // Code execution
  {
    patterns: [/execute_code/i, /run_code/i, /eval/i, /exec/i, /shell/i, /bash/i, /python_exec/i, /subprocess/i],
    severity: "critical",
    description: "Code execution capability — agent can run arbitrary code on the host.",
    nistRef: "GOVERN-2.2",
    euActRef: "Article 9",
    requiredControls: ["requiresApproval", "auditLog", "scopes"],
    recommendation:
      "CRITICAL: Code execution must be sandboxed (container/VM isolation). " +
      "Require human approval for all code execution. " +
      "Log all executed code with output. " +
      "Implement timeout and resource limits.",
  },
  // Payment / financial
  {
    patterns: [/payment/i, /charge/i, /stripe/i, /transaction/i, /transfer/i, /invoice/i, /billing/i],
    severity: "critical",
    description: "Financial transaction capability — agent can initiate payments or transfers.",
    nistRef: "MANAGE-1.1",
    euActRef: "Article 14",
    requiredControls: ["requiresApproval", "auditLog"],
    recommendation:
      "CRITICAL: All financial operations require mandatory human approval. " +
      "Implement transaction amount limits. " +
      "Full audit trail with business justification required. " +
      "Integrate with fraud detection systems.",
  },
  // Identity / auth management
  {
    patterns: [/manage_users/i, /create_user/i, /assign_role/i, /modify_permissions/i, /reset_password/i, /entra/i, /azure_ad/i, /okta/i],
    severity: "critical",
    description: "Identity management capability — agent can modify user accounts or permissions.",
    nistRef: "GOVERN-2.2",
    euActRef: "Article 9",
    requiredControls: ["requiresApproval", "auditLog"],
    recommendation:
      "CRITICAL: All identity and access management operations require human approval. " +
      "Implement separation of duties — AI should not self-assign elevated permissions. " +
      "All changes must be logged to immutable audit trail. " +
      "Integrate with Privileged Identity Management (PIM).",
  },
];

// ─── Manifest Parser ──────────────────────────────────────────────────────────

/**
 * Parse a tool manifest from a JSON/YAML config file.
 */
export function parseToolManifest(configPath: string): ToolManifest {
  const content = fs.readFileSync(configPath, "utf-8");
  let parsed: unknown;

  try {
    parsed = JSON.parse(content);
  } catch {
    // Try to extract tool names heuristically from non-JSON
    const toolMatches = content.match(/["'`]([a-z_]+(?:_[a-z]+)*)["'`]/g) ?? [];
    const tools: ToolDefinitionEntry[] = toolMatches
      .map((m) => m.replace(/["'`]/g, ""))
      .filter((name) => name.includes("_") && name.length > 4)
      .slice(0, 50)
      .map((name) => ({ name }));

    return { tools, agentId: path.basename(configPath) };
  }

  // Handle common manifest formats
  if (typeof parsed === "object" && parsed !== null) {
    const obj = parsed as Record<string, unknown>;

    // OpenAI function calling format
    if (Array.isArray(obj["tools"])) {
      return {
        tools: (obj["tools"] as Array<Record<string, unknown>>).map((t) => ({
          name: String(t["name"] || t["function"] || "unknown"),
          description: t["description"] as string | undefined,
          parameters: t["parameters"] as Record<string, unknown> | undefined,
          scopes: t["scopes"] as string[] | undefined,
          auditLog: t["auditLog"] as boolean | undefined,
          rateLimited: t["rateLimited"] as boolean | undefined,
          requiresApproval: t["requiresApproval"] as boolean | undefined,
        })),
        agentId: obj["agentId"] as string | undefined,
        version: obj["version"] as string | undefined,
      };
    }

    // Lyrie agent config format
    if (Array.isArray(obj["allowedTools"])) {
      return {
        tools: (obj["allowedTools"] as string[]).map((name) => ({ name })),
        agentId: obj["id"] as string | undefined,
      };
    }

    // Flat tool list
    if (Array.isArray(obj["functions"])) {
      return {
        tools: (obj["functions"] as Array<Record<string, unknown>>).map((t) => ({
          name: String(t["name"] || "unknown"),
          description: t["description"] as string | undefined,
        })),
      };
    }
  }

  // Fallback
  return { tools: [], agentId: path.basename(configPath) };
}

// ─── AgentPermissionAnalyzer ──────────────────────────────────────────────────

export class AgentPermissionAnalyzer {
  /**
   * Analyze a tool manifest and produce a permission risk report.
   *
   * @param toolManifest - The agent's tool manifest to analyze
   * @returns PermissionReport
   */
  analyze(toolManifest: ToolManifest): PermissionReport {
    const findings: PermissionFinding[] = [];
    const excessivePermissions: string[] = [];
    const missingControls: Set<string> = new Set();
    const complianceFlags: Set<string> = new Set();

    for (const tool of toolManifest.tools) {
      for (const rule of TOOL_RISK_RULES) {
        const matches = rule.patterns.some((pattern) => pattern.test(tool.name));
        if (!matches) continue;

        // Check which required controls are missing
        const missingForTool = rule.requiredControls.filter((ctrl) => {
          if (ctrl === "auditLog") return !tool.auditLog;
          if (ctrl === "rateLimited") return !tool.rateLimited;
          if (ctrl === "requiresApproval") return !tool.requiresApproval;
          if (ctrl === "scopes") return !tool.scopes || tool.scopes.length === 0;
          return false;
        });

        // Escalate severity if critical controls are missing
        let effectiveSeverity = rule.severity;
        if (missingForTool.includes("requiresApproval") && rule.severity === "high") {
          effectiveSeverity = "critical";
        }

        findings.push({
          tool: tool.name,
          severity: effectiveSeverity,
          description: rule.description,
          nistRef: rule.nistRef,
          euActRef: rule.euActRef,
          recommendation: missingForTool.length > 0
            ? `Missing controls: [${missingForTool.join(", ")}]. ${rule.recommendation}`
            : rule.recommendation,
        });

        if (effectiveSeverity === "critical" || effectiveSeverity === "high") {
          excessivePermissions.push(tool.name);
        }

        for (const ctrl of missingForTool) {
          missingControls.add(ctrl);
        }

        if (rule.nistRef) complianceFlags.add(`NIST AI RMF: ${rule.nistRef}`);
        if (rule.euActRef) complianceFlags.add(`EU AI Act: ${rule.euActRef}`);
      }
    }

    // Check for missing audit logging globally
    const toolsWithoutLogs = toolManifest.tools.filter((t) => !t.auditLog);
    if (toolsWithoutLogs.length > 0) {
      missingControls.add("auditLog");
      complianceFlags.add("NIST AI RMF: MEASURE-2.5 (Audit Logging)");
      findings.push({
        tool: "*",
        severity: "critical",
        description: `${toolsWithoutLogs.length} tool(s) lack audit logging — actions cannot be reconstructed for security review.`,
        nistRef: "MEASURE-2.5",
        euActRef: "Article 12",
        recommendation:
          "Enable structured audit logging for ALL agent tools. " +
          "Each log entry must include: tool name, input parameters, output summary, " +
          "user/session ID, and timestamp. Retain for minimum 90 days.",
      });
    }

    // Compute risk score
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;
    const mediumCount = findings.filter((f) => f.severity === "medium").length;

    const rawScore = criticalCount * 30 + highCount * 15 + mediumCount * 5;
    const riskScore = Math.min(100, rawScore);

    const riskLevel =
      riskScore >= 80 ? "CRITICAL" :
      riskScore >= 60 ? "HIGH" :
      riskScore >= 40 ? "MEDIUM" :
      riskScore >= 20 ? "LOW" : "MINIMAL";

    // Build recommendations
    const topFindings = findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .slice(0, 5);

    const recommendations = topFindings.map(
      (f, i) => `${i + 1}. [${f.tool}] ${f.recommendation.split(".")[0]}.`,
    );

    if (missingControls.has("auditLog")) {
      recommendations.unshift("0. Enable audit logging for all agent tools immediately — this is a critical compliance requirement.");
    }

    return {
      riskScore,
      riskLevel,
      excessivePermissions: [...new Set(excessivePermissions)],
      missingControls: [...missingControls],
      recommendations,
      complianceFlags: [...complianceFlags].sort(),
      findings: findings.sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return order[a.severity] - order[b.severity];
      }),
      toolCount: toolManifest.tools.length,
      analyzedAt: new Date().toISOString(),
    };
  }

  /**
   * Format a permission report as human-readable markdown.
   */
  static formatReport(report: PermissionReport, agentId?: string): string {
    const lines: string[] = [
      "# 🔐 Agent Permission Analysis Report",
      "",
      `**Agent:** ${agentId ?? "unknown"}`,
      `**Analyzed:** ${report.analyzedAt}`,
      `**Tools Scanned:** ${report.toolCount}`,
      `**Risk Score:** ${report.riskScore}/100`,
      `**Risk Level:** ${report.riskLevel}`,
      "",
      "## Excessive Permissions",
      "",
    ];

    if (report.excessivePermissions.length === 0) {
      lines.push("✅ No tools with excessive permissions detected.");
    } else {
      report.excessivePermissions.forEach((t) => lines.push(`- ⚠️  \`${t}\``));
    }

    lines.push("", "## Missing Controls", "");
    if (report.missingControls.length === 0) {
      lines.push("✅ All required controls are in place.");
    } else {
      report.missingControls.forEach((c) => lines.push(`- ❌ ${c}`));
    }

    lines.push("", "## Compliance Flags", "");
    report.complianceFlags.forEach((f) => lines.push(`- 🚩 ${f}`));

    lines.push("", "## Recommendations", "");
    report.recommendations.forEach((r) => lines.push(r));

    lines.push("", "## Detailed Findings", "");
    for (const f of report.findings) {
      if (f.tool === "*") continue; // shown in missing controls
      lines.push(`### [${f.severity.toUpperCase()}] \`${f.tool}\``);
      lines.push(`${f.description}`);
      lines.push(`**NIST:** ${f.nistRef}${f.euActRef ? ` | **EU AI Act:** ${f.euActRef}` : ""}`);
      lines.push(`**Fix:** ${f.recommendation}`);
      lines.push("");
    }

    return lines.join("\n");
  }
}
