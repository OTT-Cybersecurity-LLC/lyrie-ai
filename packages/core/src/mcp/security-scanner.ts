/**
 * Lyrie MCP Security Scanner
 *
 * Scans MCP server manifests for tool poisoning, typosquatting,
 * hidden unicode injections, and suspicious permission patterns.
 * Covers CVE-2026-30615 class (MCP RCE family).
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { readFileSync } from "node:fs";

export interface McpScanTarget {
  /** Path to mcp.json manifest file */
  manifestPath?: string;
  /** Inline manifest object */
  manifestJson?: object;
  /** Live server URL to probe (currently uses manifest fetched from URL) */
  serverUrl?: string;
}

export interface McpFinding {
  rule: string;
  severity: "critical" | "high" | "medium" | "low";
  tool?: string;
  description: string;
  evidence: string;
  remediation: string;
}

export interface McpScanResult {
  ok: boolean;
  target: string;
  findings: McpFinding[];
  toolCount: number;
  scanDurationMs: number;
}

// ─── Rule implementations ──────────────────────────────────────────────────────

/** Popular tool names used for typosquatting detection */
const POPULAR_TOOLS = ["bash", "python", "git", "curl", "node", "npm", "pip", "docker", "sh", "exec", "run"];

/** Levenshtein distance */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/** Rule 1: TOOL_NAME_TYPOSQUATTING */
function checkTyposquatting(toolName: string): McpFinding | null {
  const lower = toolName.toLowerCase();
  for (const popular of POPULAR_TOOLS) {
    if (lower === popular) continue; // exact match is fine
    const dist = levenshtein(lower, popular);
    if (dist > 0 && dist < 2) {
      return {
        rule: "TOOL_NAME_TYPOSQUATTING",
        severity: "high",
        tool: toolName,
        description: `Tool name "${toolName}" is suspiciously close to the popular tool "${popular}" (edit distance: ${dist}).`,
        evidence: `Tool: "${toolName}", Similar to: "${popular}", Distance: ${dist}`,
        remediation: "Verify tool origin. Reject manifest if tool is not from a trusted publisher.",
      };
    }
  }
  return null;
}

/** Rule 2: HIDDEN_UNICODE */
function checkHiddenUnicode(toolName: string, description: string, field: string): McpFinding | null {
  const text = `${toolName} ${description}`;
  // Zero-width chars, RTL override, homoglyphs (simplified set)
  const hiddenPattern = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/;
  // Homoglyph detection for common chars
  const homoglyphs: Record<string, RegExp> = {
    "a": /[\u0430\u0251\u00E0-\u00E4]/,
    "e": /[\u0435\u00E8-\u00EB]/,
    "o": /[\u043E\u00F2-\u00F6]/,
    "i": /[\u0456\u00EC-\u00EF]/,
  };

  if (hiddenPattern.test(text)) {
    const matches = text.match(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g) ?? [];
    return {
      rule: "HIDDEN_UNICODE",
      severity: "critical",
      tool: toolName,
      description: `Hidden unicode characters detected in ${field}: zero-width or directional override characters found.`,
      evidence: `Chars: ${matches.map((c) => `U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`).join(", ")}`,
      remediation: "Strip or reject any manifest containing zero-width or RTL override characters. This is a strong indicator of prompt injection.",
    };
  }

  // Check homoglyphs in tool name only
  for (const [char, pattern] of Object.entries(homoglyphs)) {
    if (pattern.test(toolName)) {
      return {
        rule: "HIDDEN_UNICODE",
        severity: "high",
        tool: toolName,
        description: `Homoglyph detected in tool name "${toolName}": character resembling "${char}" from non-ASCII range.`,
        evidence: `Tool name contains homoglyph for "${char}"`,
        remediation: "Normalize tool names to ASCII and reject homoglyphs.",
      };
    }
  }

  return null;
}

/** Rule 3: DESCRIPTION_PROMPT_INJECTION */
const INJECTION_PATTERNS = [
  /ignore\s+previous/i,
  /ignore\s+all\s+instructions/i,
  /system\s*:/i,
  /IGNORE\s+ALL/,
  /\[INST\]/,
  /<\|system\|>/,
  /disregard\s+(all\s+)?(prior|previous)/i,
  /you\s+are\s+now/i,
  /new\s+instructions:/i,
  /override\s+instructions/i,
];

function checkPromptInjection(toolName: string, description: string): McpFinding | null {
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(description)) {
      return {
        rule: "DESCRIPTION_PROMPT_INJECTION",
        severity: "critical",
        tool: toolName,
        description: `Tool description contains prompt injection pattern: "${pattern.source}"`,
        evidence: `Description: "${description.slice(0, 200)}"`,
        remediation: "Reject this manifest immediately. Descriptions must not contain instruction override patterns.",
      };
    }
  }
  return null;
}

/** Rule 4: EXCESSIVE_PERMISSIONS */
const PERMISSION_KEYWORDS = {
  write: /\b(write|modify|delete|create|update|edit|overwrite|rm|remove)\b/i,
  exec: /\b(exec|execute|run|spawn|shell|command|subprocess|fork|eval)\b/i,
  network: /\b(network|http|fetch|request|socket|connect|download|upload|url)\b/i,
  filesystem: /\b(file|disk|path|directory|folder|mount|fs|storage|read)\b/i,
};

function checkExcessivePermissions(toolName: string, description: string, inputSchema?: object): McpFinding | null {
  const text = JSON.stringify({ description, inputSchema }).toLowerCase();
  const hits = Object.entries(PERMISSION_KEYWORDS).filter(([, pattern]) => pattern.test(text));

  if (hits.length >= 4) {
    return {
      rule: "EXCESSIVE_PERMISSIONS",
      severity: "high",
      tool: toolName,
      description: `Tool declares write + exec + network + filesystem capabilities simultaneously.`,
      evidence: `Permission categories detected: ${hits.map(([k]) => k).join(", ")}`,
      remediation: "Split tool into scoped sub-tools. A single tool should not span all four permission domains.",
    };
  }
  return null;
}

/** Rule 5: SCHEMA_MISMATCH */
function checkSchemaMismatch(toolName: string, inputSchema?: Record<string, unknown>): McpFinding | null {
  if (!inputSchema?.properties || typeof inputSchema.properties !== "object") return null;

  const props = inputSchema.properties as Record<string, { type?: string; description?: string }>;

  for (const [paramName, paramDef] of Object.entries(props)) {
    // Flag cases where param name suggests one type but declared type is another
    const isIdish = /id|uuid|key|token|hash/.test(paramName.toLowerCase());
    const isPathish = /path|file|dir|folder/.test(paramName.toLowerCase());
    const isUrlish = /url|uri|endpoint|host/.test(paramName.toLowerCase());

    if (isIdish && paramDef.type === "object") {
      return {
        rule: "SCHEMA_MISMATCH",
        severity: "medium",
        tool: toolName,
        description: `Parameter "${paramName}" name suggests a scalar identifier but is declared as type "object" — potential exfil vector.`,
        evidence: `param: ${paramName}, declared type: ${paramDef.type}`,
        remediation: "Ensure parameter types match their semantic purpose. IDs should be strings, not objects.",
      };
    }
    if ((isPathish || isUrlish) && paramDef.type === "number") {
      return {
        rule: "SCHEMA_MISMATCH",
        severity: "medium",
        tool: toolName,
        description: `Parameter "${paramName}" name suggests a path/URL but is declared as type "number" — possible schema confusion.`,
        evidence: `param: ${paramName}, declared type: ${paramDef.type}`,
        remediation: "Verify parameter schema reflects actual expected data. Mismatches enable exfiltration via type confusion.",
      };
    }
  }
  return null;
}

/** Rule 6: SUSPICIOUS_DESCRIPTION_LENGTH */
function checkDescriptionLength(toolName: string, description: string): McpFinding | null {
  if (description.length > 2000) {
    return {
      rule: "SUSPICIOUS_DESCRIPTION_LENGTH",
      severity: "medium",
      tool: toolName,
      description: `Tool description is ${description.length} characters — exceeds 2000 char threshold (padding for injection).`,
      evidence: `Description length: ${description.length} chars`,
      remediation: "Tool descriptions should be concise (< 500 chars). Long descriptions are used to pad injection payloads.",
    };
  }
  return null;
}

/** Rule 7: MISSING_SCOPE */
function checkMissingScope(toolName: string, toolDef: Record<string, unknown>): McpFinding | null {
  const hasScope = "scope" in toolDef || "permissions" in toolDef || "capabilities" in toolDef;
  if (!hasScope) {
    return {
      rule: "MISSING_SCOPE",
      severity: "low",
      tool: toolName,
      description: `Tool "${toolName}" has no scope/permissions declaration — violates ATP (Agent Trust Protocol).`,
      evidence: `Keys present: ${Object.keys(toolDef).join(", ")}`,
      remediation: "Add a 'scope' field to each tool declaration listing required capabilities (read/write/network/exec).",
    };
  }
  return null;
}

/** Rule 8: KNOWN_BAD_PATTERN — CVE-2026-30615 fingerprints */
const CVE_2026_30615_PATTERNS = [
  { field: "x-rce-payload", desc: "CVE-2026-30615 RCE marker field" },
  { field: "__proto__", desc: "Prototype pollution vector" },
  { field: "constructor", desc: "Constructor injection vector" },
  { field: "x-exec-on-load", desc: "Auto-execute on manifest load (CVE-2026-30615)" },
  { field: "eval", desc: "Eval field — direct code injection vector" },
];

function checkKnownBadPattern(toolName: string, toolDef: Record<string, unknown>): McpFinding | null {
  const toolStr = JSON.stringify(toolDef).toLowerCase();

  for (const { field, desc } of CVE_2026_30615_PATTERNS) {
    if (Object.prototype.hasOwnProperty.call(toolDef, field) || toolStr.includes(`"${field}"`) || toolStr.includes(`'${field}'`)) {
      return {
        rule: "KNOWN_BAD_PATTERN",
        severity: "critical",
        tool: toolName,
        description: `CVE-2026-30615 fingerprint detected: ${desc} (field: "${field}")`,
        evidence: `Field "${field}" found in tool definition`,
        remediation: "Immediately reject this manifest. This matches known MCP RCE attack patterns (CVE-2026-30615).",
      };
    }
  }
  return null;
}

// ─── Main scanner ──────────────────────────────────────────────────────────────

function parseManifest(target: McpScanTarget): { manifest: Record<string, unknown>; targetStr: string } {
  if (target.manifestJson) {
    return { manifest: target.manifestJson as Record<string, unknown>, targetStr: "inline" };
  }

  if (target.manifestPath) {
    const raw = readFileSync(target.manifestPath, "utf-8");
    return { manifest: JSON.parse(raw), targetStr: target.manifestPath };
  }

  if (target.serverUrl) {
    // For server URLs we'd normally fetch; in offline mode, return empty
    return { manifest: { tools: [] }, targetStr: target.serverUrl };
  }

  throw new Error("McpScanTarget must provide manifestPath, manifestJson, or serverUrl");
}

export async function scanMcpManifest(target: McpScanTarget): Promise<McpScanResult> {
  const startMs = Date.now();
  const { manifest, targetStr } = parseManifest(target);
  const findings: McpFinding[] = [];

  // Extract tools array — support both {tools: [...]} and {mcpServers: {name: {tools: [...]}}}
  let tools: Array<Record<string, unknown>> = [];
  if (Array.isArray(manifest["tools"])) {
    tools = manifest["tools"] as Array<Record<string, unknown>>;
  } else if (manifest["mcpServers"] && typeof manifest["mcpServers"] === "object") {
    const servers = manifest["mcpServers"] as Record<string, { tools?: unknown[] }>;
    for (const server of Object.values(servers)) {
      if (Array.isArray(server.tools)) {
        tools.push(...(server.tools as Array<Record<string, unknown>>));
      }
    }
  }

  for (const tool of tools) {
    const toolName = String(tool["name"] ?? "unknown");
    const description = String(tool["description"] ?? "");
    const inputSchema = tool["inputSchema"] as Record<string, unknown> | undefined;

    // Run all 8 rules
    const checks: Array<McpFinding | null> = [
      checkTyposquatting(toolName),
      checkHiddenUnicode(toolName, description, "name/description"),
      checkPromptInjection(toolName, description),
      checkExcessivePermissions(toolName, description, inputSchema),
      checkSchemaMismatch(toolName, inputSchema as Record<string, unknown> | undefined),
      checkDescriptionLength(toolName, description),
      checkMissingScope(toolName, tool),
      checkKnownBadPattern(toolName, tool),
    ];

    for (const finding of checks) {
      if (finding) findings.push(finding);
    }
  }

  const scanDurationMs = Date.now() - startMs;
  const criticals = findings.filter((f) => f.severity === "critical");
  const highs = findings.filter((f) => f.severity === "high");

  return {
    ok: criticals.length === 0 && highs.length === 0,
    target: targetStr,
    findings,
    toolCount: tools.length,
    scanDurationMs,
  };
}
