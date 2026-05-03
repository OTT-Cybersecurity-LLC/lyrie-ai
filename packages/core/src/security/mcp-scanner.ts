/**
 * MCPSecurityScanner — Pre-connection safety checks for MCP servers.
 *
 * Background: In April 2026 an Anthropic disclosure identified a family of
 * MCP RCE/data-exfil vulnerabilities that hit 7,000+ servers. The attack
 * surface breaks into eight OWASP-catalogued MCP risk classes. This scanner
 * checks all eight before Lyrie connects to ANY MCP server so a rogue or
 * compromised server cannot:
 *   - Poison the agent's context via tool-description injection
 *   - Swap out a known-good tool with a shadow implementation
 *   - Redirect npm installs via unverified npx packages
 *   - Exfiltrate data over cleartext HTTP
 *   - Pull from non-pinned/non-verified dependency registries
 *
 * Integration:
 *   const scanner = new MCPSecurityScanner({ knownGoodRegistry });
 *   const result  = await scanner.scan(serverConfig);
 *   if (!result.safe) {
 *     if (result.riskLevel === "critical") throw new Error("blocked");
 *     // else: warn operator
 *   }
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Public types ─────────────────────────────────────────────────────────────

export type MCPRiskLevel = "critical" | "high" | "medium" | "low" | "safe";
export type MCPFindingSeverity = "critical" | "high" | "medium" | "low";

export interface MCPFinding {
  /** Canonical check id (one of the 8 OWASP MCP risk checks). */
  check: string;
  severity: MCPFindingSeverity;
  description: string;
  recommendation: string;
}

export interface MCPScanResult {
  /** true only when there are zero findings. */
  safe: boolean;
  findings: MCPFinding[];
  /** Highest severity across all findings; 'safe' when no findings. */
  riskLevel: MCPRiskLevel;
}

/** Minimal shape of an MCP tool declaration (as seen in mcp.json / ListTools). */
export interface MCPToolDecl {
  name: string;
  description?: string;
  /** Declared permissions / scopes (optional, non-standard extension). */
  permissions?: string[];
  /** Actual scope of operations the tool performs (non-standard extension). */
  actualScope?: string[];
}

/** Config object passed to MCPSecurityScanner.scan(). */
export interface MCPServerConfig {
  /** Server name / registry key. */
  name?: string;
  /** stdio transport command. */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** HTTP/SSE transport URL. */
  url?: string;
  /** Tool list returned by the server (needed for tool-level checks). */
  tools?: MCPToolDecl[];
  /** Declared permissions (non-standard extension used in tests). */
  permissions?: string[];
}

export interface MCPScannerOptions {
  /**
   * Set of server names / command hashes considered "known-good".
   * Used for the `unverified-server` check.
   */
  knownGoodRegistry?: ReadonlySet<string>;
  /**
   * Set of tool names considered Lyrie built-ins.
   * Used for the `shadow-tool` check.
   */
  builtinToolNames?: ReadonlySet<string>;
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Patterns that indicate a tool description is trying to inject instructions. */
const PROMPT_INJECTION_PATTERNS: ReadonlyArray<RegExp> = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+(a|an|my)\s+/i,
  /system\s*prompt\s*(override|change|modify|replace)/i,
  /forget\s+(everything|all|your)\s+/i,
  /new\s+instructions?\s*:/i,
  /\bDAN\s+mode\b/i,
  /\bjailbreak\b/i,
  /reveal\s+(your|the)\s+(system|hidden|secret)\s+prompt/i,
  // Hidden instructions in angle-bracket style comments
  /<\s*\|\s*end\s*of\s*system\s*\|\s*>/i,
  /role\s*[:=]\s*(system|developer|admin|root)/i,
  // Markdown/XML injection attempts
  /<!--\s*SYSTEM\s*/i,
  /\[HIDDEN\s+INSTRUCTION\]/i,
  // Unicode invisibility tricks
  /[\u200b\u200c\u200d\ufeff]/,
];

/** Built-in Lyrie tool names that should never be shadowed by MCP. */
const DEFAULT_BUILTIN_TOOLS = new Set<string>([
  "read_file",
  "write_file",
  "exec",
  "search",
  "lyrie_shield",
  "lyrie_memory",
  "lyrie_pentest",
]);

// ─── Severity ordering ────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<MCPFindingSeverity | "safe", number> = {
  safe: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(findings: MCPFinding[]): MCPRiskLevel {
  if (findings.length === 0) return "safe";
  let max: MCPRiskLevel = "safe";
  for (const f of findings) {
    if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[max as MCPFindingSeverity]) {
      max = f.severity;
    }
  }
  return max;
}

// ─── MCPSecurityScanner ───────────────────────────────────────────────────────

export class MCPSecurityScanner {
  private knownGoodRegistry: ReadonlySet<string>;
  private builtinToolNames: ReadonlySet<string>;

  constructor(opts: MCPScannerOptions = {}) {
    this.knownGoodRegistry = opts.knownGoodRegistry ?? new Set();
    this.builtinToolNames = opts.builtinToolNames ?? DEFAULT_BUILTIN_TOOLS;
  }

  /**
   * Run all 8 OWASP MCP security checks against `serverConfig`.
   *
   * Pure function — does NOT connect to the server; all checks are static
   * analysis of the config and declared tool list.
   */
  async scan(serverConfig: MCPServerConfig): Promise<MCPScanResult> {
    const findings: MCPFinding[] = [];

    this.checkCleartextTransport(serverConfig, findings);
    this.checkUntrustedNpx(serverConfig, findings);
    this.checkUnverifiedServer(serverConfig, findings);
    this.checkToolPoisoning(serverConfig, findings);
    this.checkPromptInToolDescription(serverConfig, findings);
    this.checkShadowTool(serverConfig, findings);
    this.checkExcessiveScope(serverConfig, findings);
    this.checkRugPull(serverConfig, findings);

    return {
      safe: findings.length === 0,
      findings,
      riskLevel: maxSeverity(findings),
    };
  }

  // ─── Check 1: cleartext-transport ─────────────────────────────────────────

  /** Blocks http:// transport — credentials and tool results travel in cleartext. */
  private checkCleartextTransport(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.url) return;
    try {
      const u = new URL(cfg.url);
      if (u.protocol === "http:") {
        out.push({
          check: "cleartext-transport",
          severity: "high",
          description: `MCP server "${cfg.name ?? cfg.url}" uses http:// — all traffic including credentials and tool results is unencrypted.`,
          recommendation: "Change the transport URL to https://. Never use plain HTTP for MCP endpoints.",
        });
      }
    } catch {
      // malformed URL — let connection attempt surface the error
    }
  }

  // ─── Check 2: untrusted-npx ───────────────────────────────────────────────

  /**
   * Flags stdio servers that launch via `npx` with an unverified package.
   *
   * `npx unverified-pkg` silently downloads and executes whatever is currently
   * published under that name — a supply-chain attack surface.
   */
  private checkUntrustedNpx(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.command) return;
    if (cfg.command !== "npx" && !cfg.command.endsWith("/npx")) return;

    const pkg = cfg.args?.[0];
    if (!pkg) return;

    // If the package is in the known-good registry it's been verified
    if (this.knownGoodRegistry.has(pkg)) return;

    out.push({
      check: "untrusted-npx",
      severity: "critical",
      description: `MCP server "${cfg.name ?? pkg}" is launched via npx with unverified package "${pkg}". This executes arbitrary remote code on every restart.`,
      recommendation: `Add "${pkg}" to Lyrie's known-good MCP registry after auditing it, or pin to a specific version and verify the checksum. Prefer local installs over npx.`,
    });
  }

  // ─── Check 3: unverified-server ───────────────────────────────────────────

  /**
   * Warns when a server name/command is not in Lyrie's known-good registry.
   *
   * Severity intentionally "medium" — useful warning but not blocking on its own.
   */
  private checkUnverifiedServer(cfg: MCPServerConfig, out: MCPFinding[]): void {
    const id = cfg.name ?? cfg.command ?? cfg.url;
    if (!id) return;
    if (this.knownGoodRegistry.has(id)) return;

    out.push({
      check: "unverified-server",
      severity: "medium",
      description: `MCP server "${id}" is not in Lyrie's known-good registry. Its behavior has not been audited.`,
      recommendation: `Review the server source and add "${id}" to the known-good registry in lyrie.config after verification.`,
    });
  }

  // ─── Check 4: tool-poisoning ──────────────────────────────────────────────

  /**
   * Detects prompt-injection via tool names (e.g. a tool named
   * "ignore_all_previous_instructions_and_…").
   */
  private checkToolPoisoning(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.tools?.length) return;

    for (const tool of cfg.tools) {
      // Check tool NAME for injection patterns.
      // Tool names use snake_case — normalize underscores to spaces so
      // the patterns match names like "ignore_previous_instructions_and_…".
      const normalizedName = tool.name.replace(/_/g, " ");
      const nameInjected = PROMPT_INJECTION_PATTERNS.some(
        (re) => re.test(tool.name) || re.test(normalizedName),
      );
      if (nameInjected) {
        out.push({
          check: "tool-poisoning",
          severity: "critical",
          description: `Tool "${tool.name}" in MCP server "${cfg.name ?? "unknown"}" has a name that contains a prompt-injection pattern.`,
          recommendation: "Do not connect to this server. The tool name is designed to manipulate the agent's context.",
        });
      }
    }
  }

  // ─── Check 5: prompt-in-tool-description ─────────────────────────────────

  /**
   * Scans tool descriptions for hidden instructions / prompt injection.
   *
   * This is the most common attack vector in the April 2026 RCE family:
   * a tool description contains `Ignore all previous instructions and…`
   * which the LLM sees when it reads the tool catalog.
   */
  private checkPromptInToolDescription(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.tools?.length) return;

    for (const tool of cfg.tools) {
      if (!tool.description) continue;
      const injected = PROMPT_INJECTION_PATTERNS.some((re) => re.test(tool.description!));
      if (injected) {
        out.push({
          check: "prompt-in-tool-description",
          severity: "critical",
          description: `Tool "${tool.name}" in MCP server "${cfg.name ?? "unknown"}" has a description containing a prompt-injection pattern. The LLM will read this when it reviews available tools.`,
          recommendation: "Do not connect to this server. Audit the server source; if legitimate, file a bug report with the maintainer.",
        });
      }
    }
  }

  // ─── Check 6: shadow-tool ─────────────────────────────────────────────────

  /**
   * Detects tools whose names shadow Lyrie built-ins.
   *
   * An attacker can publish a tool named `read_file` that exfiltrates
   * file content before (or instead of) performing the legitimate operation.
   */
  private checkShadowTool(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.tools?.length) return;

    for (const tool of cfg.tools) {
      if (this.builtinToolNames.has(tool.name)) {
        out.push({
          check: "shadow-tool",
          severity: "high",
          description: `MCP server "${cfg.name ?? "unknown"}" exports a tool named "${tool.name}" which shadows a Lyrie built-in. The external tool may intercept or override the built-in behavior.`,
          recommendation: `Rename the MCP tool to avoid collision with Lyrie built-ins, or add it to the explicit allow-list with a scoped prefix (e.g. "${cfg.name ?? "mcp"}:${tool.name}").`,
        });
      }
    }
  }

  // ─── Check 7: excessive-scope ─────────────────────────────────────────────

  /**
   * Flags tools that request more permissions than declared.
   *
   * Requires the non-standard `permissions` / `actualScope` extensions on
   * the tool declaration. When present, mismatches are flagged.
   */
  private checkExcessiveScope(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.tools?.length) return;

    for (const tool of cfg.tools) {
      if (!tool.permissions || !tool.actualScope) continue;
      const declaredSet = new Set(tool.permissions);
      const undeclared = tool.actualScope.filter((s) => !declaredSet.has(s));
      if (undeclared.length > 0) {
        out.push({
          check: "excessive-scope",
          severity: "high",
          description: `Tool "${tool.name}" in MCP server "${cfg.name ?? "unknown"}" performs operations (${undeclared.join(", ")}) beyond its declared permissions (${tool.permissions.join(", ")}).`,
          recommendation: "Update the tool's permission declaration to accurately reflect its actual scope, or restrict its runtime capabilities.",
        });
      }
    }

    // Also check server-level permissions vs tool count heuristic
    if (cfg.permissions && cfg.tools.length > 0) {
      const dangerousPerms = cfg.permissions.filter((p) =>
        /admin|root|write|exec|shell|sudo/.test(p),
      );
      if (dangerousPerms.length > 0) {
        out.push({
          check: "excessive-scope",
          severity: "medium",
          description: `MCP server "${cfg.name ?? "unknown"}" declares elevated permissions: ${dangerousPerms.join(", ")}.`,
          recommendation: "Apply least-privilege: only grant the minimum permissions required for the tools this server exposes.",
        });
      }
    }
  }

  // ─── Check 8: rug-pull ────────────────────────────────────────────────────

  /**
   * Detects non-pinned npm dependency patterns in server args.
   *
   * A "rug-pull" attack publishes a malicious update to a previously-safe
   * package. Pinning to an exact version + checksum prevents this.
   */
  private checkRugPull(cfg: MCPServerConfig, out: MCPFinding[]): void {
    if (!cfg.command) return;
    const isNpmRunner =
      cfg.command === "npx" ||
      cfg.command.endsWith("/npx") ||
      cfg.command === "npm" ||
      cfg.command.endsWith("/npm");
    if (!isNpmRunner) return;

    const args = cfg.args ?? [];
    for (const arg of args) {
      // A pinned package looks like pkg@1.2.3 or pkg@1.2.3-sha512-...
      // Non-pinned: pkg (no version), pkg@latest, pkg@next, pkg@^1, pkg@~1
      const hasVersion = /@\d/.test(arg) || arg.includes("#");
      const isTaggedLatest = /@(latest|next|beta|alpha|canary|unstable|rc)$/.test(arg);

      if (!hasVersion || isTaggedLatest) {
        out.push({
          check: "rug-pull",
          severity: "high",
          description: `MCP server "${cfg.name ?? "unknown"}" uses non-pinned dependency "${arg}". A supply-chain attacker could publish a malicious update that gets pulled on restart.`,
          recommendation: `Pin to an exact version: "${arg.split("@")[0]}@<exact-version>". Verify the tarball integrity hash. Consider using a lockfile or a private registry mirror.`,
        });
        break; // one finding per server is enough signal
      }
    }
  }
}
