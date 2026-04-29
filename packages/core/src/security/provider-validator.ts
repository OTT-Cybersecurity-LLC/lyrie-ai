/**
 * LyrieProviderValidator — CVE-aware validation for providers and MCP servers.
 *
 * CVE classes checked:
 *  - CVE-2026-41391 class: PIP_INDEX_URL / UV_INDEX_URL env poisoning
 *  - CVE-2026-7314/7315/7319 class: MCP path-traversal (unsanitized filename args)
 *  - CVE-2026-42428 class: missing integrity verification on downloads
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ProviderConfig {
  name: string;
  apiKey?: string;
  baseUrl?: string;
  env?: Record<string, string>;
  downloadUrls?: string[];
  integrityChecks?: boolean;
  [key: string]: unknown;
}

export interface McpServerConfig {
  name: string;
  /** Command to run the MCP server */
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** Declared tool list (optional, used for arg-name analysis) */
  tools?: McpToolDecl[];
  [key: string]: unknown;
}

export interface McpToolDecl {
  name: string;
  parameters?: Record<string, { type: string; description?: string }>;
}

export interface ValidationResult {
  valid: boolean;
  issues: ValidationIssue[];
  warnings: ValidationWarning[];
}

export interface ValidationIssue {
  cve: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  remediation: string;
}

export interface ValidationWarning {
  message: string;
}

export interface ValidationReport {
  timestamp: string;
  totalProviders: number;
  totalMcpServers: number;
  issueCount: number;
  warningCount: number;
  results: {
    providers: Array<{ name: string; result: ValidationResult }>;
    mcpServers: Array<{ name: string; result: ValidationResult }>;
  };
}

// ─── Suspicious path-traversal parameter names (CVE-2026-7314/7315/7319) ─────
const PATH_TRAVERSAL_PARAM_NAMES = new Set([
  "document_name",
  "filepath",
  "file_path",
  "path",
  "context",
  "filename",
  "file_name",
  "template",
  "template_path",
  "source",
  "target",
  "dest",
  "destination",
  "input_file",
  "output_file",
]);

/** Env keys that can redirect pip/uv to a malicious index (CVE-2026-41391 class). */
const MALICIOUS_INDEX_KEYS = ["PIP_INDEX_URL", "UV_INDEX_URL", "PIP_EXTRA_INDEX_URL"];

export class LyrieProviderValidator {
  // ─── Provider validation ──────────────────────────────────────────────────

  async validateProvider(provider: ProviderConfig): Promise<ValidationResult> {
    const issues: ValidationIssue[] = [];
    const warnings: ValidationWarning[] = [];

    // CVE-2026-41391 class: check env for malicious pip/uv index poisoning
    if (provider.env) {
      for (const key of MALICIOUS_INDEX_KEYS) {
        if (provider.env[key]) {
          issues.push({
            cve: "CVE-2026-41391-class",
            severity: "critical",
            message: `Provider "${provider.name}" sets ${key}="${provider.env[key]}" — this can redirect pip/uv installs to a malicious package index.`,
            remediation: `Remove ${key} from the provider environment. Only set it if you control the index URL and it uses HTTPS with a valid cert.`,
          });
        }
      }
    }

    // CVE-2026-42428 class: no integrity verification on downloads
    if (provider.downloadUrls?.length && !provider.integrityChecks) {
      issues.push({
        cve: "CVE-2026-42428-class",
        severity: "high",
        message: `Provider "${provider.name}" downloads files without integrity verification (no checksums/SRI hashes).`,
        remediation: `Set integrityChecks: true and supply SHA-256 hashes for all downloaded assets.`,
      });
    }

    // Warn on HTTP (non-HTTPS) base URLs
    if (provider.baseUrl && provider.baseUrl.startsWith("http://")) {
      warnings.push({
        message: `Provider "${provider.name}" uses an insecure HTTP base URL. Prefer HTTPS.`,
      });
    }

    return { valid: issues.length === 0, issues, warnings };
  }

  // ─── MCP server validation ────────────────────────────────────────────────

  async validateMcpServer(server: McpServerConfig): Promise<ValidationResult> {
    const issues: ValidationIssue[] = [];
    const warnings: ValidationWarning[] = [];

    // CVE-2026-41391 class: env poisoning via pip/uv index
    if (server.env) {
      for (const key of MALICIOUS_INDEX_KEYS) {
        if (server.env[key]) {
          issues.push({
            cve: "CVE-2026-41391-class",
            severity: "critical",
            message: `MCP server "${server.name}" sets ${key} — potential package index poisoning.`,
            remediation: `Remove ${key} from the MCP server environment unless absolutely required.`,
          });
        }
      }
    }

    // CVE-2026-7314/7315/7319 class: unsanitized file path args
    if (server.tools?.length) {
      for (const tool of server.tools) {
        if (!tool.parameters) continue;
        for (const [paramName] of Object.entries(tool.parameters)) {
          if (PATH_TRAVERSAL_PARAM_NAMES.has(paramName.toLowerCase())) {
            issues.push({
              cve: "CVE-2026-7314/7315/7319-class",
              severity: "high",
              message: `MCP server "${server.name}" tool "${tool.name}" has a parameter "${paramName}" that may allow path traversal (unsanitized filename arg pattern).`,
              remediation: `Validate and sanitize "${paramName}" in tool "${tool.name}": reject paths containing "..", absolute paths, and null bytes. Apply a whitelist of allowed directories.`,
            });
          }
        }
      }
    }

    // Warn on commands that invoke pip/uv without --require-hashes
    if (server.command && /pip\s+install|uv\s+add/.test(server.command)) {
      if (!server.command.includes("--require-hashes")) {
        warnings.push({
          message: `MCP server "${server.name}" command runs pip/uv install without --require-hashes. Consider pinning dependencies.`,
        });
      }
    }

    return { valid: issues.length === 0, issues, warnings };
  }

  // ─── Full config scan ─────────────────────────────────────────────────────

  async validateAll(config: {
    providers?: ProviderConfig[];
    mcpServers?: McpServerConfig[];
  }): Promise<ValidationReport> {
    const providerResults: Array<{ name: string; result: ValidationResult }> = [];
    const mcpResults: Array<{ name: string; result: ValidationResult }> = [];

    for (const provider of config.providers ?? []) {
      const result = await this.validateProvider(provider);
      providerResults.push({ name: provider.name, result });
    }

    for (const server of config.mcpServers ?? []) {
      const result = await this.validateMcpServer(server);
      mcpResults.push({ name: server.name, result });
    }

    const issueCount = [
      ...providerResults.map((r) => r.result.issues.length),
      ...mcpResults.map((r) => r.result.issues.length),
    ].reduce((a, b) => a + b, 0);

    const warningCount = [
      ...providerResults.map((r) => r.result.warnings.length),
      ...mcpResults.map((r) => r.result.warnings.length),
    ].reduce((a, b) => a + b, 0);

    return {
      timestamp: new Date().toISOString(),
      totalProviders: providerResults.length,
      totalMcpServers: mcpResults.length,
      issueCount,
      warningCount,
      results: {
        providers: providerResults,
        mcpServers: mcpResults,
      },
    };
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

let _instance: LyrieProviderValidator | null = null;

export function getProviderValidator(): LyrieProviderValidator {
  if (!_instance) _instance = new LyrieProviderValidator();
  return _instance;
}
