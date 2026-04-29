#!/usr/bin/env bun
/**
 * lyrie security validate — CVE-aware provider + MCP server validation.
 *
 * Usage:
 *   bun run scripts/security-validate.ts
 *   bun run scripts/security-validate.ts --config <path>
 *   bun run scripts/security-validate.ts --json
 *   bun run scripts/security-validate.ts --fail-on critical
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readFileSync, readdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { LyrieProviderValidator } from "../packages/core/src/security/provider-validator";
import type { ValidationReport } from "../packages/core/src/security/provider-validator";

// ─── ANSI ─────────────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  cyan: "\x1b[36m", magenta: "\x1b[35m",
};
function color(str: string, ...codes: string[]): string {
  return codes.join("") + str + C.reset;
}

// ─── Args ─────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const asJson = args.includes("--json");
const configPath = args[args.indexOf("--config") + 1];
const failOnIdx = args.indexOf("--fail-on");
const failOnSeverity = failOnIdx >= 0 ? args[failOnIdx + 1] : null;

// ─── Load config ──────────────────────────────────────────────────────────────
interface ScanConfig {
  providers?: Array<{ name: string; apiKey?: string; baseUrl?: string; env?: Record<string, string>; downloadUrls?: string[]; integrityChecks?: boolean }>;
  mcpServers?: Array<{ name: string; command?: string; args?: string[]; env?: Record<string, string>; tools?: any[] }>;
}

function loadConfig(path?: string): ScanConfig {
  // Try explicit path first
  if (path && existsSync(path)) {
    try {
      return JSON.parse(readFileSync(path, "utf-8"));
    } catch {
      console.error(`Failed to read config: ${path}`);
    }
  }

  // Auto-discover from ~/.lyrie/config/
  const lyrieConfigDir = join(homedir(), ".lyrie", "config");
  const combined: ScanConfig = { providers: [], mcpServers: [] };

  if (existsSync(lyrieConfigDir)) {
    for (const file of readdirSync(lyrieConfigDir).filter((f) => f.endsWith(".json"))) {
      try {
        const raw = JSON.parse(readFileSync(join(lyrieConfigDir, file), "utf-8"));
        if (Array.isArray(raw.providers)) combined.providers!.push(...raw.providers);
        if (Array.isArray(raw.mcpServers)) combined.mcpServers!.push(...raw.mcpServers);
      } catch { /* skip */ }
    }
  }

  // Also check claude_desktop_config.json
  const claudeConfig = join(homedir(), ".claude", "claude_desktop_config.json");
  if (existsSync(claudeConfig)) {
    try {
      const raw = JSON.parse(readFileSync(claudeConfig, "utf-8"));
      const mcpEntries = Object.entries(raw.mcpServers ?? {}).map(([name, cfg]: [string, any]) => ({
        name,
        command: cfg.command,
        args: cfg.args,
        env: cfg.env,
      }));
      combined.mcpServers!.push(...mcpEntries);
    } catch { /* skip */ }
  }

  return combined;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  if (!asJson) {
    console.log(`
${color("  ╔══════════════════════════════════════════════╗", C.cyan, C.bold)}
${color("  ║      🛡️  LYRIE SECURITY VALIDATE             ║", C.cyan, C.bold)}
${color("  ║      CVE-Aware Provider + MCP Scanner        ║", C.cyan)}
${color("  ╚══════════════════════════════════════════════╝", C.cyan, C.bold)}
${color("  © OTT Cybersecurity LLC / Lyrie.ai", C.dim)}
`);
  }

  const config = loadConfig(configPath);
  const validator = new LyrieProviderValidator();
  const report = await validator.validateAll(config);

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.issueCount > 0 ? 1 : 0);
  }

  // Print human-readable report
  console.log(color(`  Scanned: ${report.totalProviders} provider(s), ${report.totalMcpServers} MCP server(s)`, C.dim));
  console.log(color(`  Issues:  ${report.issueCount}   Warnings: ${report.warningCount}\n`, C.dim));

  let hasFailOnSeverity = false;

  // Providers
  if (report.results.providers.length > 0) {
    console.log(color("  PROVIDERS", C.bold));
    for (const { name, result } of report.results.providers) {
      const icon = result.valid ? "✅" : "❌";
      console.log(`  ${icon} ${color(name, C.cyan)}`);
      for (const issue of result.issues) {
        console.log(`     ${color(`[${issue.severity.toUpperCase()}]`, issue.severity === "critical" ? C.red : C.yellow)} ${issue.cve}`);
        console.log(`     ${issue.message}`);
        console.log(`     Fix: ${color(issue.remediation, C.dim)}`);
        if (failOnSeverity && issue.severity === failOnSeverity) hasFailOnSeverity = true;
      }
      for (const w of result.warnings) {
        console.log(`     ${color("⚠", C.yellow)} ${w.message}`);
      }
    }
    console.log();
  }

  // MCP Servers
  if (report.results.mcpServers.length > 0) {
    console.log(color("  MCP SERVERS", C.bold));
    for (const { name, result } of report.results.mcpServers) {
      const icon = result.valid ? "✅" : "❌";
      console.log(`  ${icon} ${color(name, C.cyan)}`);
      for (const issue of result.issues) {
        console.log(`     ${color(`[${issue.severity.toUpperCase()}]`, issue.severity === "critical" ? C.red : C.yellow)} ${issue.cve}`);
        console.log(`     ${issue.message}`);
        console.log(`     Fix: ${color(issue.remediation, C.dim)}`);
        if (failOnSeverity && issue.severity === failOnSeverity) hasFailOnSeverity = true;
      }
      for (const w of result.warnings) {
        console.log(`     ${color("⚠", C.yellow)} ${w.message}`);
      }
    }
    console.log();
  }

  if (report.issueCount === 0) {
    console.log(color("  ✅ All providers and MCP servers passed security validation.\n", C.green, C.bold));
  } else {
    console.log(color(`  ⚠️  ${report.issueCount} issue(s) found. Review above and remediate.\n`, C.yellow, C.bold));
  }

  if (hasFailOnSeverity) {
    console.error(color(`  ✗ --fail-on ${failOnSeverity}: exiting with error.\n`, C.red));
    process.exit(1);
  }

  process.exit(report.issueCount > 0 ? 1 : 0);
}

main().catch((err: Error) => {
  console.error(`Security validation crashed: ${err.message}`);
  process.exit(2);
});
