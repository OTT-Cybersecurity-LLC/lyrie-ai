#!/usr/bin/env bun
/**
 * Lyrie Agent — Migration CLI
 * 
 * "Switch to Lyrie in one command."
 * 
 * Usage:
 *   bun run scripts/migrate.ts --from openclaw
 *   bun run scripts/migrate.ts --from all
 *   bun run scripts/migrate.ts --detect
 *   bun run scripts/migrate.ts --from hermes --dry-run
 *   bun run scripts/migrate.ts --from dify --verbose
 *   bun run scripts/migrate.ts --list
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { homedir } from "os";
import { join } from "path";
import {
  runMigration,
  runAllMigrations,
  detectInstalledPlatforms,
  SUPPORTED_PLATFORMS,
  type MigrationRunContext,
} from "../packages/core/src/migrate/index";
import type { MigratorPlatform, MigrationResult } from "../packages/core/src/migrate/types";
import { LyrieProviderValidator } from "../packages/core/src/security/provider-validator";

// ─── ANSI colors ──────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  magenta: "\x1b[35m",
};

function color(str: string, ...codes: string[]): string {
  return codes.join("") + str + C.reset;
}

// ─── Banner ───────────────────────────────────────────────────────────────────
function printBanner(): void {
  console.log(`
${color("  ╔══════════════════════════════════════════════╗", C.cyan, C.bold)}
${color("  ║         🛡️  LYRIE AGENT — MIGRATION          ║", C.cyan, C.bold)}
${color("  ║     Switch to Lyrie in one command™           ║", C.cyan)}
${color("  ╚══════════════════════════════════════════════╝", C.cyan, C.bold)}
${color("  © OTT Cybersecurity LLC / Lyrie.ai", C.dim)}
`);
}

// ─── Argument parsing ─────────────────────────────────────────────────────────
function parseArgs(argv: string[]): {
  from: string | null;
  dryRun: boolean;
  verbose: boolean;
  detect: boolean;
  list: boolean;
  lyrieDir: string;
  help: boolean;
  secure: boolean;
} {
  const args = argv.slice(2);
  const result = {
    from: null as string | null,
    dryRun: false,
    verbose: false,
    detect: false,
    list: false,
    lyrieDir: join(homedir(), ".lyrie"),
    help: false,
    secure: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--from":
      case "-f":
        result.from = args[++i] ?? null;
        break;
      case "--dry-run":
      case "-n":
        result.dryRun = true;
        break;
      case "--verbose":
      case "-v":
        result.verbose = true;
        break;
      case "--detect":
      case "-d":
        result.detect = true;
        break;
      case "--list":
      case "-l":
        result.list = true;
        break;
      case "--dir":
        result.lyrieDir = args[++i] ?? result.lyrieDir;
        break;
      case "--secure":
      case "-s":
        result.secure = true;
        break;
      case "--help":
      case "-h":
        result.help = true;
        break;
    }
  }

  return result;
}

// ─── Help ─────────────────────────────────────────────────────────────────────
function printHelp(): void {
  console.log(`
${color("USAGE", C.bold, C.white)}
  bun run scripts/migrate.ts [options]

${color("OPTIONS", C.bold, C.white)}
  ${color("--from <platform>", C.cyan)}    Migrate from a specific platform (or "all")
  ${color("--detect", C.cyan)}             Auto-detect installed platforms
  ${color("--list", C.cyan)}               List all supported platforms
  ${color("--dry-run", C.cyan)}            Preview what would be migrated (no writes)
  ${color("--verbose", C.cyan)}            Show detailed progress
  ${color("--secure", C.cyan)}             Post-import Shield scan: API key scan + CVE-2026-7314/7315/7319 check
  ${color("--dir <path>", C.cyan)}         Output directory (default: ~/.lyrie)
  ${color("--help", C.cyan)}               Show this help

${color("SUPPORTED PLATFORMS", C.bold, C.white)}
  ${SUPPORTED_PLATFORMS.join(", ")}

${color("EXAMPLES", C.bold, C.white)}
  ${color("# Migrate from OpenClaw", C.dim)}
  bun run scripts/migrate.ts --from openclaw

  ${color("# Migrate from Claude Code with security scan", C.dim)}
  bun run scripts/migrate.ts --from claude-code --secure

  ${color("# Migrate from Cursor", C.dim)}
  bun run scripts/migrate.ts --from cursor --dry-run

  ${color("# Migrate from everything detected", C.dim)}
  bun run scripts/migrate.ts --from all

  ${color("# See what would be imported without writing", C.dim)}
  bun run scripts/migrate.ts --from hermes --dry-run

  ${color("# Verbose migration to custom dir", C.dim)}
  bun run scripts/migrate.ts --from autogpt --verbose --dir /opt/lyrie

  ${color("# Post-import Shield scan (CVE check + API key scan)", C.dim)}
  bun run scripts/migrate.ts --from openclaw --secure
`);
}

// ─── Result display ───────────────────────────────────────────────────────────
function printResult(result: MigrationResult): void {
  const icon = result.success ? "✅" : "❌";
  const statusColor = result.success ? C.green : C.red;

  console.log(`\n${color("─".repeat(50), C.dim)}`);
  console.log(
    `${icon} ${color(result.platform.toUpperCase(), C.bold)} — ` +
    color(result.success ? "SUCCESS" : "FAILED", statusColor, C.bold)
  );
  console.log(
    `   Items migrated: ${color(String(result.itemsMigrated), C.cyan, C.bold)} | ` +
    `Duration: ${color(result.duration + "ms", C.dim)}`
  );

  // Manifest summary
  const manifest = result.manifest;
  const parts: string[] = [];
  if (manifest.memory) parts.push(`${manifest.memory} memories`);
  if (manifest.skills) parts.push(`${manifest.skills} skills`);
  if (manifest.agents) parts.push(`${manifest.agents} agents`);
  if (manifest.tools) parts.push(`${manifest.tools} tools`);
  if (manifest.cronJobs) parts.push(`${manifest.cronJobs} crons`);
  if (manifest.channels?.length) parts.push(`${manifest.channels.length} channels`);
  if (manifest.workflows) parts.push(`${manifest.workflows} workflows`);
  if (manifest.datasets) parts.push(`${manifest.datasets} datasets`);
  if (manifest.conversations) parts.push(`${manifest.conversations} conversations`);

  if (parts.length > 0) {
    console.log(`   Imported: ${color(parts.join(", "), C.white)}`);
  }

  if (result.warnings.length > 0) {
    console.log(color(`\n   ⚠ Warnings (${result.warnings.length}):`, C.yellow));
    for (const w of result.warnings) {
      console.log(`     · ${w}`);
    }
  }

  if (result.errors.length > 0) {
    console.log(color(`\n   ✗ Errors (${result.errors.length}):`, C.red));
    for (const e of result.errors) {
      console.log(`     · ${e}`);
    }
  }
}

function printSummary(results: Map<MigratorPlatform, MigrationResult>): void {
  const all = [...results.values()];
  const succeeded = all.filter((r) => r.success).length;
  const totalItems = all.reduce((s, r) => s + r.itemsMigrated, 0);

  console.log(`\n${color("═".repeat(50), C.cyan)}`);
  console.log(color("  MIGRATION SUMMARY", C.bold, C.cyan));
  console.log(color("═".repeat(50), C.cyan));
  console.log(`  Platforms: ${succeeded}/${all.length} succeeded`);
  console.log(`  Total items: ${color(String(totalItems), C.cyan, C.bold)}`);
  console.log(`  Output: ${color(join(homedir(), ".lyrie"), C.white)}`);
  console.log(
    `\n  ${color("Your agent is ready. Run:", C.dim)} lyrie start\n`
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────
// ─── Secure post-import scan ─────────────────────────────────────────────────────

async function runSecureScan(lyrieDir: string): Promise<void> {
  console.log(color("\n🛡️  Running post-import security scan...", C.magenta, C.bold));

  // 1. Scan for API keys in migrated configs
  const configDir = join(lyrieDir, "config");
  const validator = new LyrieProviderValidator();
  let totalIssues = 0;
  let totalWarnings = 0;

  // Try to read any migration JSON files
  const { existsSync, readdirSync, readFileSync } = await import("fs");
  if (existsSync(configDir)) {
    const files = readdirSync(configDir).filter((f: string) => f.endsWith(".json"));
    for (const file of files) {
      try {
        const raw = JSON.parse(readFileSync(join(configDir, file), "utf-8"));

        // Check providers
        const providers = raw.providers ?? [];
        for (const p of providers) {
          const result = await validator.validateProvider(p);
          totalIssues += result.issues.length;
          totalWarnings += result.warnings.length;
          if (result.issues.length > 0) {
            console.log(color(`  ✗ ${p.name}: ${result.issues.length} security issue(s)`, C.red));
            for (const issue of result.issues) {
              console.log(`    [${issue.cve}] ${issue.message}`);
              console.log(`    Fix: ${issue.remediation}`);
            }
          }
        }

        // Check MCP servers against CVE-2026-7314/7315/7319
        const mcpServers = raw.mcpServers ?? [];
        for (const server of mcpServers) {
          const result = await validator.validateMcpServer(server);
          totalIssues += result.issues.length;
          totalWarnings += result.warnings.length;
          if (result.issues.length > 0) {
            console.log(color(`  ✗ MCP:${server.name}: ${result.issues.length} issue(s)`, C.red));
            for (const issue of result.issues) {
              console.log(`    [${issue.cve}] ${issue.message}`);
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
  }

  console.log();
  if (totalIssues === 0 && totalWarnings === 0) {
    console.log(color("  ✅ Security scan passed — no issues found.", C.green, C.bold));
  } else {
    if (totalIssues > 0) {
      console.log(color(`  ⚠️  ${totalIssues} security issue(s) found. Review above.", C.yellow, C.bold));
    }
    if (totalWarnings > 0) {
      console.log(color(`  ℹ️  ${totalWarnings} warning(s). Run with --verbose for details.`, C.dim));
    }
  }
  console.log();
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);

  printBanner();

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  if (opts.list) {
    console.log(color("Supported platforms:\n", C.bold));
    for (const p of SUPPORTED_PLATFORMS) {
      console.log(`  • ${color(p, C.cyan)}`);
    }
    console.log();
    process.exit(0);
  }

  const ctx: MigrationRunContext = {
    lyrieDir: opts.lyrieDir,
    dryRun: opts.dryRun,
    verbose: opts.verbose,
  };

  if (opts.secure) {
    console.log(color("  [SECURE] Post-import Shield scan enabled\n", C.magenta, C.bold));
  }

  if (opts.dryRun) {
    console.log(color("  [DRY RUN] — No files will be written\n", C.yellow, C.bold));
  }

  // ── Detect mode ──────────────────────────────────────────────────────────────
  if (opts.detect || !opts.from) {
    console.log("🔍 Detecting installed agent platforms...\n");
    const detected = await detectInstalledPlatforms();

    if (detected.length === 0) {
      console.log(color("  No supported platforms detected.\n", C.yellow));
      console.log(
        `  Supported: ${SUPPORTED_PLATFORMS.join(", ")}\n` +
        `  Use ${color("--from <platform>", C.cyan)} to migrate manually.\n`
      );
      process.exit(0);
    }

    console.log(`  Found: ${detected.map((p) => color(p, C.green)).join(", ")}\n`);

    if (opts.detect && !opts.from) {
      process.exit(0);
    }
  }

  // ── Migrate ──────────────────────────────────────────────────────────────────
  if (opts.from === "all") {
    console.log("🚀 Migrating from all detected platforms...\n");
    const results = await runAllMigrations(ctx);

    if (results.size === 0) {
      console.log(color("  Nothing to migrate.\n", C.yellow));
      process.exit(0);
    }

    for (const result of results.values()) {
      printResult(result);
    }

    printSummary(results);

  } else if (opts.from) {
    const platform = opts.from as MigratorPlatform;

    if (!SUPPORTED_PLATFORMS.includes(platform)) {
      console.error(
        color(`\n  ✗ Unknown platform: "${platform}"\n`, C.red) +
        `  Supported: ${SUPPORTED_PLATFORMS.join(", ")}\n`
      );
      process.exit(1);
    }

    console.log(`🚀 Migrating from ${color(platform, C.cyan, C.bold)}...\n`);
    const result = await runMigration(platform, ctx);
    printResult(result);

    // Final message
    console.log();
    if (result.success) {
      console.log(color("  ✅ Migration complete!", C.green, C.bold));
      console.log(
        `  Your data is in: ${color(opts.lyrieDir, C.white)}\n` +
        `  Start Lyrie: ${color("bun run start", C.cyan)}\n`
      );

      // --secure: run post-import CVE + API key scan
      if (opts.secure) {
        await runSecureScan(opts.lyrieDir);
      }
    } else {
      console.log(color("  ⚠ Migration completed with errors.", C.yellow));
      console.log("  Check the errors above and re-run with --verbose for details.\n");
      process.exit(1);
    }
  } else {
    // No --from specified
    printHelp();
    process.exit(0);
  }
}

main().catch((err: Error) => {
  console.error(color(`\n✗ Migration crashed: ${err.message}`, C.red));
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
