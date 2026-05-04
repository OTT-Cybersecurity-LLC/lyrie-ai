#!/usr/bin/env bun
/**
 * Lyrie Agent — Init Wizard
 *
 * Sets up ~/.lyrie/ directory structure, optionally migrates from OpenClaw,
 * and prepares the agent for first run.
 *
 * Usage:
 *   bun run scripts/init.ts
 *   bun run scripts/init.ts --migrate-from openclaw
 *   bun run scripts/init.ts --migrate-from openclaw --dry-run
 *   bun run scripts/init.ts --telegram-token <TOKEN>
 *   bun run scripts/init.ts --dir /opt/lyrie
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";

// ─── ANSI ─────────────────────────────────────────────────────────────────────
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
  blue: "\x1b[34m",
};

function c(str: string, ...codes: string[]): string {
  return codes.join("") + str + C.reset;
}

// ─── Banner ───────────────────────────────────────────────────────────────────
function printBanner(): void {
  console.log(`
${c("  ╔═══════════════════════════════════════════════╗", C.cyan, C.bold)}
${c("  ║        🛡️  LYRIE AGENT — SETUP WIZARD          ║", C.cyan, C.bold)}
${c("  ║   The world's first autonomous AI cybersecurity ║", C.cyan)}
${c("  ╚═══════════════════════════════════════════════╝", C.cyan, C.bold)}
${c("  © OTT Cybersecurity LLC / Lyrie.ai", C.dim)}
`);
}

// ─── Args ────────────────────────────────────────────────────────────────────
interface InitOptions {
  lyrieDir: string;
  migrateFrom: string | null;
  telegramToken: string | null;
  dryRun: boolean;
  verbose: boolean;
  help: boolean;
  skipDaemon: boolean;
}

function parseArgs(argv: string[]): InitOptions {
  const args = argv.slice(2);
  const opts: InitOptions = {
    lyrieDir: join(homedir(), ".lyrie"),
    migrateFrom: null,
    telegramToken: null,
    dryRun: false,
    verbose: false,
    help: false,
    skipDaemon: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--migrate-from":
        opts.migrateFrom = args[++i] ?? null;
        break;
      case "--telegram-token":
        opts.telegramToken = args[++i] ?? null;
        break;
      case "--dir":
        opts.lyrieDir = args[++i] ?? opts.lyrieDir;
        break;
      case "--dry-run":
      case "-n":
        opts.dryRun = true;
        break;
      case "--verbose":
      case "-v":
        opts.verbose = true;
        break;
      case "--skip-daemon":
        opts.skipDaemon = true;
        break;
      case "--help":
      case "-h":
        opts.help = true;
        break;
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`
${c("USAGE", C.bold, C.white)}
  bun run scripts/init.ts [options]

${c("OPTIONS", C.bold, C.white)}
  ${c("--migrate-from <platform>", C.cyan)}   Migrate from platform (e.g. openclaw)
  ${c("--telegram-token <token>", C.cyan)}    Set Telegram bot token
  ${c("--dir <path>", C.cyan)}                Output directory (default: ~/.lyrie)
  ${c("--dry-run", C.cyan)}                   Preview without writing
  ${c("--verbose", C.cyan)}                   Show detailed output
  ${c("--skip-daemon", C.cyan)}               Don't start lyrie daemon
  ${c("--help", C.cyan)}                      Show this help

${c("EXAMPLES", C.bold, C.white)}
  ${c("# Interactive setup", C.dim)}
  bun run scripts/init.ts

  ${c("# Migrate from OpenClaw in one command", C.dim)}
  bun run scripts/init.ts --migrate-from openclaw

  ${c("# Dry run to preview what init would do", C.dim)}
  bun run scripts/init.ts --migrate-from openclaw --dry-run
`);
}

// ─── Directory structure ─────────────────────────────────────────────────────
const LYRIE_DIRS = [
  "",           // root ~/.lyrie
  "memory",
  "skills",
  "config",
  "channels",
  "migrations",
  "workspace",
  "logs",
  "backups",
];

function ensureLyrieStructure(lyrieDir: string, dryRun: boolean): void {
  for (const sub of LYRIE_DIRS) {
    const dir = sub ? join(lyrieDir, sub) : lyrieDir;
    if (!existsSync(dir)) {
      if (!dryRun) {
        mkdirSync(dir, { recursive: true });
      }
      console.log(`  ${c("✓", C.green)} Created: ${dir}`);
    } else {
      console.log(`  ${c("-", C.dim)} Exists:  ${dir}`);
    }
  }
}

// ─── Config ──────────────────────────────────────────────────────────────────
interface LyrieInitConfig {
  version: string;
  initializedAt: string;
  agent: {
    name: string;
    defaultModel: string;
  };
  channels: { type: string; token?: string }[];
  migrated?: {
    from: string;
    at: string;
  };
}

function writeInitConfig(
  lyrieDir: string,
  config: LyrieInitConfig,
  dryRun: boolean
): void {
  const configPath = join(lyrieDir, "config", "lyrie.json");
  if (!dryRun) {
    // Don't overwrite if already exists (migration may have written it)
    if (!existsSync(configPath)) {
      mkdirSync(join(lyrieDir, "config"), { recursive: true });
      writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    }
  }
  console.log(`  ${c("✓", C.green)} Config: ${configPath}`);
}

// ─── Telegram token detection ─────────────────────────────────────────────────
function detectTelegramToken(): string | null {
  // Check ~/.openclaw/openclaw.json
  const ocConfig = join(homedir(), ".openclaw", "openclaw.json");
  if (existsSync(ocConfig)) {
    try {
      const raw = JSON.parse(readFileSync(ocConfig, "utf8"));

      // Common paths where token might live
      const candidates = [
        raw?.channels?.telegram?.token,
        raw?.plugins?.telegram?.token,
        raw?.telegram?.token,
        raw?.telegramToken,
      ];

      for (const candidate of candidates) {
        if (typeof candidate === "string" && candidate.length > 20) {
          return candidate;
        }
      }
    } catch {
      // Ignore
    }
  }

  // Check environment
  if (process.env.TELEGRAM_BOT_TOKEN) {
    return process.env.TELEGRAM_BOT_TOKEN;
  }

  return null;
}

// ─── Daemon stub ─────────────────────────────────────────────────────────────
async function startDaemon(lyrieDir: string, dryRun: boolean): Promise<void> {
  if (dryRun) {
    console.log(`  ${c("⟶", C.dim)}  [DRY RUN] Would start lyrie daemon`);
    return;
  }

  // Check if daemon script exists
  const daemonScript = join(process.cwd(), "scripts", "daemon.ts");
  if (!existsSync(daemonScript)) {
    console.log(`  ${c("⚠", C.yellow)}  Daemon script not found at ${daemonScript}`);
    console.log(`  ${c("-", C.dim)}  Start manually: bun run start`);
    return;
  }

  console.log(`  ${c("⟶", C.dim)}  Daemon ready. Run: ${c("bun run scripts/daemon.ts", C.cyan)}`);
}

// ─── Main ────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const opts = parseArgs(process.argv);

  printBanner();

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  if (opts.dryRun) {
    console.log(c("  [DRY RUN] — No files will be written\n", C.yellow, C.bold));
  }

  // ── Step 1: Create directory structure ─────────────────────────────────────
  console.log(c("\n── Step 1: Create ~/.lyrie directory structure ──", C.cyan, C.bold));
  ensureLyrieStructure(opts.lyrieDir, opts.dryRun);

  // ── Step 2: Telegram token ─────────────────────────────────────────────────
  console.log(c("\n── Step 2: Telegram configuration ──", C.cyan, C.bold));
  let telegramToken = opts.telegramToken;

  if (!telegramToken) {
    telegramToken = detectTelegramToken();
    if (telegramToken) {
      console.log(`  ${c("✓", C.green)} Telegram token detected from OpenClaw config`);
    } else {
      console.log(`  ${c("⚠", C.yellow)}  No Telegram token found.`);
      console.log(
        `  ${c("-", C.dim)}  Set it later: edit ~/.lyrie/channels/telegram.json\n` +
        `  ${c("-", C.dim)}  or pass: --telegram-token <YOUR_BOT_TOKEN>`
      );
    }
  }

  // Write channel config
  if (telegramToken && !opts.dryRun) {
    const channelPath = join(opts.lyrieDir, "channels", "telegram.json");
    if (!existsSync(channelPath)) {
      writeFileSync(
        channelPath,
        JSON.stringify({ type: "telegram", token: telegramToken }, null, 2) + "\n"
      );
      console.log(`  ${c("✓", C.green)} Wrote: ${channelPath}`);
    }
  }

  // ── Step 3: Migration ──────────────────────────────────────────────────────
  if (opts.migrateFrom) {
    console.log(c(`\n── Step 3: Migrate from ${opts.migrateFrom} ──`, C.cyan, C.bold));

    const { runMigration } = await import(
      "../packages/core/src/migrate/index"
    );
    const platform = opts.migrateFrom as import("../packages/core/src/migrate/types").MigratorPlatform;

    try {
      const result = await runMigration(platform, {
        lyrieDir: opts.lyrieDir,
        dryRun: opts.dryRun,
        verbose: opts.verbose,
      });

      if (result.success) {
        console.log(`\n  ${c("✅ Migration complete!", C.green, C.bold)}`);

        const m = result.manifest;
        const parts: string[] = [];
        if (m.memory) parts.push(`${m.memory} memories`);
        if (m.skills) parts.push(`${m.skills} skills`);
        if (m.cronJobs) parts.push(`${m.cronJobs} crons`);
        if (m.channels?.length) parts.push(`${m.channels.length} channels`);

        if (parts.length) {
          console.log(`  ${c("Imported:", C.dim)} ${parts.join(", ")}`);
        }
      } else {
        console.log(`\n  ${c("⚠ Migration completed with errors:", C.yellow)}`);
        for (const err of result.errors) {
          console.log(`     · ${err}`);
        }
      }
    } catch (err: any) {
      console.error(`\n  ${c("✗ Migration failed:", C.red)} ${err?.message}`);
    }
  } else {
    console.log(c("\n── Step 3: Migration (skipped — no --migrate-from) ──", C.dim));
    console.log(`  ${c("-", C.dim)}  Migrate later: bun run scripts/migrate.ts --from openclaw`);
  }

  // ── Step 4: Write base config ──────────────────────────────────────────────
  console.log(c("\n── Step 4: Write base config ──", C.cyan, C.bold));
  const initConfig: LyrieInitConfig = {
    version: "0.1.0",
    initializedAt: new Date().toISOString(),
    agent: {
      name: "Lyrie Agent",
      defaultModel: "anthropic/claude-sonnet-4-6",
    },
    channels: telegramToken ? [{ type: "telegram", token: telegramToken }] : [],
    ...(opts.migrateFrom
      ? { migrated: { from: opts.migrateFrom, at: new Date().toISOString() } }
      : {}),
  };
  writeInitConfig(opts.lyrieDir, initConfig, opts.dryRun);

  // ── Step 5: Daemon ─────────────────────────────────────────────────────────
  if (!opts.skipDaemon) {
    console.log(c("\n── Step 5: Start daemon ──", C.cyan, C.bold));
    await startDaemon(opts.lyrieDir, opts.dryRun);
  }

  // ── Done ───────────────────────────────────────────────────────────────────
  console.log(`
${c("  ═══════════════════════════════════════════════", C.cyan)}
  ${c("✅ Lyrie is ready!", C.green, C.bold)}

  Your Lyrie directory: ${c(opts.lyrieDir, C.white)}

  Next steps:
    ${c("1.", C.cyan)} Send a message to your Telegram bot to test
    ${c("2.", C.cyan)} bun run start          — start the agent
    ${c("3.", C.cyan)} bun run scripts/migrate.ts --from openclaw  — re-run migration
${c("  ═══════════════════════════════════════════════", C.cyan)}
`);

  if (opts.dryRun) {
    console.log(c("  [DRY RUN] — No files were actually written.", C.yellow));
  }
}

main().catch((err: Error) => {
  console.error(c(`\n✗ Init failed: ${err.message}`, C.red));
  if (process.env.DEBUG) console.error(err.stack);
  process.exit(1);
});
