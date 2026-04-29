/**
 * Lyrie Agent — Migration Coordinator
 * 
 * "Switch to Lyrie in one command."
 * 
 * Detects installed agent platforms and runs the appropriate migrator.
 * Supports: OpenClaw, Hermes, AutoGPT, NanoClaw, ZeroClaw, Dify,
 *           SuperAGI, Nanobot, grip-ai
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, mkdirSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { MigrationResult, MigratorPlatform } from "./types";

// Re-export migrators for programmatic use
export { migrateFromOpenClaw } from "./openclaw";
export { migrateFromHermes } from "./hermes";
export { migrateFromAutoGPT } from "./autogpt";
export { migrateFromNanoClaw } from "./nanoclaw";
export { migrateFromZeroClaw } from "./zeroclaw";
export { migrateFromDify } from "./dify";
export { migrateFromSuperAGI } from "./superagi";
export { migrateFromNanobot } from "./nanobot";
export { migrateFromGripAI } from "./grip-ai";
export { migrateFromClaudeCode } from "./claude-code";
export { migrateFromCursor } from "./cursor";
export type { MigrationResult, MigratorPlatform, MigrationContext } from "./types";

// ─────────────────────────────────────────────
//  Platform registry
// ─────────────────────────────────────────────

interface PlatformEntry {
  name: MigratorPlatform;
  label: string;
  detect: () => boolean;
  migrate: (ctx: MigrationRunContext) => Promise<MigrationResult>;
}

export interface MigrationRunContext {
  lyrieDir: string;
  dryRun: boolean;
  verbose: boolean;
}

async function buildRegistry(): Promise<PlatformEntry[]> {
  const home = homedir();

  // Lazy-import migrators to keep startup fast
  const [
    { migrateFromOpenClaw, detectOpenClaw },
    { migrateFromHermes, detectHermes },
    { migrateFromAutoGPT, detectAutoGPT },
    { migrateFromNanoClaw, detectNanoClaw },
    { migrateFromZeroClaw, detectZeroClaw },
    { migrateFromDify, detectDify },
    { migrateFromSuperAGI, detectSuperAGI },
    { migrateFromNanobot, detectNanobot },
    { migrateFromGripAI, detectGripAI },
    { migrateFromClaudeCode, detectClaudeCode },
    { migrateFromCursor, detectCursor },
  ] = await Promise.all([
    import("./openclaw"),
    import("./hermes"),
    import("./autogpt"),
    import("./nanoclaw"),
    import("./zeroclaw"),
    import("./dify"),
    import("./superagi"),
    import("./nanobot"),
    import("./grip-ai"),
    import("./claude-code"),
    import("./cursor"),
  ]);

  return [
    {
      name: "openclaw" as MigratorPlatform,
      label: "OpenClaw",
      detect: detectOpenClaw,
      migrate: (ctx) => migrateFromOpenClaw(ctx),
    },
    {
      name: "hermes" as MigratorPlatform,
      label: "Hermes Agent",
      detect: detectHermes,
      migrate: (ctx) => migrateFromHermes(ctx),
    },
    {
      name: "autogpt" as MigratorPlatform,
      label: "AutoGPT",
      detect: detectAutoGPT,
      migrate: (ctx) => migrateFromAutoGPT(ctx),
    },
    {
      name: "nanoclaw" as MigratorPlatform,
      label: "NanoClaw",
      detect: detectNanoClaw,
      migrate: (ctx) => migrateFromNanoClaw(ctx),
    },
    {
      name: "zeroclaw" as MigratorPlatform,
      label: "ZeroClaw",
      detect: detectZeroClaw,
      migrate: (ctx) => migrateFromZeroClaw(ctx),
    },
    {
      name: "dify" as MigratorPlatform,
      label: "Dify",
      detect: detectDify,
      migrate: (ctx) => migrateFromDify(ctx),
    },
    {
      name: "superagi" as MigratorPlatform,
      label: "SuperAGI",
      detect: detectSuperAGI,
      migrate: (ctx) => migrateFromSuperAGI(ctx),
    },
    {
      name: "nanobot" as MigratorPlatform,
      label: "Nanobot",
      detect: detectNanobot,
      migrate: (ctx) => migrateFromNanobot(ctx),
    },
    {
      name: "grip-ai" as MigratorPlatform,
      label: "grip-ai",
      detect: detectGripAI,
      migrate: (ctx) => migrateFromGripAI(ctx),
    },
    {
      name: "claude-code" as MigratorPlatform,
      label: "Claude Code",
      detect: detectClaudeCode,
      migrate: (ctx) => migrateFromClaudeCode(ctx),
    },
    {
      name: "cursor" as MigratorPlatform,
      label: "Cursor",
      detect: detectCursor,
      migrate: (ctx) => migrateFromCursor(ctx),
    },
  ];
}

// ─────────────────────────────────────────────
//  Auto-detect installed platforms
// ─────────────────────────────────────────────

export async function detectInstalledPlatforms(): Promise<MigratorPlatform[]> {
  const registry = await buildRegistry();
  return registry
    .filter((p) => {
      try {
        return p.detect();
      } catch {
        return false;
      }
    })
    .map((p) => p.name);
}

// ─────────────────────────────────────────────
//  Run a single migration
// ─────────────────────────────────────────────

export async function runMigration(
  platform: MigratorPlatform,
  options: Partial<MigrationRunContext> = {}
): Promise<MigrationResult> {
  const lyrieDir = options.lyrieDir ?? join(homedir(), ".lyrie");
  const dryRun = options.dryRun ?? false;
  const verbose = options.verbose ?? false;

  const ctx: MigrationRunContext = { lyrieDir, dryRun, verbose };

  // Ensure ~/.lyrie exists
  if (!dryRun) {
    ensureLyrieDir(lyrieDir);
  }

  const registry = await buildRegistry();
  const entry = registry.find((p) => p.name === platform);

  if (!entry) {
    return {
      platform,
      success: false,
      itemsMigrated: 0,
      errors: [`Unknown platform: ${platform}`],
      warnings: [],
      manifest: {},
      duration: 0,
    };
  }

  const start = Date.now();

  try {
    const result = await entry.migrate(ctx);
    result.duration = Date.now() - start;

    // Write migration manifest
    if (!dryRun && result.success) {
      writeMigrationManifest(lyrieDir, result);
    }

    return result;
  } catch (err: any) {
    return {
      platform,
      success: false,
      itemsMigrated: 0,
      errors: [`Migration failed: ${err?.message ?? String(err)}`],
      warnings: [],
      manifest: {},
      duration: Date.now() - start,
    };
  }
}

// ─────────────────────────────────────────────
//  Run all detected migrations
// ─────────────────────────────────────────────

export async function runAllMigrations(
  options: Partial<MigrationRunContext> = {}
): Promise<Map<MigratorPlatform, MigrationResult>> {
  const platforms = await detectInstalledPlatforms();

  if (platforms.length === 0) {
    console.log("ℹ️  No supported agent platforms detected.");
    return new Map();
  }

  const results = new Map<MigratorPlatform, MigrationResult>();

  for (const platform of platforms) {
    const result = await runMigration(platform, options);
    results.set(platform, result);
  }

  return results;
}

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

function ensureLyrieDir(lyrieDir: string): void {
  const dirs = [
    lyrieDir,
    join(lyrieDir, "memory"),
    join(lyrieDir, "skills"),
    join(lyrieDir, "config"),
    join(lyrieDir, "channels"),
    join(lyrieDir, "migrations"),
  ];

  for (const dir of dirs) {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }
}

function writeMigrationManifest(lyrieDir: string, result: MigrationResult): void {
  const manifestPath = join(
    lyrieDir,
    "migrations",
    `${result.platform}-${Date.now()}.json`
  );

  writeFileSync(
    manifestPath,
    JSON.stringify(
      {
        ...result,
        migratedAt: new Date().toISOString(),
        lyrieVersion: "0.1.0",
      },
      null,
      2
    )
  );
}

// ─────────────────────────────────────────────
//  List supported platforms
// ─────────────────────────────────────────────

export const SUPPORTED_PLATFORMS: MigratorPlatform[] = [
  "openclaw",
  "hermes",
  "autogpt",
  "nanoclaw",
  "zeroclaw",
  "dify",
  "superagi",
  "nanobot",
  "grip-ai",
  "claude-code",
  "cursor",
];
