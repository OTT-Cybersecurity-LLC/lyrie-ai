/**
 * Lyrie Agent — Migrate from Claude Code (claude_desktop_config.json)
 *
 * Reads:
 *   ~/.claude/claude_desktop_config.json — MCP servers + provider config
 *   ~/.claude/settings.json              — workspace settings
 *   ~/.claude/                           — local context files
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { MigrationResult } from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  writeJson,
  MigrationLogger,
} from "./utils";

const CLAUDE_DIR = join(homedir(), ".claude");
const DESKTOP_CONFIG = join(CLAUDE_DIR, "claude_desktop_config.json");
const SETTINGS_FILE = join(CLAUDE_DIR, "settings.json");

export function detectClaudeCode(): boolean {
  return existsSync(CLAUDE_DIR) && existsSync(DESKTOP_CONFIG);
}

export async function migrateFromClaudeCode(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("claude-code", ctx.verbose);
  const errors: string[] = [];
  const warnings: string[] = [];
  let itemsMigrated = 0;

  const manifest: Record<string, unknown> = {};

  // ── 1. Read claude_desktop_config.json ──────────────────────────────────────
  const desktopConfig = safeReadJson<any>(DESKTOP_CONFIG);

  if (!desktopConfig) {
    errors.push(`Could not read ${DESKTOP_CONFIG}`);
    return {
      platform: "claude-code",
      success: false,
      itemsMigrated: 0,
      errors,
      warnings,
      manifest,
      duration: 0,
    };
  }

  log("Loaded claude_desktop_config.json");

  // ── 2. Import MCP servers ────────────────────────────────────────────────────
  const mcpServers: Record<string, any> = desktopConfig.mcpServers ?? {};
  const importedMcpServers: any[] = [];

  for (const [name, serverConfig] of Object.entries(mcpServers)) {
    log(`  → MCP server: ${name}`);
    importedMcpServers.push({
      name,
      command: serverConfig.command,
      args: serverConfig.args ?? [],
      env: serverConfig.env ?? {},
    });
    itemsMigrated++;
  }

  manifest.mcpServers = importedMcpServers.length;

  // ── 3. Import provider API keys ──────────────────────────────────────────────
  const providers: any[] = [];
  const providerKeys: Record<string, string> = {
    anthropicApiKey: "anthropic",
    openaiApiKey: "openai",
    googleApiKey: "google",
  };

  for (const [configKey, providerName] of Object.entries(providerKeys)) {
    const value = desktopConfig[configKey] ?? desktopConfig.env?.[configKey.toUpperCase()];
    if (value) {
      log(`  → Provider key: ${providerName}`);
      providers.push({ name: providerName, apiKey: value });
      itemsMigrated++;
    }
  }

  manifest.providers = providers.length;

  // ── 4. Import settings ───────────────────────────────────────────────────────
  const settings = safeReadJson<any>(SETTINGS_FILE) ?? {};
  let model = settings.defaultModel ?? desktopConfig.defaultModel ?? null;

  // ── 5. Write Lyrie config ────────────────────────────────────────────────────
  if (!ctx.dryRun) {
    const lyrieConfig: any = {
      migratedFrom: "claude-code",
      migratedAt: new Date().toISOString(),
      mcpServers: importedMcpServers,
      providers,
    };

    if (model) lyrieConfig.defaultModel = model;

    writeJson(join(ctx.lyrieDir, "config", "claude-code-migration.json"), lyrieConfig);
    log("Wrote config/claude-code-migration.json");
  }

  return {
    platform: "claude-code",
    success: errors.length === 0,
    itemsMigrated,
    errors,
    warnings,
    manifest,
    duration: 0,
  };
}
