/**
 * Lyrie Agent — Migrate from Cursor
 *
 * Reads:
 *   ~/.cursor/settings.json       — workspace settings, model config
 *   ~/.cursor/extensions/         — installed extensions (skills equivalent)
 *   ~/.cursor/User/keybindings.json — keybindings (advisory only)
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { MigrationResult } from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  writeJson,
  MigrationLogger,
} from "./utils";

const CURSOR_DIR = join(homedir(), ".cursor");
const CURSOR_SETTINGS = join(CURSOR_DIR, "settings.json");

export function detectCursor(): boolean {
  return existsSync(CURSOR_DIR) && existsSync(CURSOR_SETTINGS);
}

export async function migrateFromCursor(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("cursor", ctx.verbose);
  const errors: string[] = [];
  const warnings: string[] = [];
  let itemsMigrated = 0;

  const manifest: Record<string, unknown> = {};

  // ── 1. Read settings.json ───────────────────────────────────────────────────
  const settings = safeReadJson<any>(CURSOR_SETTINGS);

  if (!settings) {
    errors.push(`Could not read ${CURSOR_SETTINGS}`);
    return {
      platform: "cursor",
      success: false,
      itemsMigrated: 0,
      errors,
      warnings,
      manifest,
      duration: 0,
    };
  }

  log("Loaded ~/.cursor/settings.json");

  // ── 2. Extract model configuration ──────────────────────────────────────────
  const modelConfig: Record<string, unknown> = {};

  const modelKeys = [
    "cursor.aiModel",
    "cursor.defaultModel",
    "cursor.preferredModel",
    "editor.defaultFormatter",
  ];

  for (const key of modelKeys) {
    if (settings[key] !== undefined) {
      const shortKey = key.replace(/^cursor\./, "");
      modelConfig[shortKey] = settings[key];
      itemsMigrated++;
      log(`  → Setting: ${key} = ${settings[key]}`);
    }
  }

  manifest.settings = Object.keys(modelConfig).length;

  // ── 3. Extract API keys ──────────────────────────────────────────────────────
  const providers: Array<{ name: string; apiKey: string }> = [];

  const keyMap: Record<string, string> = {
    "cursor.openaiApiKey": "openai",
    "cursor.anthropicApiKey": "anthropic",
    "openai.apiKey": "openai",
  };

  for (const [settingKey, providerName] of Object.entries(keyMap)) {
    if (settings[settingKey]) {
      providers.push({ name: providerName, apiKey: settings[settingKey] });
      itemsMigrated++;
      log(`  → Provider key: ${providerName}`);
    }
  }

  manifest.providers = providers.length;

  // ── 4. Scan extensions directory ────────────────────────────────────────────
  const extensionsDir = join(CURSOR_DIR, "extensions");
  const extensions: string[] = [];

  if (existsSync(extensionsDir)) {
    try {
      const dirs = readdirSync(extensionsDir, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name);
      extensions.push(...dirs);
      itemsMigrated += dirs.length;
      log(`  → Extensions: ${dirs.length}`);
    } catch {
      warnings.push("Could not read extensions directory");
    }
  }

  manifest.extensions = extensions.length;

  // ── 5. Write Lyrie config ────────────────────────────────────────────────────
  if (!ctx.dryRun) {
    const lyrieConfig: any = {
      migratedFrom: "cursor",
      migratedAt: new Date().toISOString(),
      modelConfig,
      providers,
      extensions,
    };

    writeJson(join(ctx.lyrieDir, "config", "cursor-migration.json"), lyrieConfig);
    log("Wrote config/cursor-migration.json");
  }

  return {
    platform: "cursor",
    success: errors.length === 0,
    itemsMigrated,
    errors,
    warnings,
    manifest,
    duration: 0,
  };
}
