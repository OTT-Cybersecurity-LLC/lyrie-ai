/**
 * Lyrie Agent — Migrate from Hermes Agent (Nous Research)
 * 
 * Reads:
 *   ~/.hermes/config.json         — main config
 *   ~/.hermes/plugins/            — installed plugins/skills
 *   ~/.hermes/memory/             — memory store
 *   ~/.hermes/conversations/      — conversation history
 *   ~/.hermes/tools/              — custom tools
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync } from "fs";
import { homedir } from "os";
import { join, basename } from "path";
import type { MigrationResult, LyrieMemoryEntry, LyrieSkill } from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  safeReadText,
  writeJson,
  listDirs,
  listFiles,
  MigrationLogger,
  uuidv4,
  truncate,
} from "./utils";

const HERMES_DIR = join(homedir(), ".hermes");

export function detectHermes(): boolean {
  return (
    existsSync(HERMES_DIR) &&
    (existsSync(join(HERMES_DIR, "config.json")) ||
      existsSync(join(HERMES_DIR, "plugins")) ||
      existsSync(join(HERMES_DIR, "memory")))
  );
}

export async function migrateFromHermes(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("hermes", ctx.verbose);
  console.log("\n🤖 Migrating from Hermes Agent...");

  const manifest: MigrationResult["manifest"] = {};

  // ── 1. Config ──────────────────────────────────────────────────────────────
  log.step("Reading Hermes config...");
  const hermesConfig = safeReadJson<Record<string, unknown>>(
    join(HERMES_DIR, "config.json")
  );

  if (hermesConfig) {
    const lyrieConfig = {
      version: "0.1.0",
      agent: {
        name: "Lyrie Agent",
        defaultModel: (hermesConfig.model as string) ??
          (hermesConfig.defaultModel as string) ??
          undefined,
      },
      migrated: {
        from: "hermes",
        at: new Date().toISOString(),
      },
    };
    writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
    log.ok("Config imported");
    manifest.config = true;
  } else {
    log.skip("No config.json found");
    manifest.config = false;
  }

  // ── 2. Plugins → Skills ────────────────────────────────────────────────────
  log.step("Importing plugins...");
  const skills: LyrieSkill[] = [];
  const pluginsDir = join(HERMES_DIR, "plugins");

  if (existsSync(pluginsDir)) {
    // Plugins can be dirs or JSON files
    const pluginNames = listDirs(pluginsDir);
    for (const name of pluginNames) {
      const pluginDir = join(pluginsDir, name);
      const meta = safeReadJson<Record<string, unknown>>(
        join(pluginDir, "plugin.json")
      ) ?? safeReadJson<Record<string, unknown>>(join(pluginDir, "package.json"));

      skills.push({
        name,
        description: (meta?.description as string) ?? "",
        source: "hermes",
        path: pluginDir,
        enabled: (meta?.enabled as boolean) ?? true,
        config: (meta?.config as Record<string, unknown>) ?? undefined,
      });
      log.ok(`Plugin: ${name}`);
    }

    // Also check for flat JSON plugin files
    const pluginFiles = listFiles(pluginsDir, ".json");
    for (const file of pluginFiles) {
      const plugin = safeReadJson<Record<string, unknown>>(file);
      if (!plugin) continue;
      const name = basename(file, ".json");
      if (pluginNames.includes(name)) continue; // already handled

      skills.push({
        name,
        description: (plugin.description as string) ?? "",
        source: "hermes",
        enabled: (plugin.enabled as boolean) ?? true,
        config: (plugin.config as Record<string, unknown>) ?? undefined,
      });
      log.ok(`Plugin (file): ${name}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "skills", "hermes-plugins.json"),
    skills,
    ctx.dryRun
  );
  manifest.skills = skills.length;

  // ── 3. Memory ──────────────────────────────────────────────────────────────
  log.step("Importing memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];
  const memDir = join(HERMES_DIR, "memory");

  if (existsSync(memDir)) {
    // memory.json (flat store)
    const flatMem = safeReadJson<unknown[]>(join(memDir, "memory.json"));
    if (Array.isArray(flatMem)) {
      for (const item of flatMem) {
        const m = item as Record<string, unknown>;
        memoryEntries.push({
          id: (m.id as string) ?? uuidv4(),
          category: (m.type as LyrieMemoryEntry["category"]) ??
            (m.category as LyrieMemoryEntry["category"]) ??
            "fact",
          text: (m.content as string) ?? (m.text as string) ?? String(item),
          importance: (m.importance as number) ?? (m.weight as number) ?? 0.7,
          source: "hermes:memory",
          createdAt: (m.createdAt as string) ?? (m.timestamp as string) ?? new Date().toISOString(),
          tags: (m.tags as string[]) ?? [],
        });
      }
      log.ok(`memory.json: ${flatMem.length} entries`);
    }

    // memory/*.json (vector store entries)
    const memFiles = listFiles(memDir, ".json").filter(
      (f) => basename(f) !== "memory.json"
    );
    for (const file of memFiles) {
      const data = safeReadJson<Record<string, unknown>>(file);
      if (!data) continue;

      const text = (data.content as string) ?? (data.text as string) ?? JSON.stringify(data);
      memoryEntries.push({
        id: (data.id as string) ?? uuidv4(),
        category: (data.category as LyrieMemoryEntry["category"]) ?? "fact",
        text,
        importance: (data.importance as number) ?? 0.6,
        source: `hermes:memory/${basename(file)}`,
        createdAt: (data.createdAt as string) ?? new Date().toISOString(),
      });
      log.ok(`Memory: ${truncate(text, 50)}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "memory", "hermes-import.json"),
    memoryEntries,
    ctx.dryRun
  );
  manifest.memory = memoryEntries.length;

  // ── 4. Conversations ───────────────────────────────────────────────────────
  log.step("Importing conversations...");
  const convsDir = join(HERMES_DIR, "conversations");
  let convCount = 0;

  if (existsSync(convsDir)) {
    const convFiles = listFiles(convsDir, ".json");
    for (const file of convFiles) {
      const conv = safeReadJson<Record<string, unknown>>(file);
      if (!conv) continue;

      // Store conversations as-is for historical reference
      writeJson(
        join(ctx.lyrieDir, "conversations", `hermes-${basename(file)}`),
        conv,
        ctx.dryRun
      );
      convCount++;
      log.ok(`Conversation: ${basename(file)}`);
    }
  }

  manifest.conversations = convCount;

  // ── 5. Tools ───────────────────────────────────────────────────────────────
  log.step("Importing tools...");
  const toolsDir = join(HERMES_DIR, "tools");
  let toolCount = 0;

  if (existsSync(toolsDir)) {
    const toolFiles = listFiles(toolsDir);
    for (const file of toolFiles) {
      const content = safeReadText(file);
      if (!content) continue;

      writeText(
        join(ctx.lyrieDir, "tools", `hermes-${basename(file)}`),
        content,
        ctx.dryRun
      );
      toolCount++;
      log.ok(`Tool: ${basename(file)}`);
    }
  }

  manifest.tools = toolCount;

  const errors = log.getErrors();
  return {
    platform: "hermes",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
