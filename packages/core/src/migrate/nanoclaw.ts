/**
 * Lyrie Agent — Migrate from NanoClaw
 * 
 * Reads:
 *   ~/.nanoclaw/config.json        — main config
 *   ~/.nanoclaw/memory/            — memory entries
 *   ~/.nanoclaw/channels/          — channel configs
 *   ~/.nanoclaw/skills/            — installed skills
 *   ~/.nanoclaw/nanoclaw.json      — alternative config location
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync } from "fs";
import { homedir } from "os";
import { join, basename } from "path";
import type { MigrationResult, LyrieMemoryEntry, LyrieSkill, LyrieConfig } from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  safeReadText,
  writeJson,
  listDirs,
  listFiles,
  MigrationLogger,
  uuidv4,
} from "./utils";

const NANOCLAW_DIR = join(homedir(), ".nanoclaw");

export function detectNanoClaw(): boolean {
  return (
    existsSync(NANOCLAW_DIR) &&
    (existsSync(join(NANOCLAW_DIR, "config.json")) ||
      existsSync(join(NANOCLAW_DIR, "nanoclaw.json")) ||
      existsSync(join(NANOCLAW_DIR, "memory")) ||
      existsSync(join(NANOCLAW_DIR, "channels")))
  );
}

export async function migrateFromNanoClaw(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("nanoclaw", ctx.verbose);
  console.log("\n🔷 Migrating from NanoClaw...");

  const manifest: MigrationResult["manifest"] = {};

  // ── 1. Config ──────────────────────────────────────────────────────────────
  log.step("Reading NanoClaw config...");
  const config =
    safeReadJson<Record<string, unknown>>(join(NANOCLAW_DIR, "nanoclaw.json")) ??
    safeReadJson<Record<string, unknown>>(join(NANOCLAW_DIR, "config.json"));

  if (config) {
    const lyrieConfig: LyrieConfig = {
      version: "0.1.0",
      agent: {
        name: (config.agentName as string) ?? (config.name as string) ?? "Lyrie Agent",
        defaultModel: (config.model as string) ?? (config.defaultModel as string) ?? undefined,
        persona: (config.persona as string) ?? undefined,
      },
      migrated: {
        from: "nanoclaw",
        at: new Date().toISOString(),
        version: (config.version as string) ?? "unknown",
      },
    };

    // Preserve shield settings if present
    if (config.shield || config.security) {
      const shieldConfig = (config.shield ?? config.security) as Record<string, unknown>;
      lyrieConfig.shield = {
        enabled: (shieldConfig?.enabled as boolean) ?? true,
        level: (shieldConfig?.level as "passive" | "active" | "aggressive") ?? "passive",
      };
    }

    writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
    log.ok(`Config imported (model: ${lyrieConfig.agent.defaultModel ?? "default"})`);
    manifest.config = true;
  } else {
    log.skip("No config found, using defaults");
  }

  // ── 2. Memory ──────────────────────────────────────────────────────────────
  log.step("Importing memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];
  const memDir = join(NANOCLAW_DIR, "memory");

  if (existsSync(memDir)) {
    // Flat JSON
    const flatMem = safeReadJson<unknown[]>(join(memDir, "memories.json"));
    if (Array.isArray(flatMem)) {
      for (const item of flatMem) {
        const m = item as Record<string, unknown>;
        memoryEntries.push({
          id: (m.id as string) ?? uuidv4(),
          category: (m.category as LyrieMemoryEntry["category"]) ?? "fact",
          text: (m.text as string) ?? (m.content as string) ?? String(item),
          importance: (m.importance as number) ?? 0.7,
          source: "nanoclaw:memory",
          createdAt: (m.createdAt as string) ?? new Date().toISOString(),
          tags: (m.tags as string[]) ?? [],
        });
      }
      log.ok(`memories.json: ${flatMem.length} entries`);
    }

    // Per-file memories
    const memFiles = listFiles(memDir, ".json").filter(
      (f) => basename(f) !== "memories.json"
    );
    for (const file of memFiles) {
      const data = safeReadJson<unknown>(file);
      if (!data) continue;

      if (Array.isArray(data)) {
        for (const item of data) {
          const m = item as Record<string, unknown>;
          memoryEntries.push({
            id: (m.id as string) ?? uuidv4(),
            category: (m.category as LyrieMemoryEntry["category"]) ?? "fact",
            text: (m.text as string) ?? (m.content as string) ?? JSON.stringify(item),
            importance: (m.importance as number) ?? 0.6,
            source: `nanoclaw:${basename(file)}`,
            createdAt: (m.createdAt as string) ?? new Date().toISOString(),
          });
        }
        log.ok(`${basename(file)}: ${(data as unknown[]).length} entries`);
      }
    }

    // Markdown memory files
    const mdFiles = listFiles(memDir, ".md");
    for (const file of mdFiles) {
      const content = safeReadText(file);
      if (!content) continue;
      memoryEntries.push({
        id: uuidv4(),
        category: "fact",
        text: content,
        importance: 0.7,
        source: `nanoclaw:memory/${basename(file)}`,
        createdAt: new Date().toISOString(),
      });
      log.ok(`Memory (md): ${basename(file)}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "memory", "nanoclaw-import.json"),
    memoryEntries,
    ctx.dryRun
  );
  manifest.memory = memoryEntries.length;

  // ── 3. Channels ────────────────────────────────────────────────────────────
  log.step("Importing channel configs...");
  const channelsDir = join(NANOCLAW_DIR, "channels");
  const channels: string[] = [];

  if (existsSync(channelsDir)) {
    const channelFiles = listFiles(channelsDir, ".json");
    for (const file of channelFiles) {
      const channelData = safeReadJson<Record<string, unknown>>(file);
      if (!channelData) continue;

      const channelName = basename(file, ".json");
      channels.push(channelName);
      writeJson(
        join(ctx.lyrieDir, "channels", `${channelName}.json`),
        channelData,
        ctx.dryRun
      );
      log.ok(`Channel: ${channelName}`);
    }
  }

  // Check config for inline channel configs
  if (config?.channels && typeof config.channels === "object") {
    const configChannels = config.channels as Record<string, unknown>;
    for (const [name, data] of Object.entries(configChannels)) {
      if (!channels.includes(name)) {
        channels.push(name);
        writeJson(
          join(ctx.lyrieDir, "channels", `${name}.json`),
          data,
          ctx.dryRun
        );
        log.ok(`Channel (from config): ${name}`);
      }
    }
  }

  manifest.channels = channels;

  // ── 4. Skills ──────────────────────────────────────────────────────────────
  log.step("Importing skills...");
  const skills: LyrieSkill[] = [];
  const skillsDir = join(NANOCLAW_DIR, "skills");

  if (existsSync(skillsDir)) {
    const skillNames = listDirs(skillsDir);
    for (const name of skillNames) {
      const skillDir = join(skillsDir, name);
      const meta = safeReadJson<Record<string, unknown>>(join(skillDir, "SKILL.json")) ??
        safeReadJson<Record<string, unknown>>(join(skillDir, "package.json"));
      const skillMd = safeReadText(join(skillDir, "SKILL.md"));

      let description = "";
      if (skillMd) {
        description = skillMd.split("\n").find((l) => l.trim().length > 0)?.replace(/^#+\s*/, "") ?? "";
      }

      skills.push({
        name,
        description: description || (meta?.description as string) || "",
        source: "nanoclaw",
        path: skillDir,
        enabled: (meta?.enabled as boolean) ?? true,
      });
      log.ok(`Skill: ${name}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "skills", "nanoclaw-skills.json"),
    skills,
    ctx.dryRun
  );
  manifest.skills = skills.length;

  const errors = log.getErrors();
  return {
    platform: "nanoclaw",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
