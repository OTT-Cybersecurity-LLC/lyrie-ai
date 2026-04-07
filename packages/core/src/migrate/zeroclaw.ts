/**
 * Lyrie Agent — Migrate from ZeroClaw
 * 
 * Reads:
 *   ~/.zeroclaw/zeroclaw.json      — main config
 *   ~/.zeroclaw/config.json        — alternative config
 *   ~/.zeroclaw/memory/            — memory store
 *   ~/.zeroclaw/workspace/         — workspace files
 *   ~/.zeroclaw/channels/          — channel configs
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

const ZEROCLAW_DIR = join(homedir(), ".zeroclaw");

export function detectZeroClaw(): boolean {
  return (
    existsSync(ZEROCLAW_DIR) &&
    (existsSync(join(ZEROCLAW_DIR, "zeroclaw.json")) ||
      existsSync(join(ZEROCLAW_DIR, "config.json")) ||
      existsSync(join(ZEROCLAW_DIR, "memory")))
  );
}

export async function migrateFromZeroClaw(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("zeroclaw", ctx.verbose);
  console.log("\n⚡ Migrating from ZeroClaw...");

  const manifest: MigrationResult["manifest"] = {};

  // ── 1. Config ──────────────────────────────────────────────────────────────
  log.step("Reading ZeroClaw config...");
  const config =
    safeReadJson<Record<string, unknown>>(join(ZEROCLAW_DIR, "zeroclaw.json")) ??
    safeReadJson<Record<string, unknown>>(join(ZEROCLAW_DIR, "config.json"));

  if (config) {
    const lyrieConfig: LyrieConfig = {
      version: "0.1.0",
      agent: {
        name: (config.name as string) ?? (config.agentName as string) ?? "Lyrie Agent",
        defaultModel: (config.model as string) ??
          (config.defaultModel as string) ??
          undefined,
        persona: (config.persona as string) ??
          (config.systemPrompt as string) ??
          undefined,
      },
      migrated: {
        from: "zeroclaw",
        at: new Date().toISOString(),
        version: (config.version as string) ?? "unknown",
      },
    };

    // Migrate security/shield config
    if (config.shield) {
      const s = config.shield as Record<string, unknown>;
      lyrieConfig.shield = {
        enabled: (s.enabled as boolean) ?? true,
        level: (s.level as "passive" | "active" | "aggressive") ?? "passive",
      };
    }

    writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
    log.ok(`Config imported`);
    manifest.config = true;

    // Migrate providers/API config (non-sensitive)
    if (config.providers) {
      const safeProviders: Record<string, unknown> = {};
      const providers = config.providers as Record<string, unknown>;
      for (const [key, value] of Object.entries(providers)) {
        if (typeof value === "object" && value !== null) {
          const prov = value as Record<string, unknown>;
          // Strip API keys
          const { apiKey, api_key, secret, token, ...safe } = prov;
          safeProviders[key] = safe;
        }
      }
      writeJson(
        join(ctx.lyrieDir, "config", "providers.json"),
        safeProviders,
        ctx.dryRun
      );
      log.ok("Provider config imported (keys excluded)");
    }
  } else {
    log.skip("No config found");
  }

  // ── 2. Memory ──────────────────────────────────────────────────────────────
  log.step("Importing memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];
  const memDir = join(ZEROCLAW_DIR, "memory");

  if (existsSync(memDir)) {
    const memFiles = listFiles(memDir, ".json");
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
            importance: (m.importance as number) ?? 0.7,
            source: `zeroclaw:${basename(file)}`,
            createdAt: (m.createdAt as string) ?? new Date().toISOString(),
            tags: (m.tags as string[]) ?? [],
          });
        }
        log.ok(`${basename(file)}: ${(data as unknown[]).length} entries`);
      } else if (typeof data === "object" && data !== null) {
        memoryEntries.push({
          id: uuidv4(),
          category: "fact",
          text: JSON.stringify(data),
          importance: 0.6,
          source: `zeroclaw:${basename(file)}`,
          createdAt: new Date().toISOString(),
        });
        log.ok(`${basename(file)}: 1 entry`);
      }
    }

    // Markdown files in memory dir
    for (const file of listFiles(memDir, ".md")) {
      const content = safeReadText(file);
      if (!content) continue;
      memoryEntries.push({
        id: uuidv4(),
        category: "fact",
        text: content,
        importance: 0.7,
        source: `zeroclaw:memory/${basename(file)}`,
        createdAt: new Date().toISOString(),
      });
      log.ok(`Memory (md): ${basename(file)}`);
    }
  }

  // Workspace markdown files
  const workspaceDir = join(ZEROCLAW_DIR, "workspace");
  if (existsSync(workspaceDir)) {
    for (const file of listFiles(workspaceDir, ".md")) {
      const content = safeReadText(file);
      if (!content) continue;
      memoryEntries.push({
        id: uuidv4(),
        category: "preference",
        text: content,
        importance: 0.8,
        source: `zeroclaw:workspace/${basename(file)}`,
        createdAt: new Date().toISOString(),
        tags: ["workspace"],
      });
      log.ok(`Workspace: ${basename(file)}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "memory", "zeroclaw-import.json"),
    memoryEntries,
    ctx.dryRun
  );
  manifest.memory = memoryEntries.length;

  // ── 3. Channels ────────────────────────────────────────────────────────────
  log.step("Importing channel configs...");
  const channels: string[] = [];
  const channelsDir = join(ZEROCLAW_DIR, "channels");

  if (existsSync(channelsDir)) {
    for (const file of listFiles(channelsDir, ".json")) {
      const data = safeReadJson<Record<string, unknown>>(file);
      if (!data) continue;
      const name = basename(file, ".json");
      channels.push(name);
      writeJson(join(ctx.lyrieDir, "channels", `${name}.json`), data, ctx.dryRun);
      log.ok(`Channel: ${name}`);
    }
  }

  // Inline channels from config
  if (config?.channels && typeof config.channels === "object") {
    for (const [name, data] of Object.entries(config.channels as Record<string, unknown>)) {
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
  const skillsDir = join(ZEROCLAW_DIR, "skills");

  if (existsSync(skillsDir)) {
    for (const name of listDirs(skillsDir)) {
      const skillDir = join(skillsDir, name);
      const meta = safeReadJson<Record<string, unknown>>(join(skillDir, "package.json"));
      skills.push({
        name,
        description: (meta?.description as string) ?? "",
        source: "zeroclaw",
        path: skillDir,
        enabled: true,
      });
      log.ok(`Skill: ${name}`);
    }
  }

  if (skills.length > 0) {
    writeJson(
      join(ctx.lyrieDir, "skills", "zeroclaw-skills.json"),
      skills,
      ctx.dryRun
    );
  }
  manifest.skills = skills.length;

  const errors = log.getErrors();
  return {
    platform: "zeroclaw",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
