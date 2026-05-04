/**
 * Lyrie Agent — Migrate from OpenClaw
 * 
 * Reads:
 *   ~/.openclaw/openclaw.json         — main config
 *   ~/.openclaw/workspace/MEMORY.md   — memory (markdown)
 *   ~/.openclaw/workspace/skills/     — installed skills
 *   ~/.openclaw/crons.json            — cron jobs
 *   ~/.openclaw/channels/             — channel configs (Telegram, etc.)
 *   ~/.openclaw/memory/               — structured memory entries
 *
 * Supports selective migration via ctx.only:
 *   "memory"   — import only memory entries
 *   "skills"   — import only skills
 *   "crons"    — import only cron jobs
 *   "channels" — import only channel configs
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readdirSync } from "fs";
import { homedir } from "os";
import { join, basename } from "path";
import type {
  MigrationResult,
  LyrieConfig,
  LyrieMemoryEntry,
  LyrieSkill,
  LyrieCronJob,
} from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  safeReadText,
  writeJson,
  writeText,
  listDirs,
  listFiles,
  MigrationLogger,
  uuidv4,
} from "./utils";

const OPENCLAW_DIR = join(homedir(), ".openclaw");
const WORKSPACE_DIR = join(OPENCLAW_DIR, "workspace");

export function detectOpenClaw(): boolean {
  return (
    existsSync(OPENCLAW_DIR) &&
    (existsSync(join(OPENCLAW_DIR, "openclaw.json")) ||
      existsSync(join(WORKSPACE_DIR, "MEMORY.md")) ||
      existsSync(join(WORKSPACE_DIR, "AGENTS.md")))
  );
}

export async function migrateFromOpenClaw(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("openclaw", ctx.verbose);
  const { only } = ctx as MigrationContext & { only?: string };

  // Determine which sections to run
  const runMemory  = !only || only === "memory";
  const runSkills  = !only || only === "skills";
  const runCrons   = !only || only === "crons";
  const runChannels = !only || only === "channels";
  const runConfig  = !only; // config always migrated on full run

  if (only) {
    console.log(`\n🦞 Migrating from OpenClaw (--only ${only})...`);
  } else {
    console.log("\n🦞 Migrating from OpenClaw...");
  }

  const manifest: MigrationResult["manifest"] = {};

  // ── 1. Config ──────────────────────────────────────────────────────────────
  log.step("Reading OpenClaw config...");
  const ocConfig = safeReadJson<Record<string, unknown>>(
    join(OPENCLAW_DIR, "openclaw.json")
  );

  const lyrieConfig: LyrieConfig = {
    version: "0.1.0",
    agent: {
      name: "Lyrie Agent",
      persona: extractPersona(ocConfig),
      defaultModel: extractDefaultModel(ocConfig),
    },
    migrated: {
      from: "openclaw",
      at: new Date().toISOString(),
      version: (ocConfig?.version as string) ?? "unknown",
    },
  };

  if (ocConfig) {
    log.ok(`Config loaded (version: ${ocConfig.version ?? "unknown"})`);
    manifest.config = true;
  } else {
    log.skip("No openclaw.json found, using defaults");
    manifest.config = false;
  }

  // ── 2. Channel configs ─────────────────────────────────────────────────────
  const channels: string[] = [];
  if (runChannels) {
  log.step("Reading channel configs...");
  const channelsDir = join(OPENCLAW_DIR, "channels");

  if (existsSync(channelsDir)) {
    const channelFiles = listFiles(channelsDir, ".json");
    for (const file of channelFiles) {
      const channelData = safeReadJson<Record<string, unknown>>(file);
      if (!channelData) continue;

      const channelName = basename(file, ".json");
      channels.push(channelName);

      // Write to lyrie channels dir
      writeJson(
        join(ctx.lyrieDir, "channels", `${channelName}.json`),
        channelData,
        ctx.dryRun
      );
      log.ok(`Channel: ${channelName}`);
    }
  }

  // Also check for Telegram token in main config
  if (ocConfig?.plugins) {
    const plugins = ocConfig.plugins as Record<string, unknown>;
    for (const [key, value] of Object.entries(plugins)) {
      if (key.toLowerCase().includes("telegram") || key.toLowerCase().includes("channel")) {
        channels.push(key);
        writeJson(
          join(ctx.lyrieDir, "channels", `${key}.json`),
          value,
          ctx.dryRun
        );
        log.ok(`Channel from config: ${key}`);
      }
    }
  }

  lyrieConfig.channels = channels.map((c) => ({ type: c }));
  manifest.channels = channels;
  } // end runChannels

  // ── 3. Memory — markdown workspace files ───────────────────────────────────
  if (runMemory) {
  log.step("Importing workspace memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];

  // MEMORY.md
  const memoryMd = safeReadText(join(WORKSPACE_DIR, "MEMORY.md"));
  if (memoryMd) {
    const lines = memoryMd.split("\n").filter((l) => l.trim().length > 0);
    for (const line of lines.slice(0, 500)) {
      memoryEntries.push({
        id: uuidv4(),
        category: "fact",
        text: line.replace(/^#+\s*/, "").trim(),
        importance: 0.7,
        source: "openclaw:MEMORY.md",
        createdAt: new Date().toISOString(),
      });
    }
    log.ok(`MEMORY.md: ${memoryEntries.length} lines imported`);
  }

  // USER.md
  const userMd = safeReadText(join(WORKSPACE_DIR, "USER.md"));
  if (userMd) {
    memoryEntries.push({
      id: uuidv4(),
      category: "entity",
      text: userMd,
      importance: 0.9,
      source: "openclaw:USER.md",
      createdAt: new Date().toISOString(),
      tags: ["user", "profile"],
    });
    log.ok("USER.md imported");
  }

  // SOUL.md / IDENTITY.md
  for (const file of ["SOUL.md", "IDENTITY.md", "AGENTS.md"]) {
    const content = safeReadText(join(WORKSPACE_DIR, file));
    if (content) {
      memoryEntries.push({
        id: uuidv4(),
        category: "preference",
        text: content,
        importance: 0.95,
        source: `openclaw:${file}`,
        createdAt: new Date().toISOString(),
        tags: ["identity", "system"],
      });
      log.ok(`${file} imported`);
    }
  }

  // ~/.openclaw/memory/*.json (structured memories)
  const ocMemDir = join(OPENCLAW_DIR, "memory");
  if (existsSync(ocMemDir)) {
    const memFiles = listFiles(ocMemDir, ".json");
    for (const file of memFiles) {
      const entries = safeReadJson<unknown[]>(file);
      if (Array.isArray(entries)) {
        for (const entry of entries) {
          const e = entry as Record<string, unknown>;
          memoryEntries.push({
            id: (e.id as string) ?? uuidv4(),
            category: (e.category as LyrieMemoryEntry["category"]) ?? "fact",
            text: (e.text as string) ?? String(e.content ?? ""),
            importance: (e.importance as number) ?? 0.7,
            source: `openclaw:memory/${basename(file)}`,
            createdAt: (e.createdAt as string) ?? new Date().toISOString(),
            tags: (e.tags as string[]) ?? [],
          });
        }
        log.ok(`Memory file ${basename(file)}: ${entries.length} entries`);
      }
    }
  }

  writeJson(
    join(ctx.lyrieDir, "memory", "openclaw-import.json"),
    memoryEntries,
    ctx.dryRun
  );
  manifest.memory = memoryEntries.length;
  } // end runMemory

  // ── 4. Skills ──────────────────────────────────────────────────────────────
  if (runSkills) {
  log.step("Importing skills...");
  const skills: LyrieSkill[] = [];

  const skillDirs = [
    join(OPENCLAW_DIR, "workspace", "skills"),
    join(WORKSPACE_DIR, "skills"),
  ];

  const seenSkills = new Set<string>();

  for (const skillsDir of skillDirs) {
    if (!existsSync(skillsDir)) continue;

    const skillNames = listDirs(skillsDir);
    for (const skillName of skillNames) {
      if (seenSkills.has(skillName)) continue;
      seenSkills.add(skillName);

      const skillDir = join(skillsDir, skillName);
      const skillMd = safeReadText(join(skillDir, "SKILL.md"));
      const skillPkg = safeReadJson<Record<string, unknown>>(
        join(skillDir, "package.json")
      );

      // Extract description from SKILL.md
      let description = "";
      if (skillMd) {
        const firstLine = skillMd.split("\n").find((l) => l.trim().length > 0) ?? "";
        description = firstLine.replace(/^#+\s*/, "").trim();
      }

      skills.push({
        name: skillName,
        description: description || (skillPkg?.description as string) || "",
        source: "openclaw",
        path: skillDir,
        enabled: true,
        config: safeReadJson(join(skillDir, "config.json")) ?? undefined,
      });

      log.ok(`Skill: ${skillName}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "skills", "openclaw-skills.json"),
    skills,
    ctx.dryRun
  );
  manifest.skills = skills.length;
  } // end runSkills

  // ── 5. Cron jobs ───────────────────────────────────────────────────────────
  if (runCrons) {
  log.step("Importing cron jobs...");
  const cronJobs: LyrieCronJob[] = [];

  // Try crons.json
  const cronsJson = safeReadJson<unknown[]>(join(OPENCLAW_DIR, "crons.json"));
  if (Array.isArray(cronsJson)) {
    for (const cron of cronsJson) {
      const c = cron as Record<string, unknown>;
      cronJobs.push({
        name: (c.name as string) ?? "Unnamed cron",
        schedule: (c.schedule as string) ?? (c.cron as string) ?? "0 * * * *",
        task: (c.task as string) ?? (c.command as string) ?? "",
        model: (c.model as string) ?? undefined,
        enabled: (c.enabled as boolean) ?? true,
      });
    }
    log.ok(`${cronJobs.length} cron jobs imported from crons.json`);
  }

  // Also check workspace AGENTS.md for cron patterns
  const agentsMd = safeReadText(join(WORKSPACE_DIR, "AGENTS.md"));
  if (agentsMd && cronJobs.length === 0) {
    // Parse cron table from markdown
    const cronMatches = agentsMd.matchAll(
      /(\d{1,2}(?::\d{2})?\s*(?:AM|PM)|Every\s+\w+|\d+h|\d+\s*min)[^|]*\|[^|]*([^\n]+)/gi
    );
    for (const match of cronMatches) {
      const line = match[0];
      if (line.includes("|")) {
        const parts = line.split("|").map((s) => s.trim());
        if (parts.length >= 2 && parts[0] && parts[1]) {
          cronJobs.push({
            name: parts[1] ?? "Cron job",
            schedule: parts[0],
            task: parts[2] ?? parts[1] ?? "",
            enabled: true,
          });
        }
      }
    }
    if (cronJobs.length > 0) {
      log.ok(`${cronJobs.length} cron jobs parsed from AGENTS.md`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "config", "crons.json"),
    cronJobs,
    ctx.dryRun
  );
  manifest.cronJobs = cronJobs.length;
  } // end runCrons

  // ── 6. Write final config ──────────────────────────────────────────────────
  if (runConfig) {
  writeJson(
    join(ctx.lyrieDir, "config", "lyrie.json"),
    lyrieConfig,
    ctx.dryRun
  );
  } // end runConfig

  const totalErrors = log.getErrors();
  const success = totalErrors.length === 0;

  return {
    platform: "openclaw",
    success,
    itemsMigrated: log.getCount(),
    errors: totalErrors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractPersona(config: Record<string, unknown> | null): string | undefined {
  if (!config) return undefined;
  return (config.persona as string) ??
    (config.agent as Record<string, unknown>)?.persona as string ??
    undefined;
}

function extractDefaultModel(config: Record<string, unknown> | null): string | undefined {
  if (!config) return undefined;
  const agents = config.agents as Record<string, unknown> | undefined;
  if (agents?.defaultModel) return agents.defaultModel as string;
  return (config.defaultModel as string) ?? undefined;
}
