/**
 * Lyrie Agent — Migrate from Nanobot
 * 
 * Reads:
 *   nanobot.yaml          — project-level config (cwd)
 *   ~/nanobot.yaml        — home-level config
 *   ~/.nanobot/           — global config dir
 *   tools/*.py            — tool definitions
 *   agents/*.yaml         — agent definitions
 *   prompts/              — prompt templates
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync } from "fs";
import { homedir } from "os";
import { join, basename } from "path";
import type { MigrationResult, LyrieMemoryEntry, LyrieSkill, LyrieCronJob } from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  safeReadText,
  writeJson,
  listFiles,
  listDirs,
  MigrationLogger,
  uuidv4,
} from "./utils";

const HOME = homedir();
const NANOBOT_DIR = join(HOME, ".nanobot");

const NANOBOT_YAML_CANDIDATES = [
  join(process.cwd(), "nanobot.yaml"),
  join(process.cwd(), "nanobot.yml"),
  join(HOME, "nanobot.yaml"),
  join(HOME, "nanobot.yml"),
  join(NANOBOT_DIR, "nanobot.yaml"),
  join(NANOBOT_DIR, "config.yaml"),
].filter(existsSync);

export function detectNanobot(): boolean {
  return NANOBOT_YAML_CANDIDATES.length > 0 || existsSync(NANOBOT_DIR);
}

function parseNanobotYaml(content: string): Record<string, unknown> {
  /**
   * Parse Nanobot YAML config.
   * Nanobot uses a specific format:
   *   name: agent-name
   *   description: ...
   *   tools:
   *     - name: tool1
   *       ...
   *   agents:
   *     - name: agent1
   *       ...
   */
  const result: Record<string, unknown> = {};
  const lines = content.split("\n");
  let currentKey = "";
  let currentList: Record<string, unknown>[] = [];
  let currentListItem: Record<string, unknown> | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line.trim() || line.trim().startsWith("#")) continue;

    const indent = line.length - line.trimStart().length;

    // Top-level key: value
    if (indent === 0) {
      if (currentListItem) {
        currentList.push(currentListItem);
        currentListItem = null;
      }
      if (currentKey && currentList.length > 0) {
        result[currentKey] = currentList;
        currentList = [];
      }

      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim();

      if (!value) {
        currentKey = key;
      } else {
        result[key] = value.replace(/^["']|["']$/g, "");
      }
    } else if (indent === 2 && line.trim().startsWith("- ")) {
      // List item start
      if (currentListItem) currentList.push(currentListItem);
      currentListItem = {};
      const itemContent = line.trim().slice(2);
      const colonIdx = itemContent.indexOf(":");
      if (colonIdx !== -1) {
        const key = itemContent.slice(0, colonIdx).trim();
        const value = itemContent.slice(colonIdx + 1).trim();
        currentListItem[key] = value.replace(/^["']|["']$/g, "");
      }
    } else if (indent === 4 && currentListItem) {
      // Nested key in list item
      const colonIdx = line.indexOf(":");
      if (colonIdx !== -1) {
        const key = line.slice(0, colonIdx).trim();
        const value = line.slice(colonIdx + 1).trim();
        currentListItem[key] = value.replace(/^["']|["']$/g, "");
      }
    }
  }

  // Flush remaining
  if (currentListItem) currentList.push(currentListItem);
  if (currentKey && currentList.length > 0) result[currentKey] = currentList;

  return result;
}

export async function migrateFromNanobot(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("nanobot", ctx.verbose);
  console.log("\n🤖 Migrating from Nanobot...");

  const manifest: MigrationResult["manifest"] = {};

  // ── 1. Parse nanobot.yaml ──────────────────────────────────────────────────
  log.step("Reading nanobot.yaml...");
  let nanobotConfig: Record<string, unknown> = {};
  let configSource = "";

  for (const yamlPath of NANOBOT_YAML_CANDIDATES) {
    const raw = safeReadText(yamlPath);
    if (!raw) continue;
    nanobotConfig = parseNanobotYaml(raw);
    configSource = yamlPath;
    log.ok(`Loaded: ${yamlPath}`);
    break;
  }

  if (Object.keys(nanobotConfig).length === 0) {
    log.warn("No nanobot.yaml found or empty config");
  }

  // Build Lyrie config from Nanobot config
  const lyrieConfig = {
    version: "0.1.0",
    agent: {
      name: (nanobotConfig.name as string) ?? "Lyrie Agent",
      defaultModel: (nanobotConfig.model as string) ??
        (nanobotConfig.llm as string) ??
        undefined,
      persona: (nanobotConfig.description as string) ??
        (nanobotConfig.system_prompt as string) ??
        undefined,
    },
    migrated: {
      from: "nanobot",
      at: new Date().toISOString(),
      source: configSource,
    },
  };

  writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
  manifest.config = true;

  // ── 2. Tools → Skills ──────────────────────────────────────────────────────
  log.step("Importing tools...");
  const skills: LyrieSkill[] = [];

  // Tools from YAML
  const yamlTools = (nanobotConfig.tools as Record<string, unknown>[]) ?? [];
  for (const tool of yamlTools) {
    skills.push({
      name: (tool.name as string) ?? "unknown",
      description: (tool.description as string) ?? "",
      source: "nanobot",
      enabled: true,
      config: tool,
    });
    log.ok(`Tool: ${tool.name}`);
  }

  // Tools from filesystem
  const toolDirs = [
    join(process.cwd(), "tools"),
    join(HOME, "nanobot-tools"),
    join(NANOBOT_DIR, "tools"),
  ];

  for (const toolDir of toolDirs) {
    if (!existsSync(toolDir)) continue;

    const pyFiles = listFiles(toolDir, ".py");
    for (const file of pyFiles) {
      const name = basename(file, ".py");
      if (skills.find((s) => s.name === name)) continue;

      const content = safeReadText(file);
      let description = "";
      if (content) {
        const m = content.match(/"""([^"]+)"""/);
        if (m) description = m[1].trim().split("\n")[0];
      }

      skills.push({
        name,
        description,
        source: "nanobot",
        path: file,
        enabled: true,
      });
      log.ok(`Tool (file): ${name}`);
    }
  }

  // ── 3. Agents ──────────────────────────────────────────────────────────────
  log.step("Importing agents...");
  let agentCount = 0;

  // Agents from YAML
  const yamlAgents = (nanobotConfig.agents as Record<string, unknown>[]) ?? [];
  for (const agent of yamlAgents) {
    writeJson(
      join(ctx.lyrieDir, "agents", `nanobot-${agent.name ?? uuidv4()}.json`),
      agent,
      ctx.dryRun
    );
    agentCount++;
    log.ok(`Agent: ${agent.name}`);
  }

  // Agents from agents/ dir
  const agentDirs = [
    join(process.cwd(), "agents"),
    join(NANOBOT_DIR, "agents"),
  ];

  for (const agentDir of agentDirs) {
    if (!existsSync(agentDir)) continue;

    const agentFiles = [
      ...listFiles(agentDir, ".yaml"),
      ...listFiles(agentDir, ".yml"),
      ...listFiles(agentDir, ".json"),
    ];

    for (const file of agentFiles) {
      const raw = safeReadText(file);
      if (!raw) continue;
      const data = safeReadJson<Record<string, unknown>>(file) ??
        parseNanobotYaml(raw);

      writeJson(
        join(ctx.lyrieDir, "agents", `nanobot-${basename(file, ".yaml")}.json`),
        data,
        ctx.dryRun
      );
      agentCount++;
      log.ok(`Agent: ${basename(file)}`);
    }
  }

  manifest.agents = agentCount;

  // ── 4. Prompts → Memory ────────────────────────────────────────────────────
  log.step("Importing prompt templates...");
  const memoryEntries: LyrieMemoryEntry[] = [];

  const promptDirs = [
    join(process.cwd(), "prompts"),
    join(NANOBOT_DIR, "prompts"),
  ];

  for (const promptDir of promptDirs) {
    if (!existsSync(promptDir)) continue;

    const promptFiles = [
      ...listFiles(promptDir, ".txt"),
      ...listFiles(promptDir, ".md"),
    ];

    for (const file of promptFiles) {
      const content = safeReadText(file);
      if (!content) continue;

      memoryEntries.push({
        id: uuidv4(),
        category: "preference",
        text: content,
        importance: 0.8,
        source: `nanobot:prompts/${basename(file)}`,
        createdAt: new Date().toISOString(),
        tags: ["prompt", "template"],
      });
      log.ok(`Prompt: ${basename(file)}`);
    }
  }

  if (memoryEntries.length > 0) {
    writeJson(
      join(ctx.lyrieDir, "memory", "nanobot-prompts.json"),
      memoryEntries,
      ctx.dryRun
    );
  }

  // ── 5. Cron / schedules ────────────────────────────────────────────────────
  log.step("Checking for schedules...");
  const cronJobs: LyrieCronJob[] = [];

  const yamlSchedules = (nanobotConfig.schedules as Record<string, unknown>[]) ??
    (nanobotConfig.crons as Record<string, unknown>[]) ??
    [];

  for (const sched of yamlSchedules) {
    cronJobs.push({
      name: (sched.name as string) ?? "Nanobot schedule",
      schedule: (sched.cron as string) ?? (sched.schedule as string) ?? "0 * * * *",
      task: (sched.task as string) ?? (sched.command as string) ?? "",
      enabled: true,
    });
    log.ok(`Schedule: ${sched.name}`);
  }

  if (cronJobs.length > 0) {
    writeJson(
      join(ctx.lyrieDir, "config", "nanobot-crons.json"),
      cronJobs,
      ctx.dryRun
    );
  }

  writeJson(
    join(ctx.lyrieDir, "skills", "nanobot-tools.json"),
    skills,
    ctx.dryRun
  );

  manifest.skills = skills.length;
  manifest.tools = skills.length;
  manifest.memory = memoryEntries.length;
  manifest.cronJobs = cronJobs.length;

  const errors = log.getErrors();
  return {
    platform: "nanobot",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
