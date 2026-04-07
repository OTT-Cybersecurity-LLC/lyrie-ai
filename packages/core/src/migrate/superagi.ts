/**
 * Lyrie Agent — Migrate from SuperAGI
 * 
 * Reads:
 *   ~/SuperAGI/                    — project dir
 *   ~/.superagi/                   — config dir
 *   ~/SuperAGI/config.yaml         — main config
 *   ~/SuperAGI/superagi/           — source (agents, tools, memory)
 *   ~/SuperAGI/.env                — environment
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
} from "./utils";

const HOME = homedir();

const SUPERAGI_CANDIDATES = [
  join(HOME, "SuperAGI"),
  join(HOME, ".superagi"),
  join(HOME, "superagi"),
  "/app/SuperAGI",
  process.env.SUPERAGI_DIR,
].filter(Boolean).filter(existsSync) as string[];

export function detectSuperAGI(): boolean {
  return SUPERAGI_CANDIDATES.length > 0 ||
    existsSync(join(HOME, "SuperAGI", "config.yaml")) ||
    existsSync(join(HOME, "SuperAGI", "superagi"));
}

function findSuperAGIDir(): string | null {
  if (SUPERAGI_CANDIDATES.length > 0) return SUPERAGI_CANDIDATES[0];
  const fallbacks = [join(HOME, "SuperAGI"), join(HOME, "superagi")];
  return fallbacks.find(existsSync) ?? null;
}

export async function migrateFromSuperAGI(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("superagi", ctx.verbose);
  console.log("\n🦾 Migrating from SuperAGI...");

  const manifest: MigrationResult["manifest"] = {};
  const superagiDir = findSuperAGIDir();

  if (!superagiDir) {
    return {
      platform: "superagi",
      success: false,
      itemsMigrated: 0,
      errors: ["SuperAGI directory not found"],
      warnings: [],
      manifest: {},
      duration: 0,
    };
  }

  log.ok(`Found SuperAGI at: ${superagiDir}`);

  // ── 1. Config ──────────────────────────────────────────────────────────────
  log.step("Reading SuperAGI config...");
  const configYaml = safeReadText(join(superagiDir, "config.yaml"));
  const configJson = safeReadJson<Record<string, unknown>>(join(superagiDir, "config.json"));
  const config: Record<string, string> = {};

  if (configYaml) {
    for (const line of configYaml.split("\n")) {
      const m = line.match(/^(\w+(?:_\w+)*):\s*(.+)$/);
      if (m) config[m[1]] = m[2].trim().replace(/^["']|["']$/g, "");
    }
    log.ok("config.yaml parsed");
  }
  if (configJson) {
    Object.assign(config, configJson);
    log.ok("config.json parsed");
  }

  const lyrieConfig = {
    version: "0.1.0",
    agent: {
      name: config.AGENT_NAME ?? "Lyrie Agent",
      defaultModel: config.MODEL_API ?? config.DEFAULT_MODEL ?? undefined,
    },
    migrated: { from: "superagi", at: new Date().toISOString() },
  };
  writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
  manifest.config = true;

  // ── 2. Agents ──────────────────────────────────────────────────────────────
  log.step("Importing agents...");
  let agentCount = 0;

  // SuperAGI stores agent configs in DB, but also in YAML/JSON files
  const agentPaths = [
    join(superagiDir, "superagi", "agent"),
    join(superagiDir, "agents"),
  ];

  for (const agentDir of agentPaths) {
    if (!existsSync(agentDir)) continue;

    const agentFiles = [
      ...listFiles(agentDir, ".json"),
      ...listFiles(agentDir, ".yaml"),
    ];

    for (const file of agentFiles) {
      const name = basename(file);
      // Skip Python source files that aren't agent defs
      if (!name.match(/agent.*\.(json|yaml|yml)$/i) && name !== "config.json") continue;

      const data = safeReadJson<Record<string, unknown>>(file) ??
        { raw: safeReadText(file), source: file };

      writeJson(
        join(ctx.lyrieDir, "agents", `superagi-${basename(file, ".yaml").replace(".yml", "")}.json`),
        data,
        ctx.dryRun
      );
      agentCount++;
      log.ok(`Agent: ${name}`);
    }
  }

  manifest.agents = agentCount;

  // ── 3. Tools → Skills ──────────────────────────────────────────────────────
  log.step("Importing tools...");
  const skills: LyrieSkill[] = [];

  const toolDirs = [
    join(superagiDir, "superagi", "tools"),
    join(superagiDir, "tools"),
    join(superagiDir, "superagi_tools"),
  ];

  for (const toolDir of toolDirs) {
    if (!existsSync(toolDir)) continue;

    for (const toolName of listDirs(toolDir)) {
      const tDir = join(toolDir, toolName);
      const meta = safeReadJson<Record<string, unknown>>(join(tDir, "config.json"));
      const initPy = safeReadText(join(tDir, "__init__.py"));

      // Extract description from Python docstring or config
      let description = (meta?.description as string) ?? "";
      if (!description && initPy) {
        const docMatch = initPy.match(/"""([^"]+)"""/);
        if (docMatch) description = docMatch[1].trim().split("\n")[0];
      }

      skills.push({
        name: toolName,
        description,
        source: "superagi",
        path: tDir,
        enabled: true,
        config: meta ?? undefined,
      });
      log.ok(`Tool → Skill: ${toolName}`);
    }

    // Also check tool Python files directly
    const pyFiles = listFiles(toolDir, ".py").filter(
      (f) => !basename(f).startsWith("_") && basename(f).endsWith("_tool.py")
    );
    for (const file of pyFiles) {
      const name = basename(file, "_tool.py");
      if (skills.find((s) => s.name === name)) continue;

      const content = safeReadText(file);
      let description = "";
      if (content) {
        const classMatch = content.match(/class\s+\w+.*?:\s*\n\s*"""([^"]+)"""/s);
        if (classMatch) description = classMatch[1].trim().split("\n")[0];
      }

      skills.push({
        name,
        description,
        source: "superagi",
        enabled: true,
      });
      log.ok(`Tool (file): ${name}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "skills", "superagi-tools.json"),
    skills,
    ctx.dryRun
  );
  manifest.tools = skills.length;
  manifest.skills = skills.length;

  // ── 4. Memory ──────────────────────────────────────────────────────────────
  log.step("Importing memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];

  const memDirs = [
    join(superagiDir, "superagi", "memory"),
    join(superagiDir, "memory"),
    join(superagiDir, "data"),
  ];

  for (const memDir of memDirs) {
    if (!existsSync(memDir)) continue;

    for (const file of listFiles(memDir, ".json")) {
      const data = safeReadJson<unknown>(file);
      if (!data) continue;

      if (Array.isArray(data)) {
        for (const item of data) {
          const m = item as Record<string, unknown>;
          memoryEntries.push({
            id: (m.id as string) ?? uuidv4(),
            category: "fact",
            text: (m.content as string) ?? (m.text as string) ?? JSON.stringify(item),
            importance: 0.6,
            source: `superagi:memory/${basename(file)}`,
            createdAt: (m.created_at as string) ?? new Date().toISOString(),
          });
        }
        log.ok(`Memory ${basename(file)}: ${(data as unknown[]).length} entries`);
      }
    }
  }

  writeJson(
    join(ctx.lyrieDir, "memory", "superagi-import.json"),
    memoryEntries,
    ctx.dryRun
  );
  manifest.memory = memoryEntries.length;

  const errors = log.getErrors();
  return {
    platform: "superagi",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
