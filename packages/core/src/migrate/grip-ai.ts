/**
 * Lyrie Agent — Migrate from grip-ai
 * 
 * Reads:
 *   ~/.grip-ai/               — config dir
 *   ~/.grip-ai/config.py      — Python config
 *   ~/.grip-ai/config.json    — JSON config
 *   ~/.grip-ai/memory/        — memory store
 *   ~/.grip-ai/.env           — environment
 *   ~/grip-ai/                — project dir (if cloned)
 *   grip_ai.yaml              — project-level config
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
  listFiles,
  listDirs,
  MigrationLogger,
  uuidv4,
} from "./utils";

const HOME = homedir();
const GRIPAL_DIR = join(HOME, ".grip-ai");

const GRIP_CANDIDATES = [
  GRIPAL_DIR,
  join(HOME, "grip-ai"),
  join(HOME, ".gripai"),
  join(process.cwd(), "grip-ai"),
].filter(existsSync);

export function detectGripAI(): boolean {
  return GRIP_CANDIDATES.length > 0 ||
    existsSync(join(process.cwd(), "grip_ai.yaml")) ||
    existsSync(join(process.cwd(), "grip_ai.yml"));
}

function parsePythonConfig(content: string): Record<string, unknown> {
  /**
   * Parse Python config files (simple key=value assignments).
   * grip-ai uses Python configs like:
   *   MODEL = "gpt-4"
   *   API_KEY = "..."
   *   AGENT_NAME = "Grip"
   */
  const result: Record<string, unknown> = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;

    const eqIdx = trimmed.indexOf("=");
    const key = trimmed.slice(0, eqIdx).trim();
    let value: string = trimmed.slice(eqIdx + 1).trim();

    // Skip complex Python expressions
    if (value.includes("{") || value.includes("[") || value.includes("(")) continue;

    // Strip quotes, comments
    value = value.replace(/#.*$/, "").trim();
    value = value.replace(/^["']|["']$/g, "");

    if (key && value && /^[A-Z_a-z][A-Z_a-z0-9]*$/.test(key)) {
      result[key] = value;
    }
  }
  return result;
}

export async function migrateFromGripAI(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("grip-ai", ctx.verbose);
  console.log("\n🦾 Migrating from grip-ai...");

  const manifest: MigrationResult["manifest"] = {};
  const gripDir = GRIP_CANDIDATES[0] ?? null;

  // ── 1. Config ──────────────────────────────────────────────────────────────
  log.step("Reading grip-ai config...");
  let config: Record<string, unknown> = {};

  // Try JSON config first
  const jsonConfig = safeReadJson<Record<string, unknown>>(
    gripDir ? join(gripDir, "config.json") : ""
  );
  if (jsonConfig) {
    config = jsonConfig;
    log.ok("config.json loaded");
  }

  // Try Python config
  const configPyPaths = [
    gripDir && join(gripDir, "config.py"),
    gripDir && join(gripDir, "settings.py"),
    join(process.cwd(), "config.py"),
  ].filter(Boolean) as string[];

  for (const pyPath of configPyPaths) {
    const raw = safeReadText(pyPath);
    if (!raw) continue;
    const parsed = parsePythonConfig(raw);
    Object.assign(config, parsed);
    log.ok(`Parsed Python config: ${pyPath}`);
    break;
  }

  // Try .env
  const envPaths = [
    gripDir && join(gripDir, ".env"),
    join(process.cwd(), ".env"),
  ].filter(Boolean) as string[];

  for (const envPath of envPaths) {
    const raw = safeReadText(envPath);
    if (!raw) continue;

    for (const line of raw.split("\n")) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.+)$/);
      if (!m) continue;
      const [, key, value] = m;
      if (!key.includes("KEY") && !key.includes("SECRET")) {
        config[key] = value.replace(/^["']|["']$/g, "");
      }
    }
    log.ok(`.env loaded from: ${envPath}`);
    break;
  }

  // Try YAML config
  const yamlPaths = [
    join(process.cwd(), "grip_ai.yaml"),
    join(process.cwd(), "grip_ai.yml"),
    gripDir && join(gripDir, "config.yaml"),
  ].filter(Boolean) as string[];

  for (const yamlPath of yamlPaths) {
    const raw = safeReadText(yamlPath);
    if (!raw) continue;

    for (const line of raw.split("\n")) {
      const m = line.match(/^(\w+):\s*(.+)$/);
      if (!m) continue;
      const [, key, value] = m;
      config[key] = value.trim().replace(/^["']|["']$/g, "");
    }
    log.ok(`YAML config loaded: ${yamlPath}`);
    break;
  }

  if (Object.keys(config).length > 0) {
    const lyrieConfig = {
      version: "0.1.0",
      agent: {
        name: (config.AGENT_NAME as string) ??
          (config.agent_name as string) ??
          (config.name as string) ??
          "Lyrie Agent",
        defaultModel: (config.MODEL as string) ??
          (config.model as string) ??
          (config.DEFAULT_MODEL as string) ??
          undefined,
        persona: (config.SYSTEM_PROMPT as string) ??
          (config.system_prompt as string) ??
          (config.persona as string) ??
          undefined,
      },
      migrated: { from: "grip-ai", at: new Date().toISOString() },
    };
    writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
    manifest.config = true;
    log.ok("Lyrie config written");
  }

  // ── 2. Memory ──────────────────────────────────────────────────────────────
  log.step("Importing memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];

  const memDirs = [
    gripDir && join(gripDir, "memory"),
    gripDir && join(gripDir, "data", "memory"),
    join(process.cwd(), "memory"),
    join(process.cwd(), "grip_memory"),
  ].filter(Boolean) as string[];

  for (const memDir of memDirs) {
    if (!existsSync(memDir)) continue;

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
            text: (m.content as string) ?? (m.text as string) ?? (m.memory as string) ?? JSON.stringify(item),
            importance: (m.importance as number) ?? (m.weight as number) ?? 0.6,
            source: `grip-ai:${basename(file)}`,
            createdAt: (m.created_at as string) ?? (m.timestamp as string) ?? new Date().toISOString(),
            tags: (m.tags as string[]) ?? [],
          });
        }
        log.ok(`Memory ${basename(file)}: ${(data as unknown[]).length} entries`);
      }
    }

    // Pickle files (Python serialized) — mention but skip
    const pickleFiles = listFiles(memDir, ".pkl");
    if (pickleFiles.length > 0) {
      log.warn(
        `Found ${pickleFiles.length} .pkl memory files — ` +
        `Python serialized format cannot be parsed. ` +
        `Run: python3 -c "import pickle,json; [print(json.dumps(pickle.load(open(f,'rb')))) for f in ${JSON.stringify(pickleFiles)}]" > memory_export.json`
      );
    }

    // Text memories
    for (const file of listFiles(memDir, ".txt")) {
      const content = safeReadText(file);
      if (!content) continue;
      memoryEntries.push({
        id: uuidv4(),
        category: "fact",
        text: content,
        importance: 0.5,
        source: `grip-ai:memory/${basename(file)}`,
        createdAt: new Date().toISOString(),
      });
      log.ok(`Memory (txt): ${basename(file)}`);
    }

    break; // Use first found memory dir
  }

  if (memoryEntries.length > 0) {
    writeJson(
      join(ctx.lyrieDir, "memory", "grip-ai-import.json"),
      memoryEntries,
      ctx.dryRun
    );
  }
  manifest.memory = memoryEntries.length;

  // ── 3. Skills/Tools ────────────────────────────────────────────────────────
  log.step("Importing skills...");
  const skills: LyrieSkill[] = [];

  const skillDirs = [
    gripDir && join(gripDir, "skills"),
    gripDir && join(gripDir, "tools"),
    gripDir && join(gripDir, "plugins"),
    join(process.cwd(), "skills"),
    join(process.cwd(), "tools"),
  ].filter(Boolean) as string[];

  for (const skillDir of skillDirs) {
    if (!existsSync(skillDir)) continue;

    for (const name of listDirs(skillDir)) {
      const sDir = join(skillDir, name);
      const meta = safeReadJson<Record<string, unknown>>(join(sDir, "skill.json")) ??
        safeReadJson<Record<string, unknown>>(join(sDir, "config.json"));
      const initPy = safeReadText(join(sDir, "__init__.py"));

      let description = (meta?.description as string) ?? "";
      if (!description && initPy) {
        const m = initPy.match(/"""([^"]{1,200}?)"""/s);
        if (m) description = m[1].trim().split("\n")[0];
      }

      skills.push({
        name,
        description,
        source: "grip-ai",
        path: sDir,
        enabled: true,
        config: meta ?? undefined,
      });
      log.ok(`Skill: ${name}`);
    }

    // Python skill files
    for (const file of listFiles(skillDir, ".py")) {
      const name = basename(file, ".py");
      if (name.startsWith("_")) continue;
      if (skills.find((s) => s.name === name)) continue;

      skills.push({
        name,
        description: "",
        source: "grip-ai",
        path: file,
        enabled: true,
      });
      log.ok(`Skill (file): ${name}`);
    }

    break; // Use first found skills dir
  }

  if (skills.length > 0) {
    writeJson(
      join(ctx.lyrieDir, "skills", "grip-ai-skills.json"),
      skills,
      ctx.dryRun
    );
  }
  manifest.skills = skills.length;

  const errors = log.getErrors();
  return {
    platform: "grip-ai",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
