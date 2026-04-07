/**
 * Lyrie Agent — Migrate from AutoGPT
 * 
 * Reads:
 *   auto_gpt_workspace/           — main workspace (cwd or $AUTOGPT_WORKSPACE)
 *   ~/.config/autogpt/            — Linux config
 *   ~/auto_gpt_workspace/         — home dir workspace
 *   agents/*.json                 — agent definitions
 *   memory/                       — memory files
 *   .env / .env.local             — API keys and config
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readdirSync } from "fs";
import { homedir } from "os";
import { join, basename } from "path";
import type { MigrationResult, LyrieMemoryEntry } from "./types";
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

const AUTOGPT_CANDIDATES = [
  process.env.AUTOGPT_WORKSPACE,
  join(HOME, "auto_gpt_workspace"),
  join(process.cwd(), "auto_gpt_workspace"),
  join(HOME, ".autogpt"),
  join(HOME, ".config", "autogpt"),
  "/app/auto_gpt_workspace",
].filter(Boolean) as string[];

export function detectAutoGPT(): boolean {
  return AUTOGPT_CANDIDATES.some(
    (dir) =>
      existsSync(dir) &&
      (existsSync(join(dir, "agents")) ||
        existsSync(join(dir, "memory")) ||
        existsSync(join(dir, ".env")) ||
        existsSync(join(dir, "ai_settings.yaml")))
  );
}

function findAutoGPTDir(): string | null {
  return AUTOGPT_CANDIDATES.find(
    (dir) =>
      existsSync(dir) &&
      (existsSync(join(dir, "agents")) ||
        existsSync(join(dir, "memory")) ||
        existsSync(join(dir, ".env")) ||
        existsSync(join(dir, "ai_settings.yaml")))
  ) ?? null;
}

export async function migrateFromAutoGPT(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("autogpt", ctx.verbose);
  console.log("\n🤖 Migrating from AutoGPT...");

  const manifest: MigrationResult["manifest"] = {};
  const workspaceDir = findAutoGPTDir();

  if (!workspaceDir) {
    return {
      platform: "autogpt",
      success: false,
      itemsMigrated: 0,
      errors: ["AutoGPT workspace not found"],
      warnings: [],
      manifest: {},
      duration: 0,
    };
  }

  log.ok(`Found workspace at: ${workspaceDir}`);

  // ── 1. ai_settings.yaml → config ──────────────────────────────────────────
  log.step("Reading AI settings...");
  const aiSettings =
    safeReadJson<Record<string, unknown>>(join(workspaceDir, "ai_settings.yaml")) ??
    ((): Record<string, unknown> | null => {
      // Try parsing as YAML
      const raw = safeReadText(join(workspaceDir, "ai_settings.yaml"));
      if (!raw) return null;

      const settings: Record<string, unknown> = {};
      for (const line of raw.split("\n")) {
        const m = line.match(/^(\w+(?:_\w+)*):\s*(.+)$/);
        if (m) settings[m[1]] = m[2].trim().replace(/^["']|["']$/g, "");
      }
      return Object.keys(settings).length > 0 ? settings : null;
    })();

  if (aiSettings) {
    const lyrieConfig = {
      version: "0.1.0",
      agent: {
        name: (aiSettings.ai_name as string) ?? "Lyrie Agent",
        persona: (aiSettings.ai_role as string) ?? undefined,
        goals: aiSettings.ai_goals ?? [],
      },
      migrated: { from: "autogpt", at: new Date().toISOString() },
    };
    writeJson(join(ctx.lyrieDir, "config", "lyrie.json"), lyrieConfig, ctx.dryRun);
    log.ok(`Config: ai_name="${aiSettings.ai_name}", goals imported`);
    manifest.config = true;
  }

  // ── 2. Agents ──────────────────────────────────────────────────────────────
  log.step("Importing agents...");
  const agentsDir = join(workspaceDir, "agents");
  let agentCount = 0;

  if (existsSync(agentsDir)) {
    const agentFiles = listFiles(agentsDir, ".json");
    for (const file of agentFiles) {
      const agent = safeReadJson<Record<string, unknown>>(file);
      if (!agent) continue;

      writeJson(
        join(ctx.lyrieDir, "agents", `autogpt-${basename(file)}`),
        agent,
        ctx.dryRun
      );
      agentCount++;
      log.ok(`Agent: ${(agent.name as string) ?? basename(file, ".json")}`);
    }

    // YAML agents
    const yamlAgents = listFiles(agentsDir, ".yaml").concat(listFiles(agentsDir, ".yml"));
    for (const file of yamlAgents) {
      const raw = safeReadText(file);
      if (!raw) continue;
      writeJson(
        join(ctx.lyrieDir, "agents", `autogpt-${basename(file, ".yaml")}.json`),
        { raw, source: file },
        ctx.dryRun
      );
      agentCount++;
      log.ok(`Agent (yaml): ${basename(file)}`);
    }
  }

  manifest.agents = agentCount;

  // ── 3. Memory ──────────────────────────────────────────────────────────────
  log.step("Importing memory...");
  const memoryEntries: LyrieMemoryEntry[] = [];
  const memDir = join(workspaceDir, "memory");

  if (existsSync(memDir)) {
    // JSON memory stores
    const memFiles = listFiles(memDir, ".json");
    for (const file of memFiles) {
      const data = safeReadJson<unknown>(file);

      // AutoGPT uses various formats
      if (Array.isArray(data)) {
        for (const item of data) {
          const m = item as Record<string, unknown>;
          const text =
            (m.content as string) ??
            (m.text as string) ??
            (m.data as string) ??
            JSON.stringify(item);
          memoryEntries.push({
            id: (m.id as string) ?? uuidv4(),
            category: "fact",
            text,
            importance: 0.6,
            source: `autogpt:memory/${basename(file)}`,
            createdAt: (m.timestamp as string) ?? new Date().toISOString(),
          });
        }
        log.ok(`Memory ${basename(file)}: ${(data as unknown[]).length} entries`);
      } else if (data && typeof data === "object") {
        const d = data as Record<string, unknown>;
        // Could be { data: [...], ids: [...] } (chromadb-style)
        const vectors = (d.data as unknown[]) ?? (d.embeddings as unknown[]) ?? [];
        const ids = (d.ids as string[]) ?? [];
        const docs = (d.documents as string[]) ?? [];

        for (let i = 0; i < Math.max(vectors.length, docs.length); i++) {
          const text = docs[i] ?? JSON.stringify(vectors[i]);
          if (!text) continue;
          memoryEntries.push({
            id: ids[i] ?? uuidv4(),
            category: "fact",
            text,
            importance: 0.5,
            source: `autogpt:memory/${basename(file)}`,
            createdAt: new Date().toISOString(),
          });
        }
        if (docs.length > 0) log.ok(`Memory (vector store) ${basename(file)}: ${docs.length} docs`);
      }
    }

    // Text memory files
    const txtFiles = listFiles(memDir, ".txt");
    for (const file of txtFiles) {
      const content = safeReadText(file);
      if (!content) continue;
      memoryEntries.push({
        id: uuidv4(),
        category: "fact",
        text: content,
        importance: 0.5,
        source: `autogpt:memory/${basename(file)}`,
        createdAt: new Date().toISOString(),
      });
      log.ok(`Memory (text): ${basename(file)}`);
    }
  }

  writeJson(
    join(ctx.lyrieDir, "memory", "autogpt-import.json"),
    memoryEntries,
    ctx.dryRun
  );
  manifest.memory = memoryEntries.length;

  // ── 4. .env → extract non-sensitive config ─────────────────────────────────
  log.step("Checking .env for configuration...");
  const envContent = safeReadText(join(workspaceDir, ".env")) ??
    safeReadText(join(workspaceDir, ".env.local"));

  if (envContent) {
    const envVars: Record<string, string> = {};
    for (const line of envContent.split("\n")) {
      const m = line.match(/^([A-Z_]+)=(.+)$/);
      if (!m) continue;
      const [, key, value] = m;
      // Only export non-secret vars
      if (!key.includes("KEY") && !key.includes("SECRET") && !key.includes("TOKEN")) {
        envVars[key] = value.trim().replace(/^["']|["']$/g, "");
      }
    }
    writeJson(
      join(ctx.lyrieDir, "config", "autogpt-env.json"),
      envVars,
      ctx.dryRun
    );
    log.ok(`Environment config extracted (${Object.keys(envVars).length} non-secret vars)`);
  }

  const errors = log.getErrors();
  return {
    platform: "autogpt",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}
