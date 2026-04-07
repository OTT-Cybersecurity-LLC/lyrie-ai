/**
 * Lyrie Agent — Migrate from Dify
 * 
 * Reads (Docker or local installs):
 *   ~/dify/                        — project dir
 *   ~/.dify/                       — config dir
 *   ~/dify/docker/.env             — environment config
 *   Dify API (if running locally): http://localhost/v1
 * 
 * Exports:
 *   - App configs (chat, agent, workflow apps)
 *   - Dataset/knowledge base metadata
 *   - Workflow definitions (DSL)
 *   - Model provider configs (non-sensitive)
 * 
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync } from "fs";
import { homedir } from "os";
import { join, basename } from "path";
import type { MigrationResult, LyrieMemoryEntry } from "./types";
import type { MigrationContext } from "./index";
import {
  safeReadJson,
  safeReadText,
  writeJson,
  listFiles,
  MigrationLogger,
  uuidv4,
} from "./utils";

const HOME = homedir();

const DIFY_CANDIDATES = [
  join(HOME, "dify"),
  join(HOME, ".dify"),
  join(HOME, "dify-selfhosted"),
  "/opt/dify",
  "/app/dify",
].filter(existsSync);

const DIFY_API_BASE = process.env.DIFY_API_URL ?? "http://localhost/v1";

export function detectDify(): boolean {
  if (DIFY_CANDIDATES.length > 0) return true;
  // Also check for Dify Docker compose files
  return existsSync(join(HOME, "dify", "docker", "docker-compose.yaml")) ||
    existsSync(join(HOME, "dify", "docker", "docker-compose.yml")) ||
    existsSync("/docker-compose.yaml");
}

export async function migrateFromDify(ctx: MigrationContext): Promise<MigrationResult> {
  const log = new MigrationLogger("dify", ctx.verbose);
  console.log("\n🔮 Migrating from Dify...");

  const manifest: MigrationResult["manifest"] = {};
  const difyDir = DIFY_CANDIDATES[0] ?? null;

  // ── 1. .env config ─────────────────────────────────────────────────────────
  log.step("Reading Dify environment config...");
  const envPaths = [
    difyDir && join(difyDir, "docker", ".env"),
    difyDir && join(difyDir, ".env"),
    join(HOME, "dify", "docker", ".env"),
  ].filter(Boolean) as string[];

  let difyEnv: Record<string, string> = {};
  for (const envPath of envPaths) {
    const raw = safeReadText(envPath);
    if (!raw) continue;

    for (const line of raw.split("\n")) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
      if (!m) continue;
      const [, key, value] = m;
      difyEnv[key] = value.replace(/^["']|["']$/g, "");
    }
    log.ok(`Loaded env from: ${envPath}`);
    break;
  }

  // Extract model provider info (non-sensitive)
  const modelConfig: Record<string, unknown> = {};
  const MODEL_KEYS = [
    "OPENAI_API_BASE", "ANTHROPIC_API_URL", "AZURE_OPENAI_API_BASE",
    "OLLAMA_API_HOST", "XINFERENCE_HOST", "TONGYI_DASHSCOPE_API_BASE",
  ];
  for (const key of MODEL_KEYS) {
    if (difyEnv[key]) modelConfig[key] = difyEnv[key];
  }

  if (Object.keys(modelConfig).length > 0) {
    writeJson(
      join(ctx.lyrieDir, "config", "dify-models.json"),
      modelConfig,
      ctx.dryRun
    );
    log.ok("Model provider URLs extracted");
  }

  // ── 2. Try Dify API (if running locally) ──────────────────────────────────
  const apiKey = difyEnv.CONSOLE_API_TOKEN ??
    process.env.DIFY_API_KEY ??
    difyEnv.SECRET_KEY;

  if (apiKey) {
    log.step("Attempting Dify API export...");
    await tryDifyApiMigration(apiKey, ctx, log, manifest);
  } else {
    log.skip("No API key found — skipping API export");
    log.warn(
      "Set DIFY_API_KEY env var to enable full API export. " +
      "Get it from Dify Settings > API Keys."
    );
  }

  // ── 3. File-based app exports ──────────────────────────────────────────────
  log.step("Scanning for exported app files...");
  const exportPaths = [
    difyDir && join(difyDir, "exports"),
    difyDir && join(difyDir, "apps"),
    join(HOME, "dify-exports"),
    join(HOME, "Downloads"),
  ].filter(Boolean) as string[];

  let workflowCount = 0;

  for (const exportDir of exportPaths) {
    if (!existsSync(exportDir)) continue;

    // Dify exports as .yml DSL files
    const dslFiles = [
      ...listFiles(exportDir, ".yml"),
      ...listFiles(exportDir, ".yaml"),
    ].filter(
      (f) => basename(f).includes("dify") || basename(f).includes("workflow") || basename(f).includes("app")
    );

    for (const file of dslFiles) {
      const content = safeReadText(file);
      if (!content) continue;

      writeJson(
        join(ctx.lyrieDir, "workflows", `dify-${basename(file, ".yml")}.json`),
        { dsl: content, source: file, importedAt: new Date().toISOString() },
        ctx.dryRun
      );
      workflowCount++;
      log.ok(`Workflow DSL: ${basename(file)}`);
    }

    // JSON exports
    const jsonFiles = listFiles(exportDir, ".json").filter(
      (f) => basename(f).includes("dify") || basename(f).includes("app")
    );
    for (const file of jsonFiles) {
      const data = safeReadJson<Record<string, unknown>>(file);
      if (!data) continue;

      writeJson(
        join(ctx.lyrieDir, "workflows", `dify-${basename(file)}`),
        data,
        ctx.dryRun
      );
      workflowCount++;
      log.ok(`App export: ${basename(file)}`);
    }
  }

  manifest.workflows = (manifest.workflows as number ?? 0) + workflowCount;

  // ── 4. Generate migration notes ────────────────────────────────────────────
  const notes = `# Dify Migration Notes

## What was migrated
- Environment configuration (non-sensitive keys)
- Model provider URLs
- Workflow DSL files (if found in exports dir)
- App configs (if Dify API was accessible)

## Manual steps required
1. Re-configure API keys in Lyrie Agent (they were not copied for security)
2. Recreate datasets/knowledge bases — Dify datasets cannot be exported programmatically
3. Review workflows in ~/.lyrie/workflows/ and adapt to Lyrie format

## Dataset migration
Dify datasets must be migrated manually:
1. Open Dify dashboard → Knowledge → your dataset → Export
2. Place exported files in ~/dify-exports/
3. Re-run migration

## Dify API self-service
If Dify is running locally:
  export DIFY_API_KEY=your-key
  lyrie migrate --from dify
`;

  writeJson(
    join(ctx.lyrieDir, "migrations", "dify-notes.md"),
    notes,
    ctx.dryRun
  );

  const errors = log.getErrors();
  return {
    platform: "dify",
    success: errors.length === 0,
    itemsMigrated: log.getCount(),
    errors,
    warnings: log.getWarnings(),
    manifest,
    duration: 0,
  };
}

// ─── Dify API migration ───────────────────────────────────────────────────────

async function tryDifyApiMigration(
  apiKey: string,
  ctx: MigrationContext,
  log: MigrationLogger,
  manifest: MigrationResult["manifest"]
): Promise<void> {
  try {
    const headers = {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    };

    // List apps
    const appsRes = await fetchWithTimeout(`${DIFY_API_BASE}/apps`, { headers });
    if (appsRes.ok) {
      const appsData = (await appsRes.json()) as { data?: unknown[]; items?: unknown[] };
      const apps = appsData.data ?? appsData.items ?? [];

      let workflowCount = 0;
      let datasetCount = 0;

      for (const app of apps) {
        const a = app as Record<string, unknown>;
        const appId = a.id as string;
        const appName = (a.name as string) ?? appId;

        // Export app DSL
        const dslRes = await fetchWithTimeout(
          `${DIFY_API_BASE}/apps/${appId}/export?include_secret=false`,
          { headers }
        );
        if (dslRes.ok) {
          const dsl = await dslRes.text();
          writeJson(
            join(ctx.lyrieDir, "workflows", `dify-${appId}.json`),
            { appId, appName, dsl, exportedAt: new Date().toISOString() },
            ctx.dryRun
          );
          workflowCount++;
          log.ok(`App exported: ${appName}`);
        }
      }

      manifest.workflows = workflowCount;
      manifest.agents = apps.length;

      // List datasets
      const datasetsRes = await fetchWithTimeout(`${DIFY_API_BASE}/datasets`, { headers });
      if (datasetsRes.ok) {
        const dsData = (await datasetsRes.json()) as { data?: unknown[]; items?: unknown[] };
        const datasets = dsData.data ?? dsData.items ?? [];

        writeJson(
          join(ctx.lyrieDir, "datasets", "dify-datasets-index.json"),
          datasets,
          ctx.dryRun
        );
        datasetCount = datasets.length;
        manifest.datasets = datasetCount;
        log.ok(`Dataset index: ${datasetCount} datasets (re-upload files manually)`);
      }
    } else {
      log.warn(`Dify API returned ${appsRes.status} — check API key and server URL`);
    }
  } catch (err: any) {
    log.warn(`Dify API not reachable (${err?.message ?? "timeout"}) — file-based migration only`);
  }
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs = 5000
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}
