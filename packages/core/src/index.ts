/**
 * Lyrie Agent — The world's first autonomous AI agent with built-in cybersecurity.
 *
 * This is the main entry point. It initializes:
 * 1. The Shield (security layer)
 * 2. The Memory Core (self-healing, versioned)
 * 3. The Agent Engine (autonomous execution)
 * 4. The Gateway (channels: Telegram, WhatsApp, etc.)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Re-exports for cross-package consumption ────────────────────────────────

// Engine
export { LyrieEngine } from "./engine/lyrie-engine";
export type { LyrieEngineConfig, Message, ParsedToolCall, ProcessResult } from "./engine/lyrie-engine";

// Model Router
export { ModelRouter } from "./engine/model-router";
export type { ModelConfig, ModelInstance, TaskType, RouterConfig } from "./engine/model-router";

// Shield
export { ShieldManager } from "./engine/shield-manager";
export type { ThreatScanResult, ToolCallValidation } from "./engine/shield-manager";

// Shield Guard — lightweight cross-cutting Shield contract used by every
// Lyrie module that touches untrusted text (memory recall, MCP results,
// gateway pairing, etc.). Doctrine: every layer has a Shield hook.
export { ShieldGuard, FallbackShieldGuard } from "./engine/shield-guard";
export type { ShieldGuardLike, ShieldVerdict } from "./engine/shield-guard";

// Memory
export { MemoryCore } from "./memory/memory-core";
export type { MemoryEntry, Importance, Source } from "./memory/memory-core";
export {
  ensureFtsIndex,
  searchAcrossSessions,
  summarizeSession,
  heuristicSummarizer,
} from "./memory/fts-search";
export type {
  CrossSessionHit,
  CrossSessionSearchOptions,
  SessionSummary,
  SessionSummarizer,
  SummarizeSessionOptions,
} from "./memory/fts-search";

// Tools
export { ToolExecutor } from "./tools/tool-executor";
export type { Tool, ToolCall, ToolResult, ToolParameter, AnthropicToolDef, OpenAIToolDef } from "./tools/tool-executor";

// Cron
export { CronManager } from "./cron/cron-manager";
export type { CronTask, CronInterval, CronExecution, CronManagerConfig } from "./cron/cron-manager";

// Sub-Agents
export { SubAgentManager } from "./agents/sub-agent";
export type { SubAgentTask, SubAgentResult, SubAgentConfig, SubAgentStatus } from "./agents/sub-agent";

// Skills
export { SkillManager } from "./skills/skill-manager";
export type { Skill } from "./skills/skill-manager";

// Config
export {
  getConfig,
  resetConfig,
  getConfiguredProviders,
  getConfiguredChannels,
  assertMinimalConfig,
} from "./config";
export type { LyrieConfig } from "./config";

// Providers
export {
  createProviderRegistry,
  AnthropicProvider,
  OpenAIProvider,
  GoogleProvider,
  XAIProvider,
  MiniMaxProvider,
  OllamaProvider,
} from "./engine/providers/index";
export type { Provider, ProviderRegistry } from "./engine/providers/index";

// Channel Gateway (from core)
export { ChannelGateway } from "./channels/gateway";
export type { ChannelConfig, ChannelGatewayConfig } from "./channels/gateway";

// Migration
export {
  detectInstalledPlatforms,
  runMigration,
  runAllMigrations,
  SUPPORTED_PLATFORMS,
} from "./migrate/index";
export type { MigrationResult, MigratorPlatform } from "./migrate/types";

// ─── Version ─────────────────────────────────────────────────────────────────

export const VERSION = "0.1.0";

// ─── Boot ────────────────────────────────────────────────────────────────────

import { LyrieEngine } from "./engine/lyrie-engine";
import { MemoryCore } from "./memory/memory-core";
import { ModelRouter } from "./engine/model-router";
import { ShieldManager } from "./engine/shield-manager";
import { ChannelGateway } from "./channels/gateway";
import { getConfig, assertMinimalConfig } from "./config";

async function main() {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║         🛡️  LYRIE AGENT v${VERSION}         ║
  ║   The AI that protects while it helps  ║
  ╚═══════════════════════════════════════╝
  `);

  // Load config and validate
  const config = getConfig();
  assertMinimalConfig(config);

  // Phase 1: Initialize the Shield (security first, always)
  console.log("🛡️  Initializing Shield...");
  const shield = new ShieldManager();
  await shield.initialize();

  // Phase 2: Initialize Memory (self-healing, versioned)
  console.log("🧠 Initializing Memory Core...");
  const memory = new MemoryCore();
  await memory.initialize();

  // Phase 3: Initialize Model Router with real API keys
  console.log("🔀 Initializing Model Router...");
  const router = new ModelRouter();
  await router.initialize({
    anthropicApiKey: config.anthropicApiKey,
    openaiApiKey: config.openaiApiKey,
    googleApiKey: config.googleApiKey,
    xaiApiKey: config.xaiApiKey,
    minimaxApiKey: config.minimaxApiKey,
    preferLocal: config.preferLocal,
  });

  // Phase 4: Initialize the Agent Engine
  console.log("⚡ Initializing Agent Engine...");
  const engine = new LyrieEngine({
    shield,
    memory,
    router,
    enableCron: true,
    maxToolTurns: 25,
    maxToolCalls: 50,
    subAgentConfig: { maxConcurrent: 5, defaultTimeout: 300000 },
  });
  await engine.initialize();

  // Phase 5: Start Channel Gateway
  console.log("📡 Starting Channel Gateway...");
  const gateway = new ChannelGateway({ engine });
  await gateway.start();

  const cronStatus = engine.getCron()?.stats();
  console.log(`
  ✅ Lyrie Agent is running.
  
  Channels: ${gateway.activeChannels().join(", ") || "CLI only"}
  Models:   ${router.availableModels().length} configured
  Tools:    ${engine.getTools().listNames().length} available (${engine.getTools().listNames().join(", ")})
  Cron:     ${cronStatus ? `${cronStatus.totalTasks} tasks scheduled` : "disabled"}
  Memory:   ${memory.status()}
  Shield:   ${shield.status()}
  
  Ready to protect and serve.
  `);
}

// Only run main() when executed directly, not when imported
const isDirectRun =
  typeof Bun !== "undefined"
    ? Bun.main === import.meta.path
    : process.argv[1]?.endsWith("core/src/index.ts");

if (isDirectRun) {
  main().catch((err) => {
    console.error("❌ Lyrie Agent failed to start:", err);
    process.exit(1);
  });
}
