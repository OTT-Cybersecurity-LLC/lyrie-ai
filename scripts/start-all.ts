#!/usr/bin/env bun
/**
 * Lyrie Agent — Full Stack Launcher
 *
 * Boots Core (engine + memory + shield) and Gateway (channels) together.
 *
 * Usage:
 *   bun run scripts/start-all.ts
 *   bun run scripts/start-all.ts --gateway-only
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  LyrieEngine,
  MemoryCore,
  ModelRouter,
  ShieldManager,
  getConfig,
  assertMinimalConfig,
  VERSION,
} from "../packages/core/src/index";

import { LyrieGateway } from "../packages/gateway/src/index";

// ─── Banner ─────────────────────────────────────────────────────────────────

function printBanner() {
  console.log(`
\x1b[36m\x1b[1m  ╔═══════════════════════════════════════════════════╗
  ║                                                   ║
  ║   🛡️   L Y R I E   A G E N T   v${VERSION}            ║
  ║                                                   ║
  ║   The AI that protects while it helps.             ║
  ║   © OTT Cybersecurity LLC — https://lyrie.ai       ║
  ║                                                   ║
  ╚═══════════════════════════════════════════════════╝\x1b[0m
`);
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const gatewayOnly = process.argv.includes("--gateway-only");

  printBanner();

  if (gatewayOnly) {
    console.log("  ℹ️  Starting in gateway-only mode (no engine)\n");
    const gateway = new LyrieGateway();
    await gateway.start();
    return;
  }

  // Phase 1: Shield
  console.log("🛡️  Phase 1/5 — Initializing Shield...");
  const shield = new ShieldManager();
  await shield.initialize();

  // Phase 2: Memory
  console.log("🧠 Phase 2/5 — Initializing Memory Core...");
  const memory = new MemoryCore();
  await memory.initialize();

  // Phase 3: Model Router — with real API keys from .env
  console.log("🔀 Phase 3/5 — Initializing Model Router...");
  const config = getConfig();
  assertMinimalConfig(config);
  const router = new ModelRouter();
  await router.initialize({
    anthropicApiKey: config.anthropicApiKey,
    openaiApiKey: config.openaiApiKey,
    googleApiKey: config.googleApiKey,
    xaiApiKey: config.xaiApiKey,
    minimaxApiKey: config.minimaxApiKey,
    preferLocal: config.preferLocal,
  });

  // Phase 4: Engine
  console.log("⚡ Phase 4/5 — Initializing Agent Engine...");
  const engine = new LyrieEngine({ shield, memory, router });
  await engine.initialize();

  // Phase 5: Gateway — pass engine so messages route to the AI
  console.log("📡 Phase 5/5 — Starting Gateway...");

  // The gateway's EngineInterface matches LyrieEngine.process signature
  const gateway = new LyrieGateway({
    process: (msg) =>
      engine.process({
        role: msg.role as "user" | "assistant" | "system",
        content: msg.content,
        source: msg.source,
        timestamp: Date.now(),
      }),
    running: engine.running,
  });

  await gateway.start();

  // Summary
  console.log(`
\x1b[32m  ═══════════════════════════════════════════════════
  ✅  Lyrie Agent is fully operational.

  Engine:   Running
  Models:   ${router.availableModels().length} configured
  Memory:   ${memory.status()}
  Shield:   ${shield.status()}

  Type Ctrl+C to stop.
  ═══════════════════════════════════════════════════\x1b[0m
`);

  // Graceful shutdown
  const shutdown = async () => {
    console.log("\n🛑 Shutting down Lyrie Agent...");
    await gateway.stop();
    console.log("👋 Goodbye. Stay protected. 🛡️\n");
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("\n❌ Lyrie Agent failed to start:", err);
  process.exit(1);
});
