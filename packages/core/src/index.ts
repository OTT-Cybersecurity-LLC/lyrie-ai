/**
 * Lyrie Agent — The world's first autonomous AI agent with built-in cybersecurity.
 * 
 * This is the main entry point. It initializes:
 * 1. The Shield (security layer)
 * 2. The Memory Core (self-healing, versioned)
 * 3. The Agent Engine (autonomous execution)
 * 4. The Gateway (channels: Telegram, WhatsApp, etc.)
 */

import { LyrieEngine } from "./engine/lyrie-engine";
import { MemoryCore } from "./memory/memory-core";
import { ModelRouter } from "./engine/model-router";
import { ShieldManager } from "./engine/shield-manager";
import { ChannelGateway } from "./channels/gateway";

const VERSION = "0.1.0";

async function main() {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║         🛡️  LYRIE AGENT v${VERSION}         ║
  ║   The AI that protects while it helps  ║
  ╚═══════════════════════════════════════╝
  `);

  // Phase 1: Initialize the Shield (security first, always)
  console.log("🛡️  Initializing Shield...");
  const shield = new ShieldManager();
  await shield.initialize();

  // Phase 2: Initialize Memory (self-healing, versioned)
  console.log("🧠 Initializing Memory Core...");
  const memory = new MemoryCore();
  await memory.initialize();

  // Phase 3: Initialize Model Router (smart routing to best model per task)
  console.log("🔀 Initializing Model Router...");
  const router = new ModelRouter();
  await router.initialize();

  // Phase 4: Initialize the Agent Engine
  console.log("⚡ Initializing Agent Engine...");
  const engine = new LyrieEngine({ shield, memory, router });
  await engine.initialize();

  // Phase 5: Start Channel Gateway
  console.log("📡 Starting Channel Gateway...");
  const gateway = new ChannelGateway({ engine });
  await gateway.start();

  console.log(`
  ✅ Lyrie Agent is running.
  
  Channels: ${gateway.activeChannels().join(", ") || "CLI only"}
  Models: ${router.availableModels().length} configured
  Memory: ${memory.status()}
  Shield: ${shield.status()}
  
  Ready to protect and serve.
  `);
}

main().catch((err) => {
  console.error("❌ Lyrie Agent failed to start:", err);
  process.exit(1);
});
