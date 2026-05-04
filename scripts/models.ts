#!/usr/bin/env bun
/**
 * lyrie models — Model fleet CLI for Lyrie v1.2.
 *
 * Commands:
 *   lyrie models list              — all providers + models + availability + cost
 *   lyrie models test <model>      — ping a model with "hello" and measure latency
 *   lyrie models route <task-type> — show which model is selected for a task type
 *   lyrie models health            — health check all configured providers
 *   lyrie models cost              — spend summary by provider
 *
 * Usage:
 *   bun run scripts/models.ts list
 *   bun run scripts/models.ts route code
 *   bun run scripts/models.ts health
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { ModelFleet, autoRoute } from "../packages/core/src/engine/model-fleet";
import type { TaskType } from "../packages/core/src/engine/model-fleet";
import { buildFleetProviders } from "../packages/core/src/engine/providers/fleet-adapters";

// ─── Env / config ─────────────────────────────────────────────────────────────

const cfg = {
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
  openaiApiKey: process.env.OPENAI_API_KEY,
  xaiApiKey: process.env.XAI_API_KEY,
  minimaxApiKey: process.env.MINIMAX_API_KEY,
  minimaxGroupId: process.env.MINIMAX_GROUP_ID,
  googleApiKey: process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY,
  hermesEndpoint: process.env.HERMES_ENDPOINT,
  ollamaEndpoint: process.env.OLLAMA_BASE_URL,
};

function bootstrapFleet(): ModelFleet {
  ModelFleet._reset();
  const fleet = ModelFleet.getInstance();
  const providers = buildFleetProviders(cfg);
  for (const p of providers) fleet.register(p);
  return fleet;
}

// ─── Commands ─────────────────────────────────────────────────────────────────

function cmdList(): void {
  console.log("\n🤖 Lyrie Model Fleet — Guy's 15 Models\n");

  const catalog = [
    // Anthropic
    { provider: "Anthropic", model: "claude-haiku-4-5",             type: "simple/chat",       cost: "$0.25/MTok", local: false },
    { provider: "Anthropic", model: "claude-sonnet-4-6",            type: "chat (default)",    cost: "$3/MTok",    local: false },
    { provider: "Anthropic", model: "claude-opus-4-7",              type: "reasoning fallback", cost: "$15/MTok",   local: false },
    // OpenAI
    { provider: "OpenAI",    model: "gpt-5.4-codex",                type: "code",              cost: "$2/MTok",    local: false },
    { provider: "OpenAI",    model: "gpt-5",                        type: "general",           cost: "$2.5/MTok",  local: false },
    { provider: "OpenAI",    model: "o3",                           type: "reasoning",         cost: "$10/MTok",   local: false },
    { provider: "OpenAI",    model: "o4-mini",                      type: "reasoning (cheap)", cost: "$1/MTok",    local: false },
    // xAI
    { provider: "xAI",       model: "grok-3-fast",                  type: "general",           cost: "$2/MTok",    local: false },
    { provider: "xAI",       model: "grok-4-1-fast-reasoning",      type: "reasoning",         cost: "$2/MTok",    local: false },
    { provider: "xAI",       model: "grok-4-1-fast-non-reasoning",  type: "code",              cost: "$2/MTok",    local: false },
    // MiniMax
    { provider: "MiniMax",   model: "MiniMax-M2.7",                 type: "bulk",              cost: "$0.08/MTok", local: false },
    { provider: "MiniMax",   model: "MiniMax-M2.7-highspeed",       type: "bulk (fast)",       cost: "$0.08/MTok", local: false },
    // Google
    { provider: "Google",    model: "gemini-2.5-pro",               type: "reasoning",         cost: "$1.25/MTok", local: false },
    { provider: "Google",    model: "gemini-2.5-flash",             type: "simple/fast",       cost: "$0.075/MTok", local: false },
    // Local
    { provider: "Hermes",    model: "hermes-3-70b",                 type: "local/agentic",     cost: "FREE",       local: true },
    { provider: "Ollama",    model: "llama3.2:1b",                  type: "local/fast",        cost: "FREE",       local: true },
  ];

  const maxProvider = Math.max(...catalog.map((r) => r.provider.length));
  const maxModel = Math.max(...catalog.map((r) => r.model.length));

  const header = `${"Provider".padEnd(maxProvider)}  ${"Model".padEnd(maxModel)}  ${"Type".padEnd(24)}  Cost`;
  console.log(header);
  console.log("─".repeat(header.length + 4));

  let lastProvider = "";
  for (const row of catalog) {
    const prefix = row.provider !== lastProvider ? row.provider : " ".repeat(row.provider.length);
    lastProvider = row.provider;
    const localTag = row.local ? " 🏠" : "";
    console.log(
      `${prefix.padEnd(maxProvider)}  ${row.model.padEnd(maxModel)}  ${row.type.padEnd(24)}  ${row.cost}${localTag}`,
    );
  }

  const cloudCount = catalog.filter((r) => !r.local).length;
  const localCount = catalog.filter((r) => r.local).length;
  console.log(`\n📊 ${catalog.length} models | ☁️  ${cloudCount} cloud | 🏠 ${localCount} local`);
  console.log('💡 Run "bun run scripts/models.ts health" to check live availability\n');
}

async function cmdHealth(): Promise<void> {
  console.log("\n🏥 Lyrie Model Fleet — Health Check\n");
  const fleet = bootstrapFleet();
  const report = await fleet.healthCheck();
  console.log(`Checked at: ${report.checkedAt}\n`);

  if (report.providers.length === 0) {
    console.log("⚠️  No providers registered. Set API keys in environment:\n");
    console.log("  ANTHROPIC_API_KEY  OPENAI_API_KEY   XAI_API_KEY");
    console.log("  MINIMAX_API_KEY    GOOGLE_API_KEY");
    console.log("  HERMES_ENDPOINT    OLLAMA_BASE_URL\n");
    return;
  }

  for (const p of report.providers) {
    const icon = p.available ? "✅" : "❌";
    const latency = p.latencyMs != null ? `${p.latencyMs}ms` : "n/a";
    const err = p.error ? `  error: ${p.error}` : "";
    console.log(`${icon} ${p.name.padEnd(12)} ${latency.padStart(8)}${err}`);
  }

  const ok = report.providers.filter((p) => p.available).length;
  console.log(`\n${ok}/${report.providers.length} providers healthy\n`);
}

async function cmdTest(modelArg: string): Promise<void> {
  console.log(`\n🧪 Testing model: ${modelArg}\n`);
  const fleet = bootstrapFleet();
  const providers = fleet.list();

  if (providers.length === 0) {
    console.log("❌ No providers registered. Set API keys first.");
    return;
  }

  const match = providers.find((p) => p.models.some((m) => m.includes(modelArg) || modelArg.includes(m)));
  if (!match) {
    console.log(`❌ No registered provider has model "${modelArg}"`);
    console.log(`   Available models: ${providers.flatMap((p) => p.models).join(", ")}`);
    return;
  }

  console.log(`Provider: ${match.name}`);
  const start = Date.now();
  try {
    const report = await fleet.healthCheck();
    const result = report.providers.find((p) => p.id === match.id);
    const latency = Date.now() - start;
    if (result?.available) {
      console.log(`✅ ${match.name} responded in ${latency}ms`);
    } else {
      console.log(`❌ ${match.name} unreachable (${result?.error ?? "timeout"})`);
    }
  } catch (err: any) {
    console.log(`❌ Error: ${err.message}`);
  }
  console.log();
}

function cmdRoute(taskTypeArg: string): void {
  const validTypes: TaskType[] = ["chat", "code", "bulk", "reasoning", "creative", "simple"];
  const type = taskTypeArg as TaskType;

  if (!validTypes.includes(type)) {
    console.log(`\n❌ Unknown task type: "${taskTypeArg}"`);
    console.log(`   Valid types: ${validTypes.join(", ")}\n`);
    process.exit(1);
  }

  const route = autoRoute({ type });
  console.log(`\n🔀 Routing for task type: ${type}\n`);
  console.log(`  Primary  : ${route.primary}`);
  console.log(`  Fallbacks: ${route.fallbacks.length > 0 ? route.fallbacks.join(" → ") : "(none)"}`);
  console.log(`  Reason   : ${route.reason}\n`);
}

function cmdCost(): void {
  const fleet = bootstrapFleet();
  const summary = fleet.cost.summary();
  const total = fleet.cost.total();

  console.log("\n💰 Cost Summary (this session)\n");

  if (Object.keys(summary).length === 0) {
    console.log("  No calls recorded yet.\n");
    return;
  }

  for (const [id, rec] of Object.entries(summary)) {
    console.log(`  ${id.padEnd(20)} calls=${rec.calls}  tokens=${rec.tokens.toLocaleString()}  $${rec.costUsd.toFixed(6)}`);
  }
  console.log(`\n  Total: $${total.toFixed(6)}\n`);
}

function printHelp(): void {
  console.log(`
lyrie models — Lyrie v1.2 model fleet CLI

Commands:
  list                  List all 15 models with type, cost, and local flag
  health                Health check all configured providers
  test <model>          Ping a model and measure latency
  route <task-type>     Show routing decision for a task type
  cost                  Show spend summary for this session

Task types for route:
  chat | code | bulk | reasoning | creative | simple

Examples:
  bun run scripts/models.ts list
  bun run scripts/models.ts route code
  bun run scripts/models.ts route reasoning
  bun run scripts/models.ts health
  bun run scripts/models.ts test gpt-5.4-codex
`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const [, , cmd, arg] = process.argv;

switch (cmd) {
  case "list":    cmdList(); break;
  case "health":  await cmdHealth(); break;
  case "test":
    if (!arg) { console.log("Usage: lyrie models test <model>"); process.exit(1); }
    await cmdTest(arg);
    break;
  case "route":
    if (!arg) { console.log("Usage: lyrie models route <task-type>"); process.exit(1); }
    cmdRoute(arg);
    break;
  case "cost":    cmdCost(); break;
  default:        printHelp();
}
