#!/usr/bin/env bun
/**
 * `lyrie agent run` — Run a one-shot task via a Lyrie sub-agent.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   lyrie agent run "scan https://example.com for vulnerabilities"
 *   lyrie agent run "summarise the latest CVEs" --model hermes --timeout 60
 *   lyrie agent run "run lyrie hack ./myapp" --context isolated
 *
 * Flags:
 *   --model <id>           Model ID override (e.g. "claude-haiku-4-5")
 *   --timeout <seconds>    Max seconds before abort (default: 300)
 *   --context <mode>       "isolated" (default) | "fork"
 *   --parent-context <txt> Parent context string injected when --context=fork
 *   --json                 Output raw JSON result instead of pretty text
 */

import { SubagentRunner } from "../packages/core/src/agents/subagent-runner";

// ─── Parse args ──────────────────────────────────────────────────────────────

const rawArgs = process.argv.slice(2);

// Expect first positional to be the subcommand "run"
const subcommand = rawArgs[0];
if (subcommand !== "run") {
  console.error(
    `Usage: lyrie agent run "<task>" [--model <id>] [--timeout <secs>] [--context isolated|fork]`,
  );
  process.exit(2);
}

const positionals: string[] = [];
const flags: Record<string, string | boolean> = {};

for (let i = 1; i < rawArgs.length; i++) {
  const arg = rawArgs[i];
  if (arg.startsWith("--")) {
    const key = arg.slice(2);
    const next = rawArgs[i + 1];
    if (next && !next.startsWith("--")) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = true;
    }
  } else {
    positionals.push(arg);
  }
}

const task = positionals.join(" ").trim();
if (!task) {
  console.error("Error: task description is required.");
  console.error(`  lyrie agent run "scan https://example.com for vulnerabilities"`);
  process.exit(2);
}

const modelFlag = typeof flags["model"] === "string" ? flags["model"] : undefined;
const timeoutSeconds = typeof flags["timeout"] === "string"
  ? parseInt(flags["timeout"], 10)
  : 300;
const contextMode = typeof flags["context"] === "string"
  ? flags["context"] as "isolated" | "fork"
  : "isolated";
const parentContext = typeof flags["parent-context"] === "string"
  ? flags["parent-context"]
  : undefined;
const asJson = flags["json"] === true;

// ─── Run ─────────────────────────────────────────────────────────────────────

if (!asJson) {
  console.log("");
  console.log("🤖 Lyrie Agent Runner  ·  Lyrie.ai by OTT Cybersecurity LLC");
  console.log("─────────────────────────────────────────────────────────────────");
  console.log(`Task   : ${task}`);
  if (modelFlag)     console.log(`Model  : ${modelFlag}`);
  console.log(`Timeout: ${timeoutSeconds}s`);
  console.log(`Context: ${contextMode}`);
  console.log("─────────────────────────────────────────────────────────────────");
  console.log("Running...\n");
}

const runner = new SubagentRunner();
const result = await runner.run(task, {
  model: modelFlag,
  timeoutSeconds,
  context: contextMode,
  parentContext,
});

if (asJson) {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(result.success ? 0 : 1);
}

console.log("─────────────────────────────────────────────────────────────────");
if (result.success) {
  console.log(`✅ Done  (${result.durationMs}ms · ${result.model})\n`);
  console.log(result.output);
} else {
  console.error(`❌ Failed (${result.durationMs}ms · ${result.model})`);
  console.error(`   ${result.error ?? "Unknown error"}`);
  if (result.output) console.error(`\n${result.output}`);
  process.exit(1);
}
