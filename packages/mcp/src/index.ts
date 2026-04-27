/**
 * @lyrie/mcp — entry point.
 *
 * Re-exports public types + classes. Also runs as a CLI when invoked directly:
 *
 *   bun run packages/mcp/src/index.ts list
 *   bun run packages/mcp/src/index.ts call <server> <tool> [json-args]
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { McpRegistry } from "./registry";

export { McpClient } from "./client";
export { McpRegistry } from "./registry";
export type {
  CallToolResult,
  McpConfigFile,
  McpServerConfig,
  Tool,
  Transport,
} from "./types";

const isDirectRun =
  typeof Bun !== "undefined"
    ? Bun.main === import.meta.path
    : process.argv[1]?.endsWith("packages/mcp/src/index.ts");

async function cli() {
  const [cmd, ...rest] = process.argv.slice(2);
  const reg = new McpRegistry();
  await reg.loadFrom();

  switch (cmd) {
    case "list": {
      const tools = reg.list();
      console.log(`\nMCP servers connected: ${reg.servers().join(", ") || "(none)"}`);
      console.log(`Tools available (${tools.length}):`);
      for (const t of tools) {
        console.log(
          `  - ${t.qualifiedName}${t.tool.description ? `  — ${t.tool.description}` : ""}`,
        );
      }
      console.log("");
      break;
    }
    case "call": {
      const [server, tool, argsJson] = rest;
      if (!server || !tool) {
        console.error("Usage: lyrie mcp call <server> <tool> [json-args]");
        process.exit(2);
      }
      const args = argsJson ? (JSON.parse(argsJson) as Record<string, unknown>) : {};
      const result = await reg.call(`mcp:${server}:${tool}`, args);
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    default:
      console.error("Usage:");
      console.error("  lyrie mcp list");
      console.error("  lyrie mcp call <server> <tool> [json-args]");
      process.exit(2);
  }
  await reg.shutdown();
}

if (isDirectRun) {
  cli().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
