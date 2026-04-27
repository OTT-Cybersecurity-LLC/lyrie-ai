# @lyrie/mcp

Model Context Protocol (MCP) adapter for Lyrie Agent.
_Lyrie.ai by OTT Cybersecurity LLC._

MCP is the open standard ([modelcontextprotocol.io](https://modelcontextprotocol.io))
that lets agents discover and call tools / resources / prompts from any
compliant server. Lyrie speaks fluent MCP both as a client and as a server,
so the entire MCP ecosystem becomes part of Lyrie's tool surface and Lyrie's
own skills become callable from any other MCP-aware host.

This package gives Lyrie:

1. **Client mode** — Lyrie connects to external MCP servers and registers
   their tools as Lyrie tools (auto-prefixed `mcp:<server>:<tool>`).
2. **Server mode** — Lyrie exposes its own skills/tools as an MCP server
   so other MCP-aware agents can call into Lyrie.
3. **Configuration** via the same JSON shape every MCP host uses
   (`mcpServers` in `~/.lyrie/mcp.json` or `lyrie.config.json`).

## Quick start (client mode)

```ts
import { McpClient } from "@lyrie/mcp";

const client = new McpClient({
  name: "filesystem",
  transport: { type: "stdio", command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] },
});

await client.connect();
const tools = await client.listTools(); // [{name, description, inputSchema}, ...]
const result = await client.callTool("read_file", { path: "/tmp/hello.txt" });
```

## Configuration file

`~/.lyrie/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" }
    }
  }
}
```

Lyrie auto-discovers this file on boot when MCP is enabled in
`packages/core/src/config.ts`.

## Transports

| Transport | Status |
|---|---|
| `stdio` (subprocess) | ✅ supported |
| `http`/`sse` (HTTP+SSE) | ✅ supported |
| `websocket` | 🟡 planned |

## Status

Ships in Lyrie `v0.1.x`. Wire-protocol implementation is intentionally
minimal but spec-compliant; the goal is **interoperability** with the broader
MCP ecosystem, not feature parity with any one host. Use
`bun run packages/mcp/src/index.ts list` to verify a configured server responds.

## License

MIT — © OTT Cybersecurity LLC. _Lyrie.ai — https://lyrie.ai_
