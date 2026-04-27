/**
 * McpRegistry — pure-function tests (no real subprocesses spawned).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";

import { McpRegistry } from "./registry";

describe("McpRegistry.toTransport", () => {
  test("stdio: command + args + env", () => {
    const t = McpRegistry.toTransport({
      command: "node",
      args: ["server.js"],
      env: { FOO: "1" },
    });
    expect(t).toEqual({
      type: "stdio",
      command: "node",
      args: ["server.js"],
      env: { FOO: "1" },
      cwd: undefined,
    });
  });

  test("http: url + headers", () => {
    const t = McpRegistry.toTransport({
      url: "https://example.com/mcp",
      headers: { Authorization: "Bearer x" },
    });
    expect(t).toEqual({
      type: "http",
      url: "https://example.com/mcp",
      headers: { Authorization: "Bearer x" },
    });
  });

  test("sse: explicit transportType=sse", () => {
    const t = McpRegistry.toTransport({
      url: "https://example.com/mcp",
      transportType: "sse",
    });
    expect(t.type).toBe("sse");
  });

  test("throws when neither url nor command provided", () => {
    expect(() => McpRegistry.toTransport({})).toThrow();
  });
});

describe("McpRegistry.loadConfig", () => {
  test("returns null when file is missing", () => {
    const r = McpRegistry.loadConfig("/tmp/nonexistent-mcp-9b8a7.json");
    expect(r).toBeNull();
  });
});

describe("McpRegistry inline config (no real connect)", () => {
  test("disabled servers are skipped", async () => {
    const reg = new McpRegistry();
    // Inline config with one disabled server — no connect attempted
    await reg.loadFrom({
      configInline: {
        mcpServers: {
          off: { command: "false", disabled: true },
        },
      },
    });
    expect(reg.servers().length).toBe(0);
  });

  test("invalid server config logs and continues", async () => {
    const reg = new McpRegistry();
    // No url or command → toTransport throws → caught + logged
    await reg.loadFrom({
      configInline: {
        mcpServers: {
          broken: {} as any,
        },
      },
    });
    expect(reg.list().length).toBe(0);
  });
});
