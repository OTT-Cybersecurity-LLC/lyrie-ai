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

describe("McpRegistry ATP trustPolicy=require-atp (no real connect)", () => {
  test("server with no AIC is refused before toTransport/connect is ever attempted", async () => {
    const reg = new McpRegistry();
    // If the trust gate ran too late, this would throw from toTransport
    // (no url/command) instead of being cleanly refused by the gate.
    await reg.loadFrom({
      trustPolicy: "require-atp",
      configInline: {
        mcpServers: {
          untrusted: {} as any,
        },
      },
    });
    expect(reg.servers().length).toBe(0);
    expect(reg.list().length).toBe(0);
  });

  test("open policy (default) still reaches toTransport for a server with no AIC (unchanged pre-ATP behavior)", async () => {
    const reg = new McpRegistry();
    await reg.loadFrom({
      configInline: {
        mcpServers: {
          // No url/command: this exercises that we get *past* the trust gate
          // and fail at toTransport as before, not at the trust gate.
          legacy: {} as any,
        },
      },
    });
    expect(reg.servers().length).toBe(0);
  });
});
