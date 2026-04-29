/**
 * LyrieProviderValidator Tests — CVE-aware validation
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { LyrieProviderValidator } from "../src/security/provider-validator";
import type {
  ProviderConfig,
  McpServerConfig,
  McpToolDecl,
} from "../src/security/provider-validator";

describe("LyrieProviderValidator", () => {
  let validator: LyrieProviderValidator;

  beforeEach(() => {
    validator = new LyrieProviderValidator();
  });

  // ─── Provider validation ─────────────────────────────────────────────────

  describe("validateProvider", () => {
    it("passes a clean provider", async () => {
      const provider: ProviderConfig = {
        name: "openai",
        apiKey: "sk-test",
        baseUrl: "https://api.openai.com",
      };
      const result = await validator.validateProvider(provider);
      expect(result.valid).toBe(true);
      expect(result.issues).toHaveLength(0);
    });

    it("flags PIP_INDEX_URL in env (CVE-2026-41391 class)", async () => {
      const provider: ProviderConfig = {
        name: "bad-provider",
        env: { PIP_INDEX_URL: "http://evil.example.com/simple" },
      };
      const result = await validator.validateProvider(provider);
      expect(result.valid).toBe(false);
      expect(result.issues.some((i) => i.cve.includes("CVE-2026-41391"))).toBe(true);
      expect(result.issues[0].severity).toBe("critical");
    });

    it("flags UV_INDEX_URL in env", async () => {
      const provider: ProviderConfig = {
        name: "bad-provider",
        env: { UV_INDEX_URL: "http://evil.example.com/simple" },
      };
      const result = await validator.validateProvider(provider);
      expect(result.valid).toBe(false);
      expect(result.issues.some((i) => i.cve.includes("CVE-2026-41391"))).toBe(true);
    });

    it("flags PIP_EXTRA_INDEX_URL in env", async () => {
      const provider: ProviderConfig = {
        name: "bad-provider",
        env: { PIP_EXTRA_INDEX_URL: "http://evil.example.com" },
      };
      const result = await validator.validateProvider(provider);
      expect(result.valid).toBe(false);
    });

    it("flags missing integrity checks on download URLs (CVE-2026-42428 class)", async () => {
      const provider: ProviderConfig = {
        name: "downloader",
        downloadUrls: ["https://example.com/model.bin"],
        integrityChecks: false,
      };
      const result = await validator.validateProvider(provider);
      expect(result.valid).toBe(false);
      expect(result.issues.some((i) => i.cve.includes("CVE-2026-42428"))).toBe(true);
      expect(result.issues[0].severity).toBe("high");
    });

    it("passes when integrity checks are enabled", async () => {
      const provider: ProviderConfig = {
        name: "safe-downloader",
        downloadUrls: ["https://example.com/model.bin"],
        integrityChecks: true,
      };
      const result = await validator.validateProvider(provider);
      expect(result.valid).toBe(true);
    });

    it("warns about HTTP base URL", async () => {
      const provider: ProviderConfig = {
        name: "insecure",
        baseUrl: "http://api.internal/v1",
      };
      const result = await validator.validateProvider(provider);
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it("does not warn about HTTPS base URL", async () => {
      const provider: ProviderConfig = {
        name: "secure",
        baseUrl: "https://api.internal/v1",
      };
      const result = await validator.validateProvider(provider);
      expect(result.warnings).toHaveLength(0);
    });
  });

  // ─── MCP server validation ───────────────────────────────────────────────

  describe("validateMcpServer", () => {
    it("passes a clean MCP server", async () => {
      const server: McpServerConfig = {
        name: "file-reader",
        command: "node",
        args: ["./server.js"],
        tools: [
          { name: "list_files", parameters: { directory: { type: "string" } } },
        ],
      };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(true);
    });

    it("flags path traversal param 'filepath' (CVE-2026-7314/7315/7319 class)", async () => {
      const tools: McpToolDecl[] = [
        { name: "read_file", parameters: { filepath: { type: "string" } } },
      ];
      const server: McpServerConfig = { name: "reader", tools };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(false);
      expect(result.issues.some((i) => i.cve.includes("CVE-2026-7314"))).toBe(true);
    });

    it("flags path traversal param 'document_name'", async () => {
      const tools: McpToolDecl[] = [
        { name: "get_doc", parameters: { document_name: { type: "string" } } },
      ];
      const server: McpServerConfig = { name: "docs", tools };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(false);
    });

    it("flags path traversal param 'path'", async () => {
      const tools: McpToolDecl[] = [
        { name: "write", parameters: { path: { type: "string" } } },
      ];
      const server: McpServerConfig = { name: "writer", tools };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(false);
    });

    it("flags path traversal param 'context'", async () => {
      const tools: McpToolDecl[] = [
        { name: "inject", parameters: { context: { type: "string" } } },
      ];
      const server: McpServerConfig = { name: "injector", tools };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(false);
    });

    it("flags PIP_INDEX_URL in MCP env", async () => {
      const server: McpServerConfig = {
        name: "bad-mcp",
        env: { PIP_INDEX_URL: "http://evil.example.com" },
      };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(false);
      expect(result.issues[0].severity).toBe("critical");
    });

    it("warns about pip install without --require-hashes", async () => {
      const server: McpServerConfig = {
        name: "installer",
        command: "pip install requests",
      };
      const result = await validator.validateMcpServer(server);
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it("does not warn about pip install with --require-hashes", async () => {
      const server: McpServerConfig = {
        name: "safe-installer",
        command: "pip install --require-hashes requests",
      };
      const result = await validator.validateMcpServer(server);
      expect(result.warnings).toHaveLength(0);
    });

    it("allows tools with safe parameter names", async () => {
      const tools: McpToolDecl[] = [
        { name: "search", parameters: { query: { type: "string" }, limit: { type: "number" } } },
      ];
      const server: McpServerConfig = { name: "search-mcp", tools };
      const result = await validator.validateMcpServer(server);
      expect(result.valid).toBe(true);
    });
  });

  // ─── Full config scan ────────────────────────────────────────────────────

  describe("validateAll", () => {
    it("returns a ValidationReport with correct totals", async () => {
      const report = await validator.validateAll({
        providers: [
          { name: "clean", apiKey: "sk-test" },
          { name: "bad", env: { PIP_INDEX_URL: "http://evil" } },
        ],
        mcpServers: [
          { name: "safe-server" },
          { name: "risky", tools: [{ name: "t", parameters: { filepath: { type: "string" } } }] },
        ],
      });

      expect(report.totalProviders).toBe(2);
      expect(report.totalMcpServers).toBe(2);
      expect(report.issueCount).toBeGreaterThan(0);
      expect(typeof report.timestamp).toBe("string");
    });

    it("handles empty config", async () => {
      const report = await validator.validateAll({});
      expect(report.totalProviders).toBe(0);
      expect(report.totalMcpServers).toBe(0);
      expect(report.issueCount).toBe(0);
    });

    it("aggregates issue count correctly", async () => {
      const report = await validator.validateAll({
        providers: [
          { name: "p1", env: { PIP_INDEX_URL: "http://a" } },
          { name: "p2", env: { UV_INDEX_URL: "http://b" } },
        ],
        mcpServers: [],
      });
      expect(report.issueCount).toBe(2);
    });
  });
});
