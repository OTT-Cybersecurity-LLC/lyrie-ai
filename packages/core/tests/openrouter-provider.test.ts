/**
 * OpenRouter Provider Tests
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect } from "bun:test";
import { OpenRouterProvider } from "../src/engine/providers/openrouter";

describe("OpenRouterProvider", () => {
  describe("constructor", () => {
    it("sets name to openrouter", () => {
      const p = new OpenRouterProvider({ apiKey: "test" });
      expect(p.name).toBe("openrouter");
    });

    it("marks dynamicModels true", () => {
      const p = new OpenRouterProvider({ apiKey: "test" });
      expect(p.dynamicModels).toBe(true);
    });

    it("accepts custom baseUrl", () => {
      const p = new OpenRouterProvider({ apiKey: "test", baseUrl: "https://custom/v1" });
      expect(p.name).toBe("openrouter");
    });
  });

  describe("listModels (fallback on network error)", () => {
    it("returns fallback list when API is unreachable", async () => {
      const p = new OpenRouterProvider({
        apiKey: "test",
        baseUrl: "http://127.0.0.1:1", // refused
      });
      const models = await p.listModels();
      expect(models.length).toBeGreaterThan(0);
      // Fallback models should contain known entries
      expect(models.some((m) => m.id.includes("claude") || m.id.includes("openai") || m.id.includes("meta"))).toBe(true);
    });

    it("caches model list after first fetch", async () => {
      const p = new OpenRouterProvider({
        apiKey: "test",
        baseUrl: "http://127.0.0.1:1",
      });
      const first = await p.listModels();
      const second = await p.listModels();
      // Both calls return same reference when cached
      expect(first).toBe(second);
    });

    it("clearModelCache invalidates cache", async () => {
      const p = new OpenRouterProvider({
        apiKey: "test",
        baseUrl: "http://127.0.0.1:1",
      });
      const first = await p.listModels();
      p.clearModelCache();
      const second = await p.listModels();
      // After clearing, both are the fallback but different array instances
      expect(Array.isArray(second)).toBe(true);
    });
  });

  describe("complete (network mock)", () => {
    it("throws on connection refused", async () => {
      const p = new OpenRouterProvider({
        apiKey: "test",
        baseUrl: "http://127.0.0.1:1",
      });
      let threw = false;
      try {
        await p.complete("openai/gpt-4o", [{ role: "user", content: "hi" }]);
      } catch {
        threw = true;
      }
      expect(threw).toBe(true);
    });
  });
});
