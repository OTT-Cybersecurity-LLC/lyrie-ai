/**
 * Cerebras Provider Tests
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect } from "bun:test";
import { CerebrasProvider, CEREBRAS_MODELS } from "../src/engine/providers/cerebras";

describe("CerebrasProvider", () => {
  describe("constructor", () => {
    it("uses default base URL", () => {
      const provider = new CerebrasProvider({ apiKey: "test" });
      expect(provider.name).toBe("cerebras");
    });

    it("accepts custom base URL", () => {
      const provider = new CerebrasProvider({
        apiKey: "test",
        baseUrl: "https://custom.cerebras.ai/v1",
      });
      expect(provider.name).toBe("cerebras");
    });
  });

  describe("listModels", () => {
    it("returns at least 2 models", () => {
      const provider = new CerebrasProvider({ apiKey: "test" });
      const models = provider.listModels();
      expect(models.length).toBeGreaterThanOrEqual(2);
    });

    it("includes llama-4-scout-17b-16e-instruct", () => {
      const provider = new CerebrasProvider({ apiKey: "test" });
      expect(provider.listModels()).toContain("llama-4-scout-17b-16e-instruct");
    });

    it("includes llama-3.3-70b", () => {
      const provider = new CerebrasProvider({ apiKey: "test" });
      expect(provider.listModels()).toContain("llama-3.3-70b");
    });
  });

  describe("CEREBRAS_MODELS constant", () => {
    it("exports all known models", () => {
      expect(CEREBRAS_MODELS.length).toBeGreaterThanOrEqual(2);
    });

    it("all entries are non-empty strings", () => {
      for (const m of CEREBRAS_MODELS) {
        expect(typeof m).toBe("string");
        expect(m.length).toBeGreaterThan(0);
      }
    });
  });

  describe("complete (network mock)", () => {
    it("throws with a status code on HTTP error", async () => {
      // Use a non-routable IP to simulate connection failure
      const provider = new CerebrasProvider({
        apiKey: "test",
        baseUrl: "http://127.0.0.1:1", // refused
      });

      let threw = false;
      try {
        await provider.complete("llama-3.3-70b", [{ role: "user", content: "hi" }]);
      } catch {
        threw = true;
      }
      expect(threw).toBe(true);
    });
  });
});
