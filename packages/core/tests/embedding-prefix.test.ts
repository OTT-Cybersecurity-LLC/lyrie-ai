/**
 * Asymmetric Embedding Prefix Tests (Issue #69)
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect } from "bun:test";
import { applyEmbeddingPrefix, EMBEDDING_PREFIXES } from "../src/memory/memory-core";

describe("applyEmbeddingPrefix", () => {
  describe("nomic-embed-text", () => {
    it("applies search_query prefix", () => {
      const result = applyEmbeddingPrefix("what is lyrie", "nomic-embed-text", "search_query");
      expect(result).toBe("search_query: what is lyrie");
    });

    it("applies search_document prefix", () => {
      const result = applyEmbeddingPrefix("lyrie is an AI agent", "nomic-embed-text", "search_document");
      expect(result).toBe("search_document: lyrie is an AI agent");
    });

    it("applies classification prefix", () => {
      const result = applyEmbeddingPrefix("positive", "nomic-embed-text", "classification");
      expect(result).toBe("classification: positive");
    });

    it("applies clustering prefix", () => {
      const result = applyEmbeddingPrefix("topic text", "nomic-embed-text", "clustering");
      expect(result).toBe("clustering: topic text");
    });
  });

  describe("qwen3-embedding", () => {
    it("applies query prefix (non-empty)", () => {
      const result = applyEmbeddingPrefix("find relevant docs", "qwen3-embedding", "query");
      expect(result).toContain("find relevant docs");
      expect(result.length).toBeGreaterThan("find relevant docs".length);
    });

    it("applies passage prefix (empty — no prefix for passages)", () => {
      const result = applyEmbeddingPrefix("passage text", "qwen3-embedding", "passage");
      expect(result).toBe("passage text");
    });
  });

  describe("mxbai-embed-large", () => {
    it("applies search_query prefix", () => {
      const result = applyEmbeddingPrefix("query text", "mxbai-embed-large", "search_query");
      expect(result).toContain("query text");
      expect(result.length).toBeGreaterThan("query text".length);
    });

    it("applies search_document prefix (empty for mxbai)", () => {
      const result = applyEmbeddingPrefix("document text", "mxbai-embed-large", "search_document");
      expect(result).toBe("document text");
    });
  });

  describe("unknown model", () => {
    it("returns text unchanged for unknown model", () => {
      const result = applyEmbeddingPrefix("hello", "unknown-model", "search_query");
      expect(result).toBe("hello");
    });
  });

  describe("unknown input type", () => {
    it("returns text unchanged for unknown input type", () => {
      const result = applyEmbeddingPrefix("hello", "nomic-embed-text", "unknown_type");
      expect(result).toBe("hello");
    });
  });

  describe("EMBEDDING_PREFIXES constant", () => {
    it("exports nomic-embed-text prefixes", () => {
      expect(EMBEDDING_PREFIXES["nomic-embed-text"]).toBeDefined();
    });

    it("exports qwen3-embedding prefixes", () => {
      expect(EMBEDDING_PREFIXES["qwen3-embedding"]).toBeDefined();
    });

    it("exports mxbai-embed-large prefixes", () => {
      expect(EMBEDDING_PREFIXES["mxbai-embed-large"]).toBeDefined();
    });
  });
});
