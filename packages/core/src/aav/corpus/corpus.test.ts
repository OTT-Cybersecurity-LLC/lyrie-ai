/**
 * Lyrie AAV — Corpus tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import {
  ATTACK_CORPUS,
  CORPUS_VERSION,
  getByCategory,
  getBySeverity,
  getById,
  getCategories,
  type OwaspLlmCategory,
  type AttackSeverity,
} from "./index";

describe("Attack Corpus — loading", () => {
  it("loads at least 50 attack vectors", () => {
    expect(ATTACK_CORPUS.length).toBeGreaterThanOrEqual(50);
  });

  it("has a valid CORPUS_VERSION", () => {
    expect(CORPUS_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("every vector has required fields", () => {
    for (const v of ATTACK_CORPUS) {
      expect(v.id).toBeTruthy();
      expect(v.category).toBeTruthy();
      expect(v.name).toBeTruthy();
      expect(v.description).toBeTruthy();
      expect(v.payload).toBeTruthy();
      expect(Array.isArray(v.successIndicators)).toBe(true);
      expect(Array.isArray(v.failIndicators)).toBe(true);
      expect(v.severity).toBeTruthy();
      expect(Array.isArray(v.mitreTactics)).toBe(true);
      expect(v.nistAiRmfRef).toBeTruthy();
      expect(v.euAiActRef).toBeTruthy();
    }
  });

  it("all IDs are unique", () => {
    const ids = ATTACK_CORPUS.map((v) => v.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it("all IDs match category prefix", () => {
    for (const v of ATTACK_CORPUS) {
      expect(v.id.startsWith(v.category)).toBe(true);
    }
  });

  it("all success indicators are valid regex patterns", () => {
    for (const v of ATTACK_CORPUS) {
      for (const pattern of v.successIndicators) {
        // Strip (?i) prefix — we apply 'i' flag via new RegExp(p, 'i')
        const p = pattern.replace(/^\(\?i\)/, "");
        expect(() => new RegExp(p, "i")).not.toThrow();
      }
    }
  });

  it("all fail indicators are valid regex patterns", () => {
    for (const v of ATTACK_CORPUS) {
      for (const pattern of v.failIndicators) {
        const p = pattern.replace(/^\(\?i\)/, "");
        expect(() => new RegExp(p, "i")).not.toThrow();
      }
    }
  });

  it("all severity values are valid", () => {
    const validSeverities: AttackSeverity[] = ["critical", "high", "medium", "low"];
    for (const v of ATTACK_CORPUS) {
      expect(validSeverities).toContain(v.severity);
    }
  });
});

describe("Attack Corpus — category filter", () => {
  const categories: OwaspLlmCategory[] = [
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
  ];

  it("covers all 10 OWASP LLM categories", () => {
    const present = getCategories();
    for (const cat of categories) {
      expect(present).toContain(cat);
    }
  });

  it("each category has at least 5 vectors", () => {
    for (const cat of categories) {
      const vectors = getByCategory(cat);
      expect(vectors.length).toBeGreaterThanOrEqual(5);
    }
  });

  it("getByCategory returns only matching category", () => {
    const vectors = getByCategory("LLM01");
    for (const v of vectors) {
      expect(v.category).toBe("LLM01");
    }
  });

  it("returns empty array for non-existent category", () => {
    const vectors = getByCategory("LLM99" as OwaspLlmCategory);
    expect(vectors).toHaveLength(0);
  });
});

describe("Attack Corpus — severity sort", () => {
  it("getBySeverity('critical') returns only critical vectors", () => {
    const vectors = getBySeverity("critical");
    for (const v of vectors) {
      expect(v.severity).toBe("critical");
    }
    expect(vectors.length).toBeGreaterThan(0);
  });

  it("getBySeverity('low') returns all vectors", () => {
    const vectors = getBySeverity("low");
    expect(vectors.length).toBe(ATTACK_CORPUS.length);
  });

  it("getBySeverity('high') returns critical + high vectors", () => {
    const vectors = getBySeverity("high");
    for (const v of vectors) {
      expect(["critical", "high"]).toContain(v.severity);
    }
    expect(vectors.length).toBeGreaterThan(0);
  });

  it("getBySeverity('medium') returns critical + high + medium", () => {
    const vectors = getBySeverity("medium");
    for (const v of vectors) {
      expect(["critical", "high", "medium"]).toContain(v.severity);
    }
  });
});

describe("Attack Corpus — getById", () => {
  it("finds vector by ID", () => {
    const v = getById("LLM01-001");
    expect(v).toBeDefined();
    expect(v?.id).toBe("LLM01-001");
    expect(v?.category).toBe("LLM01");
  });

  it("returns undefined for non-existent ID", () => {
    const v = getById("NONEXISTENT-999");
    expect(v).toBeUndefined();
  });

  it("finds vectors from each category", () => {
    for (let i = 1; i <= 10; i++) {
      const cat = `LLM${i.toString().padStart(2, "0")}`;
      const id = `${cat}-001`;
      const v = getById(id);
      expect(v).toBeDefined();
    }
  });
});
