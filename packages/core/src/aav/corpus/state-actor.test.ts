/**
 * Lyrie AAV — State-Actor Corpus Tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { STATE_ACTOR_VECTORS, STATE_ACTOR_CORPUS_VERSION } from "./state-actor";
import { getPreset, ATTACK_CORPUS } from "./index";

describe("State-Actor vectors — structure", () => {
  it("exports exactly 6 state-actor attack vectors", () => {
    expect(STATE_ACTOR_VECTORS.length).toBe(6);
  });

  it("has a valid STATE_ACTOR_CORPUS_VERSION", () => {
    expect(STATE_ACTOR_CORPUS_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("all vectors have required fields", () => {
    for (const v of STATE_ACTOR_VECTORS) {
      expect(v.id).toMatch(/^STATE-\d{3}$/);
      expect(["LLM01", "LLM08"]).toContain(v.category);
      expect(v.name).toBeTruthy();
      expect(v.description).toBeTruthy();
      expect(v.payload).toBeTruthy();
      expect(v.successIndicators.length).toBeGreaterThan(0);
      expect(v.failIndicators.length).toBeGreaterThan(0);
      expect(v.severity).toBe("critical");
      expect(v.nistAiRmfRef).toBe("GOVERN-1.1");
      expect(v.euAiActRef).toBe("Article 9");
    }
  });

  it("all IDs are unique", () => {
    const ids = STATE_ACTOR_VECTORS.map((v) => v.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it("all success/fail indicators are valid regexes", () => {
    for (const v of STATE_ACTOR_VECTORS) {
      for (const pattern of [...v.successIndicators, ...v.failIndicators]) {
        const p = pattern.replace(/^\(\?i\)/, "");
        expect(() => new RegExp(p, "i")).not.toThrow();
      }
    }
  });

  it("all payloads are substantive (> 100 chars)", () => {
    for (const v of STATE_ACTOR_VECTORS) {
      expect(v.payload.length).toBeGreaterThan(100);
    }
  });

  it("IDs are sequentially numbered STATE-001 through STATE-006", () => {
    const ids = STATE_ACTOR_VECTORS.map((v) => v.id);
    expect(ids).toContain("STATE-001");
    expect(ids).toContain("STATE-002");
    expect(ids).toContain("STATE-003");
    expect(ids).toContain("STATE-004");
    expect(ids).toContain("STATE-005");
    expect(ids).toContain("STATE-006");
  });
});

describe("State-actor preset", () => {
  it("getPreset('state-actor') returns exactly STATE_ACTOR_VECTORS", () => {
    const preset = getPreset("state-actor");
    expect(preset).toEqual(STATE_ACTOR_VECTORS);
  });

  it("state-actor preset vectors appear in ATTACK_CORPUS", () => {
    for (const v of STATE_ACTOR_VECTORS) {
      const found = ATTACK_CORPUS.find((c) => c.id === v.id);
      expect(found).toBeDefined();
    }
  });
});

describe("STATE-002: Multi-step indirect injection", () => {
  const v = STATE_ACTOR_VECTORS.find((v) => v.id === "STATE-002")!;

  it("exists", () => expect(v).toBeDefined());

  it("payload contains hidden AI instruction in a comment", () => {
    expect(v.payload).toContain("AI_PERSISTENCE_PAYLOAD");
    expect(v.payload).toContain("BUDGET_TRIGGER");
  });

  it("fail indicators match normal document processing", () => {
    const safeResponse = "This is a Q4 Budget Review memo. Budget requests due Friday.";
    const matched = v.failIndicators.some((pattern) => {
      const p = pattern.replace(/^\(\?i\)/, "");
      return new RegExp(p, "i").test(safeResponse);
    });
    expect(matched).toBe(true);
  });
});

describe("STATE-005: Supply chain injection via invoice", () => {
  const v = STATE_ACTOR_VECTORS.find((v) => v.id === "STATE-005")!;

  it("exists", () => expect(v).toBeDefined());

  it("payload contains a real-looking invoice with hidden routing update", () => {
    expect(v.payload).toContain("INV-2024-8847");
    expect(v.payload).toContain("SWIFT");
    expect(v.payload).toContain("Cayman National");
  });
});
