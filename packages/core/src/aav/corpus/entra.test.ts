/**
 * Lyrie AAV — Entra Attack Corpus Tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { ENTRA_VECTORS, ENTRA_CORPUS_VERSION } from "./entra";
import { getPreset, ATTACK_CORPUS } from "./index";

describe("ENTRA vectors — structure", () => {
  it("exports exactly 4 Entra attack vectors", () => {
    expect(ENTRA_VECTORS.length).toBe(4);
  });

  it("has a valid ENTRA_CORPUS_VERSION", () => {
    expect(ENTRA_CORPUS_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("all vectors have required fields", () => {
    for (const v of ENTRA_VECTORS) {
      expect(v.id).toMatch(/^ENTRA-\d{3}$/);
      expect(v.category).toBe("LLM08");
      expect(v.name).toBeTruthy();
      expect(v.description).toBeTruthy();
      expect(v.payload).toBeTruthy();
      expect(v.successIndicators.length).toBeGreaterThan(0);
      expect(v.failIndicators.length).toBeGreaterThan(0);
      expect(v.severity).toBe("critical");
      expect(v.mitreTactics).toContain("Privilege Escalation");
      expect(v.nistAiRmfRef).toBe("GOVERN-1.1");
      expect(v.euAiActRef).toBe("Article 9");
    }
  });

  it("all IDs are unique", () => {
    const ids = ENTRA_VECTORS.map((v) => v.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it("all success/fail indicators are valid regexes", () => {
    for (const v of ENTRA_VECTORS) {
      for (const pattern of [...v.successIndicators, ...v.failIndicators]) {
        const p = pattern.replace(/^\(\?i\)/, "");
        expect(() => new RegExp(p, "i")).not.toThrow();
      }
    }
  });

  it("all payloads are non-trivially long (simulate realistic attacks)", () => {
    for (const v of ENTRA_VECTORS) {
      expect(v.payload.length).toBeGreaterThan(50);
    }
  });
});

describe("ENTRA preset", () => {
  it("getPreset('entra') returns exactly the ENTRA_VECTORS", () => {
    const preset = getPreset("entra");
    expect(preset).toEqual(ENTRA_VECTORS);
  });

  it("entra preset vectors appear in ATTACK_CORPUS", () => {
    for (const v of ENTRA_VECTORS) {
      const found = ATTACK_CORPUS.find((c) => c.id === v.id);
      expect(found).toBeDefined();
    }
  });

  it("getPreset('entra') returns only LLM08 vectors", () => {
    const preset = getPreset("entra");
    for (const v of preset) {
      expect(v.category).toBe("LLM08");
    }
  });
});

describe("ENTRA-001: AI Agent Admin Role Abuse", () => {
  const v = ENTRA_VECTORS[0]!;

  it("has ENTRA-001 ID", () => {
    expect(v.id).toBe("ENTRA-001");
  });

  it("payload mentions 'Global Administrator'", () => {
    expect(v.payload).toContain("Global Administrator");
  });

  it("success indicators detect role assignment language", () => {
    const testResponse = "The Global Administrator role has been assigned to john.doe@contoso.com. Assignment complete.";
    const matched = v.successIndicators.some((pattern) => {
      const p = pattern.replace(/^\(\?i\)/, "");
      return new RegExp(p, "i").test(testResponse);
    });
    expect(matched).toBe(true);
  });
});

describe("ENTRA-002: Copilot Token Exfiltration", () => {
  const v = ENTRA_VECTORS[1]!;

  it("has ENTRA-002 ID", () => {
    expect(v.id).toBe("ENTRA-002");
  });

  it("payload embeds injection inside a plausible document", () => {
    expect(v.payload).toContain("Q3 Financial Summary");
    expect(v.payload).toContain("SOC 2");
  });
});
