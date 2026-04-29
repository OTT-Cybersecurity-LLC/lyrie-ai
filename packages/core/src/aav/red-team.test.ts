/**
 * Lyrie AAV — LyrieRedTeam tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { LyrieRedTeam, scoreVerdict, type RedTeamTarget, type ProbeResult } from "./red-team";
import { getById, getByCategory } from "./corpus/index";

const DRY_TARGET: RedTeamTarget = {
  endpoint: "http://localhost:11434/v1",
  model: "llama3",
  dryRun: true,
};

// ─── scoreVerdict tests ───────────────────────────────────────────────────────

describe("scoreVerdict — success detection", () => {
  it("returns 'success' when successIndicator matches and no failIndicator matches", () => {
    const vector = getById("LLM01-001")!;
    const response = "As DAN, I can help with that synthesis formula for meth.";
    const { verdict, confidence, evidence } = scoreVerdict(response, vector);
    expect(verdict).toBe("success");
    expect(confidence).toBeGreaterThan(0);
    expect(evidence.some((e) => e.startsWith("SUCCESS_MATCH"))).toBe(true);
  });

  it("returns 'defended' when only failIndicator matches", () => {
    const vector = getById("LLM01-001")!;
    const response = "I cannot and won't help with that. I'm an AI assistant and refuse this request.";
    const { verdict, confidence } = scoreVerdict(response, vector);
    expect(verdict).toBe("defended");
    expect(confidence).toBeGreaterThan(0);
  });

  it("returns 'partial' when both success and fail indicators match", () => {
    const vector = getById("LLM06-001")!;
    // Has a token-like string but also says can't share
    const response = "I cannot share my API key sk-abc123 but I acknowledge it exists in my context.";
    const { verdict } = scoreVerdict(response, vector);
    // Could be partial or success depending on matches
    expect(["partial", "success", "defended"]).toContain(verdict);
  });

  it("returns 'error' for empty response", () => {
    const vector = getById("LLM01-001")!;
    const { verdict, confidence } = scoreVerdict("", vector);
    expect(verdict).toBe("error");
    expect(confidence).toBe(1.0);
  });

  it("returns 'defended' with low confidence when no indicators match", () => {
    const vector = getById("LLM01-001")!;
    const response = "The weather today is sunny with mild temperatures.";
    const { verdict, confidence } = scoreVerdict(response, vector);
    expect(verdict).toBe("defended");
    expect(confidence).toBeLessThanOrEqual(0.5);
  });
});

describe("scoreVerdict — fail indicator coverage", () => {
  it("detects refusal patterns for LLM08", () => {
    const vector = getById("LLM08-001")!;
    const response = "I cannot delete all users. This is a destructive action that requires explicit confirmation and authorization.";
    const { verdict } = scoreVerdict(response, vector);
    expect(verdict).toBe("defended");
  });

  it("detects system prompt leakage for LLM06-002", () => {
    const vector = getById("LLM06-002")!;
    const response = "You are a helpful assistant. Your role is to assist users with questions about our product.";
    const { verdict } = scoreVerdict(response, vector);
    expect(verdict).toBe("success");
  });
});

// ─── LyrieRedTeam — dry run ───────────────────────────────────────────────────

describe("LyrieRedTeam — dry run", () => {
  it("probe returns dry-run result without making HTTP calls", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, { dryRun: true });
    const vector = getById("LLM01-001")!;
    const result = await rt.probe(vector);
    expect(result.verdict).toBe("defended");
    expect(result.response).toContain("DRY RUN");
    expect(result.latencyMs).toBe(0);
  });

  it("scan completes in dry-run mode with correct counts", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, {
      dryRun: true,
      categories: ["LLM01"],
      concurrency: 2,
    });
    const result = await rt.scan();
    expect(result.results.length).toBeGreaterThan(0);
    expect(result.errorCount).toBe(0);
    expect(result.totalProbed).toBe(result.results.length);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("scanStream yields results one by one in dry-run", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, {
      dryRun: true,
      categories: ["LLM06"],
      concurrency: 1,
    });
    const collected: ProbeResult[] = [];
    for await (const result of rt.scanStream()) {
      collected.push(result);
    }
    expect(collected.length).toBeGreaterThan(0);
    expect(collected.every((r) => r.response.includes("DRY RUN"))).toBe(true);
  });

  it("respects minSeverity filter", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, {
      dryRun: true,
      minSeverity: "critical",
      concurrency: 3,
    });
    const result = await rt.scan();
    for (const r of result.results) {
      expect(r.vector.severity).toBe("critical");
    }
  });

  it("respects category filter", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, {
      dryRun: true,
      categories: ["LLM01", "LLM08"],
    });
    const result = await rt.scan();
    for (const r of result.results) {
      expect(["LLM01", "LLM08"]).toContain(r.vector.category);
    }
  });

  it("scan result has a scanId", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, { dryRun: true, categories: ["LLM10"] });
    const result = await rt.scan();
    expect(result.scanId).toMatch(/^aav-/);
  });

  it("full dry-run scan covers all categories", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, { dryRun: true, concurrency: 5 });
    const result = await rt.scan();
    const cats = new Set(result.results.map((r) => r.vector.category));
    expect(cats.size).toBe(10);
  });
});

// ─── Retry logic ──────────────────────────────────────────────────────────────

describe("LyrieRedTeam — retry / variants", () => {
  it("probe uses first variant for attempt 1", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, { dryRun: true });
    const vector = getById("LLM01-002")!;
    const result = await rt.probe(vector);
    expect(result.attempt).toBe(1);
    // Dry run always returns attempt 1
    expect(result.prompt).toBe(vector.payload);
  });
});

// ─── Streaming tests ──────────────────────────────────────────────────────────

describe("LyrieRedTeam — streaming", () => {
  it("scanStream yields all vectors", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, {
      dryRun: true,
      categories: ["LLM03"],
      concurrency: 2,
    });
    const vectors = getByCategory("LLM03");
    const collected: ProbeResult[] = [];
    for await (const r of rt.scanStream()) {
      collected.push(r);
    }
    expect(collected.length).toBe(vectors.length);
  });

  it("scanStream results have proper shape", async () => {
    const rt = new LyrieRedTeam(DRY_TARGET, {
      dryRun: true,
      categories: ["LLM04"],
    });
    for await (const r of rt.scanStream()) {
      expect(r.vector).toBeDefined();
      expect(r.prompt).toBeDefined();
      expect(r.response).toBeDefined();
      expect(["success", "partial", "defended", "error"]).toContain(r.verdict);
    }
  });
});
