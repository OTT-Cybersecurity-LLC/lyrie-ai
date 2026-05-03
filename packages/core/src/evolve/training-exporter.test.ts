/**
 * Lyrie LyrieEvolve — TrainingExporter unit tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test, beforeEach } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";

import {
  TrainingExporter,
  TRAINING_EXPORTER_VERSION,
  type AtroposRecord,
  type OpenAISFTRecord,
  type ShareGPTRecord,
  type ExportOptions,
} from "./training-exporter";
import type { TaskOutcome } from "./scorer";

// ─── Helpers ───────────────────────────────────────────────────────────────

function tmpFile(suffix = ".jsonl"): string {
  return join(tmpdir(), `lyrie-test-${randomUUID()}${suffix}`);
}

function tmpOutcomesFile(outcomes: TaskOutcome[]): string {
  const path = tmpFile();
  writeFileSync(path, outcomes.map((o) => JSON.stringify(o)).join("\n") + "\n", "utf8");
  return path;
}

function makeOutcome(overrides: Partial<TaskOutcome> = {}): TaskOutcome {
  return {
    id: randomUUID(),
    timestamp: Date.now(),
    domain: "cyber",
    score: 1,
    signals: { confirmed: true, pocGenerated: true },
    summary: "XSS vulnerability confirmed with working PoC",
    useCount: 0,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
    ...overrides,
  };
}

function readJsonl<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as T);
}

// ─── TRAINING_EXPORTER_VERSION ─────────────────────────────────────────────

describe("TRAINING_EXPORTER_VERSION", () => {
  test("version string is defined and correct", () => {
    expect(TRAINING_EXPORTER_VERSION).toBe("lyrie-evolve-training-exporter-1.0.0");
  });
});

// ─── ExportOptions validation ─────────────────────────────────────────────

describe("ExportOptions defaults", () => {
  test("minScore defaults to 0.5", async () => {
    const outcomes = [makeOutcome({ score: 1 }), makeOutcome({ score: 0 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath, dryRun: false });
    const result = await exporter.export({ outputPath });
    expect(result.samplesExported).toBe(1); // only score >= 0.5
  });

  test("maxSamples defaults to 10000 (caps output)", async () => {
    const outcomes = Array.from({ length: 5 }, () => makeOutcome({ score: 1 }));
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath, dryRun: false });
    const result = await exporter.export({ outputPath, maxSamples: 3 });
    expect(result.samplesExported).toBe(3);
  });

  test("format defaults to atropos", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath, dryRun: false });
    await exporter.export({ outputPath });
    const records = readJsonl<AtroposRecord>(outputPath);
    expect(records[0]).toHaveProperty("reward");
    expect(records[0]).toHaveProperty("domain");
    expect(records[0]).toHaveProperty("task_id");
  });
});

// ─── Score filtering ────────────────────────────────────────────────────────

describe("Score filtering", () => {
  test("excludes outcomes below minScore", async () => {
    const outcomes = [
      makeOutcome({ score: 1 }),
      makeOutcome({ score: 0.5 }),
      makeOutcome({ score: 0 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, minScore: 0.5 });
    expect(result.samplesExported).toBe(2);
  });

  test("minScore=1.0 includes only perfect scores", async () => {
    const outcomes = [
      makeOutcome({ score: 1 }),
      makeOutcome({ score: 0.5 }),
      makeOutcome({ score: 0 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, minScore: 1.0 });
    expect(result.samplesExported).toBe(1);
  });

  test("minScore=0 includes all outcomes", async () => {
    const outcomes = [
      makeOutcome({ score: 1 }),
      makeOutcome({ score: 0.5 }),
      makeOutcome({ score: 0 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, minScore: 0 });
    expect(result.samplesExported).toBe(3);
  });

  test("empty outcomes file produces zero exports", async () => {
    const outcomesPath = tmpFile();
    writeFileSync(outcomesPath, "", "utf8");
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath });
    expect(result.samplesExported).toBe(0);
  });

  test("missing outcomes file produces zero exports", async () => {
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath: "/tmp/does-not-exist-lyrie.jsonl" });
    const result = await exporter.export({ outputPath });
    expect(result.samplesExported).toBe(0);
  });
});

// ─── Domain filtering ───────────────────────────────────────────────────────

describe("Domain filtering", () => {
  const domains: TaskOutcome["domain"][] = ["cyber", "seo", "trading", "code", "general"];

  test("domains=['all'] includes all domains", async () => {
    const outcomes = domains.map((d) => makeOutcome({ domain: d, score: 1 }));
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, domains: ["all"] });
    expect(result.samplesExported).toBe(5);
  });

  test("domains=['cyber'] includes only cyber outcomes", async () => {
    const outcomes = domains.map((d) => makeOutcome({ domain: d, score: 1 }));
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, domains: ["cyber"] });
    expect(result.samplesExported).toBe(1);
    expect(result.domainsBreakdown["cyber"]).toBe(1);
    expect(result.domainsBreakdown["seo"]).toBeUndefined();
  });

  test("domains=['cyber','code'] includes both", async () => {
    const outcomes = domains.map((d) => makeOutcome({ domain: d, score: 1 }));
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, domains: ["cyber", "code"] });
    expect(result.samplesExported).toBe(2);
  });
});

// ─── Domain breakdown accuracy ─────────────────────────────────────────────

describe("Domain breakdown accuracy", () => {
  test("breakdown counts match actual records", async () => {
    const outcomes = [
      makeOutcome({ domain: "cyber", score: 1 }),
      makeOutcome({ domain: "cyber", score: 1 }),
      makeOutcome({ domain: "seo", score: 1 }),
      makeOutcome({ domain: "code", score: 0.5 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, minScore: 0.5, domains: ["all"] });
    expect(result.domainsBreakdown["cyber"]).toBe(2);
    expect(result.domainsBreakdown["seo"]).toBe(1);
    expect(result.domainsBreakdown["code"]).toBe(1);
    expect(result.domainsBreakdown["trading"]).toBeUndefined();
  });

  test("breakdown sums equal samplesExported", async () => {
    const outcomes = [
      makeOutcome({ domain: "cyber", score: 1 }),
      makeOutcome({ domain: "seo", score: 1 }),
      makeOutcome({ domain: "trading", score: 1 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath, minScore: 0 });
    const total = Object.values(result.domainsBreakdown).reduce((a, b) => a + b, 0);
    expect(total).toBe(result.samplesExported);
  });
});

// ─── Atropos format structure ───────────────────────────────────────────────

describe("Atropos format", () => {
  test("each record has messages, reward, domain, task_id", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "atropos" });
    const records = readJsonl<AtroposRecord>(outputPath);
    expect(records[0]).toHaveProperty("messages");
    expect(records[0]).toHaveProperty("reward");
    expect(records[0]).toHaveProperty("domain");
    expect(records[0]).toHaveProperty("task_id");
  });

  test("reward field equals outcome score", async () => {
    const outcomes = [makeOutcome({ score: 0.5 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "atropos", minScore: 0 });
    const records = readJsonl<AtroposRecord>(outputPath);
    expect(records[0]!.reward).toBe(0.5);
  });

  test("messages has system, user, assistant roles", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "atropos" });
    const records = readJsonl<AtroposRecord>(outputPath);
    const roles = records[0]!.messages.map((m) => m.role);
    expect(roles).toContain("system");
    expect(roles).toContain("user");
    expect(roles).toContain("assistant");
  });

  test("system message contains 'Lyrie'", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "atropos" });
    const records = readJsonl<AtroposRecord>(outputPath);
    const sys = records[0]!.messages.find((m) => m.role === "system");
    expect(sys?.content).toContain("Lyrie");
  });

  test("task_id is a valid non-empty string", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "atropos" });
    const records = readJsonl<AtroposRecord>(outputPath);
    expect(typeof records[0]!.task_id).toBe("string");
    expect(records[0]!.task_id.length).toBeGreaterThan(0);
  });

  test("output is valid JSONL (each line parseable)", async () => {
    const outcomes = [makeOutcome({ score: 1 }), makeOutcome({ score: 0.5 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "atropos", minScore: 0 });
    const lines = readFileSync(outputPath, "utf8").split("\n").filter((l) => l.trim().length > 0);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });
});

// ─── OpenAI SFT format ─────────────────────────────────────────────────────

describe("openai-sft format", () => {
  test("each record has only a messages field", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "openai-sft" });
    const records = readJsonl<OpenAISFTRecord>(outputPath);
    expect(records[0]).toHaveProperty("messages");
    expect(records[0]).not.toHaveProperty("reward");
    expect(records[0]).not.toHaveProperty("domain");
  });

  test("messages roles are system/user/assistant", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "openai-sft" });
    const records = readJsonl<OpenAISFTRecord>(outputPath);
    const roles = records[0]!.messages.map((m) => m.role);
    expect(roles).toEqual(["system", "user", "assistant"]);
  });

  test("all message content fields are non-empty strings", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "openai-sft" });
    const records = readJsonl<OpenAISFTRecord>(outputPath);
    for (const msg of records[0]!.messages) {
      expect(typeof msg.content).toBe("string");
      expect(msg.content.length).toBeGreaterThan(0);
    }
  });
});

// ─── ShareGPT format ───────────────────────────────────────────────────────

describe("sharegpt format", () => {
  test("each record has conversations, reward, domain", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "sharegpt" });
    const records = readJsonl<ShareGPTRecord>(outputPath);
    expect(records[0]).toHaveProperty("conversations");
    expect(records[0]).toHaveProperty("reward");
    expect(records[0]).toHaveProperty("domain");
  });

  test("conversations use from: system/human/gpt roles", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath, format: "sharegpt" });
    const records = readJsonl<ShareGPTRecord>(outputPath);
    const froms = records[0]!.conversations.map((c) => c.from);
    expect(froms).toContain("system");
    expect(froms).toContain("human");
    expect(froms).toContain("gpt");
  });
});

// ─── File output ───────────────────────────────────────────────────────────

describe("File output", () => {
  test("output file is written to correct path", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    await exporter.export({ outputPath });
    expect(existsSync(outputPath)).toBe(true);
  });

  test("result.outputPath matches requested path", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath });
    expect(result.outputPath).toBe(outputPath);
  });

  test("sizeBytes is greater than zero for non-empty export", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath });
    const result = await exporter.export({ outputPath });
    expect(result.sizeBytes).toBeGreaterThan(0);
  });

  test("dryRun does not write file", async () => {
    const outcomes = [makeOutcome({ score: 1 })];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const outputPath = tmpFile();
    const exporter = new TrainingExporter({ outcomesPath, dryRun: true });
    await exporter.export({ outputPath });
    expect(existsSync(outputPath)).toBe(false);
  });
});

// ─── Status ────────────────────────────────────────────────────────────────

describe("status()", () => {
  test("returns correct totalOutcomes and readySamples", () => {
    const outcomes = [
      makeOutcome({ score: 1 }),
      makeOutcome({ score: 0.5 }),
      makeOutcome({ score: 0 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const exporter = new TrainingExporter({ outcomesPath });
    const status = exporter.status();
    expect(status.totalOutcomes).toBe(3);
    expect(status.readySamples).toBe(2); // score >= 0.5
  });

  test("byDomain breakdown is accurate", () => {
    const outcomes = [
      makeOutcome({ domain: "cyber", score: 1 }),
      makeOutcome({ domain: "seo", score: 1 }),
      makeOutcome({ domain: "seo", score: 1 }),
    ];
    const outcomesPath = tmpOutcomesFile(outcomes);
    const exporter = new TrainingExporter({ outcomesPath });
    const status = exporter.status();
    expect(status.byDomain["cyber"]).toBe(1);
    expect(status.byDomain["seo"]).toBe(2);
  });

  test("returns outcomesPath", () => {
    const outcomesPath = tmpFile();
    writeFileSync(outcomesPath, "", "utf8");
    const exporter = new TrainingExporter({ outcomesPath });
    const status = exporter.status();
    expect(status.outcomesPath).toBe(outcomesPath);
  });

  test("empty file gives zeros", () => {
    const outcomesPath = tmpFile();
    writeFileSync(outcomesPath, "", "utf8");
    const exporter = new TrainingExporter({ outcomesPath });
    const status = exporter.status();
    expect(status.totalOutcomes).toBe(0);
    expect(status.readySamples).toBe(0);
  });
});
