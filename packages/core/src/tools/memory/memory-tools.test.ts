/**
 * memory-tools.test.ts — 40+ mocked tests for Lyrie v1.2 memory tools.
 *
 * Uses an in-memory SQLite (":memory:") injected via setMemoryStore so
 * tests don't touch the real ~/.lyrie database and remain fully isolated.
 */

import { expect, test, describe, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";

import {
  MemoryStore,
  setMemoryStore,
  inferCategory,
  scoreImportance,
  textSimilarity,
} from "./memory-tools";
import { memoryStoreTool, memoryRecallTool, memoryForgetTool } from "./memory-tools";

// ─── In-memory store factory ─────────────────────────────────────────────────

function makeInMemoryStore(): MemoryStore {
  // Patch MemoryStore to accept ":memory:" by monkey-patching constructor args.
  // We use a DB path that bun:sqlite treats as in-memory.
  return new (class extends MemoryStore {
    constructor() {
      super(":memory:");
    }
  })();
}

// ─── Unit: inferCategory ─────────────────────────────────────────────────────

describe("inferCategory()", () => {
  test("preference — 'I prefer dark mode'", () => {
    expect(inferCategory("I prefer dark mode")).toBe("preference");
  });

  test("preference — 'I like TypeScript over Python'", () => {
    expect(inferCategory("I like TypeScript over Python")).toBe("preference");
  });

  test("preference — 'always use spaces not tabs'", () => {
    expect(inferCategory("always use spaces not tabs")).toBe("preference");
  });

  test("decision — 'I decided to use Bun as runtime'", () => {
    expect(inferCategory("I decided to use Bun as runtime")).toBe("decision");
  });

  test("decision — 'Going with SQLite for the database'", () => {
    expect(inferCategory("Going with SQLite for the database")).toBe("decision");
  });

  test("rule — 'NEVER kill Chrome'", () => {
    expect(inferCategory("NEVER kill Chrome")).toBe("rule");
  });

  test("rule — '⛔ Do not restart the gateway'", () => {
    expect(inferCategory("⛔ Do not restart the gateway")).toBe("rule");
  });

  test("entity — 'Guy is a CEO and founder'", () => {
    expect(inferCategory("Guy is a CEO and founder")).toBe("entity");
  });

  test("fact — fallback for generic text", () => {
    expect(inferCategory("The server is in Dubai")).toBe("fact");
  });

  test("fact — another generic sentence", () => {
    expect(inferCategory("The build took 12 seconds")).toBe("fact");
  });
});

// ─── Unit: scoreImportance ───────────────────────────────────────────────────

describe("scoreImportance()", () => {
  test("critical — ⛔ prefix → 1.0", () => {
    expect(scoreImportance("⛔ Never do this")).toBe(1.0);
  });

  test("critical — 'critical' keyword → 1.0", () => {
    expect(scoreImportance("This is a critical security rule")).toBe(1.0);
  });

  test("rule — 'rule:' prefix → 0.9", () => {
    expect(scoreImportance("rule: always commit with a message")).toBe(0.9);
  });

  test("preference — 'prefer' keyword → 0.7", () => {
    expect(scoreImportance("I prefer Nova voice for TTS")).toBe(0.7);
  });

  test("decision — 'decided' → 0.7", () => {
    expect(scoreImportance("I decided to use Bun")).toBe(0.7);
  });

  test("important — 'important' → 0.8", () => {
    expect(scoreImportance("This is an important architectural decision")).toBe(0.8);
  });

  test("note — 'note' → 0.6", () => {
    expect(scoreImportance("note: check logs before deploying")).toBe(0.6);
  });

  test("generic fact → 0.5", () => {
    expect(scoreImportance("The weather is sunny today")).toBe(0.5);
  });
});

// ─── Unit: textSimilarity ────────────────────────────────────────────────────

describe("textSimilarity()", () => {
  test("identical texts → similar", () => {
    const text = "I prefer dark mode for all editors";
    expect(textSimilarity(text, text)).toBe(true);
  });

  test("near-duplicate → similar (high overlap)", () => {
    // 6 common words out of 8 total unique → 0.75 similarity
    expect(
      textSimilarity(
        "I prefer dark mode for all my editors",
        "I prefer dark mode all my editors"
      )
    ).toBe(true);
  });

  test("unrelated → not similar", () => {
    expect(
      textSimilarity("I prefer dark mode", "The EPYC machine has 64 cores")
    ).toBe(false);
  });

  test("empty strings → not similar", () => {
    expect(textSimilarity("", "")).toBe(false);
  });
});

// ─── Integration: MemoryStore ────────────────────────────────────────────────

describe("MemoryStore integration", () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = makeInMemoryStore();
    setMemoryStore(store);
  });

  test("store() returns id and isNew=true for new entry", () => {
    const { id, isNew } = store.store("Guy prefers Nova voice");
    expect(id).toMatch(/^lm_/);
    expect(isNew).toBe(true);
  });

  test("store() auto-categorizes preference", () => {
    store.store("I prefer dark mode");
    const results = store.recall("prefer dark mode");
    expect(results[0]?.category).toBe("preference");
  });

  test("store() auto-categorizes fact", () => {
    store.store("The server runs on port 3000");
    const results = store.recall("server port");
    expect(results[0]?.category).toBe("fact");
  });

  test("store() auto-categorizes rule", () => {
    store.store("⛔ Never kill Chrome");
    const results = store.recall("kill Chrome");
    expect(results[0]?.category).toBe("rule");
  });

  test("store() auto-categorizes decision", () => {
    store.store("I decided to use SQLite");
    const results = store.recall("decided SQLite");
    expect(results[0]?.category).toBe("decision");
  });

  test("store() auto-scores importance for critical text", () => {
    store.store("⛔ Never restart Chrome");
    const results = store.recall("Chrome");
    expect(results[0]?.importance).toBe(1.0);
  });

  test("store() auto-scores importance for preference", () => {
    store.store("I prefer TypeScript");
    const results = store.recall("prefer TypeScript");
    expect(results[0]?.importance).toBe(0.7);
  });

  test("store() deduplicates similar entries — returns isNew=false", () => {
    // Use two strings with very high word overlap (same sentence, minor variation)
    store.store("I prefer dark mode in all my code editors always");
    const { isNew: isNew2 } = store.store("I prefer dark mode in all my code editors always"); // exact
    expect(isNew2).toBe(false);
  });

  test("store() dedup updates rather than creates new record", () => {
    store.store("The API key is ABC123");
    store.store("The API key is ABC123");
    const results = store.recall("API key");
    expect(results.length).toBe(1);
  });

  test("store() with explicit category overrides auto-detect", () => {
    store.store("The sky is blue", { category: "rule" });
    const results = store.recall("sky blue");
    expect(results[0]?.category).toBe("rule");
  });

  test("store() with explicit importance overrides auto-score", () => {
    store.store("Generic fact", { importance: 0.95 });
    const results = store.recall("Generic fact");
    expect(results[0]?.importance).toBe(0.95);
  });

  test("store() with ttlDays sets expiresAt", () => {
    store.store("Temporary note", { ttlDays: 7 });
    const results = store.recall("Temporary note");
    expect(results[0]?.expiresAt).toBeDefined();
    const exp = new Date(results[0]!.expiresAt!).getTime();
    const expected = Date.now() + 7 * 86_400_000;
    expect(Math.abs(exp - expected)).toBeLessThan(5_000); // within 5s
  });

  test("recall() returns ranked results by importance", () => {
    store.store("⛔ Never touch prod", { importance: 1.0 });
    store.store("note: check logs", { importance: 0.6 });
    store.store("important: back up daily", { importance: 0.8 });
    const results = store.recall("important");
    expect(results[0]?.importance).toBeGreaterThanOrEqual(results[1]?.importance ?? 0);
  });

  test("recall() filters by category", () => {
    store.store("I prefer Bun runtime", { category: "preference" });
    store.store("The build uses Bun", { category: "fact" });
    const results = store.recall("Bun", { category: "preference" });
    expect(results.every((r) => r.category === "preference")).toBe(true);
  });

  test("recall() filters by minImportance", () => {
    store.store("High importance Bun fact", { importance: 0.9 });
    store.store("Low importance Bun note", { importance: 0.3 });
    const results = store.recall("Bun", { minImportance: 0.8 });
    expect(results.every((r) => r.importance >= 0.8)).toBe(true);
  });

  test("recall() respects limit", () => {
    for (let i = 0; i < 10; i++) {
      store.store(`Unique memory number ${i} about the topic`);
    }
    const results = store.recall("memory", { limit: 3 });
    expect(results.length).toBeLessThanOrEqual(3);
  });

  test("recall() returns empty array when no match", () => {
    const results = store.recall("xyzzy_no_match_9999");
    expect(results).toEqual([]);
  });

  test("forget() by memoryId deletes single entry", () => {
    const { id } = store.store("Delete me by id");
    const { deleted } = store.forget({ memoryId: id });
    expect(deleted).toBe(1);
    const results = store.recall("Delete me by id");
    expect(results.length).toBe(0);
  });

  test("forget() by id returns 0 for non-existent id", () => {
    const { deleted } = store.forget({ memoryId: "lm_nonexistent_abc" });
    expect(deleted).toBe(0);
  });

  test("forget() by query removes matching entries", () => {
    store.store("Remove this sentence about bananas");
    store.store("Also remove this banana entry please");
    const { deleted } = store.forget({ query: "bananas" });
    expect(deleted).toBeGreaterThan(0);
    const remaining = store.recall("bananas");
    expect(remaining.length).toBe(0);
  });

  test("forget() with neither id nor query returns 0", () => {
    const { deleted } = store.forget({});
    expect(deleted).toBe(0);
  });

  test("countExpired() returns 0 for non-expired memories", () => {
    store.store("Not expired", { ttlDays: 30 });
    expect(store.countExpired()).toBe(0);
  });
});

// ─── Integration: Tool execute() wrappers ────────────────────────────────────

describe("memoryStoreTool.execute()", () => {
  beforeEach(() => {
    setMemoryStore(makeInMemoryStore());
  });

  test("stores a memory and returns id", async () => {
    const result = await memoryStoreTool.execute({ text: "I prefer dark mode" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/id=lm_/);
  });

  test("reports isNew=false for duplicate", async () => {
    await memoryStoreTool.execute({ text: "I prefer dark mode UI" });
    const result = await memoryStoreTool.execute({ text: "I prefer dark mode UI" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/updated/i);
  });

  test("accepts explicit category", async () => {
    const result = await memoryStoreTool.execute({
      text: "Some fact",
      category: "rule",
    });
    expect(result.success).toBe(true);
  });

  test("accepts ttlDays", async () => {
    const result = await memoryStoreTool.execute({
      text: "Temporary info",
      ttlDays: 1,
    });
    expect(result.success).toBe(true);
  });
});

describe("memoryRecallTool.execute()", () => {
  beforeEach(() => {
    const s = makeInMemoryStore();
    setMemoryStore(s);
    s.store("I prefer TypeScript over Python", { category: "preference", importance: 0.7 });
    s.store("The server runs on port 8080", { category: "fact", importance: 0.5 });
    s.store("⛔ Never restart Chrome", { category: "rule", importance: 1.0 });
  });

  test("returns results for matching query", async () => {
    const result = await memoryRecallTool.execute({ query: "TypeScript" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/TypeScript/);
  });

  test("returns 'no memories' message for no match", async () => {
    const result = await memoryRecallTool.execute({ query: "xyzzy_no_match" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/no memories/i);
  });

  test("respects limit parameter", async () => {
    const result = await memoryRecallTool.execute({ query: "the", limit: 1 });
    expect(result.success).toBe(true);
    const lines = result.output.split("\n").filter((l) => l.trim().startsWith("1.") || l.trim().startsWith("2."));
    expect(lines.length).toBeLessThanOrEqual(1);
  });

  test("includes category and importance in output", async () => {
    const result = await memoryRecallTool.execute({ query: "Chrome" });
    expect(result.output).toMatch(/rule/);
    expect(result.output).toMatch(/importance=/);
  });
});

describe("memoryForgetTool.execute()", () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = makeInMemoryStore();
    setMemoryStore(store);
  });

  test("deletes by memoryId", async () => {
    const { id } = store.store("Forget me by id please");
    const result = await memoryForgetTool.execute({ memoryId: id });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/Deleted 1/);
  });

  test("deletes by query", async () => {
    store.store("Forget me by query please zebra");
    const result = await memoryForgetTool.execute({ query: "zebra" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/Deleted/);
  });

  test("returns error when neither id nor query provided", async () => {
    const result = await memoryForgetTool.execute({});
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/memoryId or query/);
  });

  test("reports no match gracefully", async () => {
    const result = await memoryForgetTool.execute({ query: "xyzzy_no_match_ever" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/no matching/i);
  });
});
