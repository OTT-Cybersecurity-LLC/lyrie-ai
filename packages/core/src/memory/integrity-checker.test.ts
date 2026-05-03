/**
 * integrity-checker.test.ts — MemoryIntegrityChecker tests.
 *
 * Coverage:
 *   - hashAndStore: deterministic SHA-256, round-trip storage
 *   - runIntegrityCheck: pass/fail on unchanged/modified content
 *   - fixHashes: re-hashes drifted entries
 *   - crossModelVerify: agreement / disagreement scenarios
 *   - IntegrityReport structure
 *   - InMemoryIntegrityStore
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test, beforeEach } from "bun:test";
import {
  MemoryIntegrityChecker,
  InMemoryIntegrityStore,
  type MemoryEntry,
  type LlmProvider,
  type IntegrityReport,
  type VerificationResult,
} from "./integrity-checker";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeEntry(id = "entry-1", content = "Hello, world!"): MemoryEntry {
  return { id, content };
}

function mockProvider(id: string, answer: string): LlmProvider {
  return {
    id,
    async ask(_q: string) { return answer; },
  };
}

function failingProvider(id: string): LlmProvider {
  return {
    id,
    async ask(_q: string) { throw new Error("provider unavailable"); },
  };
}

// ─── InMemoryIntegrityStore ───────────────────────────────────────────────────

describe("InMemoryIntegrityStore", () => {
  test("put and get round-trip", async () => {
    const store = new InMemoryIntegrityStore();
    const entry = { id: "x", content: "abc", contentHash: "hash", hashedAt: 1 };
    await store.put(entry);
    const got = await store.get("x");
    expect(got).toEqual(entry);
  });

  test("get returns null for unknown id", async () => {
    const store = new InMemoryIntegrityStore();
    expect(await store.get("missing")).toBeNull();
  });

  test("getAll returns all stored entries", async () => {
    const store = new InMemoryIntegrityStore();
    await store.put({ id: "a", content: "1", contentHash: "h1", hashedAt: 0 });
    await store.put({ id: "b", content: "2", contentHash: "h2", hashedAt: 0 });
    const all = await store.getAll();
    expect(all.length).toBe(2);
  });

  test("put overwrites existing entry with same id", async () => {
    const store = new InMemoryIntegrityStore();
    await store.put({ id: "dup", content: "old", contentHash: "old-hash", hashedAt: 0 });
    await store.put({ id: "dup", content: "new", contentHash: "new-hash", hashedAt: 1 });
    const got = await store.get("dup");
    expect(got!.content).toBe("new");
  });

  test("size() returns correct count", async () => {
    const store = new InMemoryIntegrityStore();
    expect(store.size()).toBe(0);
    await store.put({ id: "x", content: "", contentHash: "", hashedAt: 0 });
    expect(store.size()).toBe(1);
  });

  test("clear() empties the store", async () => {
    const store = new InMemoryIntegrityStore();
    await store.put({ id: "x", content: "", contentHash: "", hashedAt: 0 });
    store.clear();
    expect(store.size()).toBe(0);
  });
});

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

describe("MemoryIntegrityChecker.sha256()", () => {
  test("produces a 64-char hex string", () => {
    const h = MemoryIntegrityChecker.sha256("test");
    expect(h).toHaveLength(64);
    expect(/^[a-f0-9]+$/.test(h)).toBe(true);
  });

  test("is deterministic — same input always same output", () => {
    const a = MemoryIntegrityChecker.sha256("content");
    const b = MemoryIntegrityChecker.sha256("content");
    expect(a).toBe(b);
  });

  test("different content produces different hash", () => {
    const a = MemoryIntegrityChecker.sha256("foo");
    const b = MemoryIntegrityChecker.sha256("bar");
    expect(a).not.toBe(b);
  });

  test("empty string has a valid hash", () => {
    const h = MemoryIntegrityChecker.sha256("");
    expect(h).toHaveLength(64);
  });
});

// ─── hashAndStore ─────────────────────────────────────────────────────────────

describe("MemoryIntegrityChecker.hashAndStore()", () => {
  let store: InMemoryIntegrityStore;
  let checker: MemoryIntegrityChecker;

  beforeEach(() => {
    store = new InMemoryIntegrityStore();
    checker = new MemoryIntegrityChecker(store);
  });

  test("stores entry with correct SHA-256 hash", async () => {
    const entry = makeEntry("e1", "My secret rule");
    const hashed = await checker.hashAndStore(entry);
    expect(hashed.contentHash).toBe(MemoryIntegrityChecker.sha256("My secret rule"));
  });

  test("stored entry is retrievable", async () => {
    await checker.hashAndStore(makeEntry("e2", "hello"));
    const got = await store.get("e2");
    expect(got).not.toBeNull();
    expect(got!.content).toBe("hello");
  });

  test("hashedAt is a positive unix timestamp", async () => {
    const before = Date.now();
    const hashed = await checker.hashAndStore(makeEntry());
    expect(hashed.hashedAt).toBeGreaterThanOrEqual(before);
  });

  test("calling twice with same id overwrites", async () => {
    await checker.hashAndStore({ id: "dup", content: "v1" });
    await checker.hashAndStore({ id: "dup", content: "v2" });
    const got = await store.get("dup");
    expect(got!.content).toBe("v2");
  });

  test("throws when id is missing", async () => {
    await expect(checker.hashAndStore({ id: "", content: "x" })).rejects.toThrow("id is required");
  });

  test("preserves metadata through storage", async () => {
    const entry: MemoryEntry = { id: "meta", content: "data", metadata: { tag: "important" } };
    const hashed = await checker.hashAndStore(entry);
    expect(hashed.metadata).toEqual({ tag: "important" });
  });
});

// ─── runIntegrityCheck ────────────────────────────────────────────────────────

describe("MemoryIntegrityChecker.runIntegrityCheck()", () => {
  let store: InMemoryIntegrityStore;
  let checker: MemoryIntegrityChecker;

  beforeEach(() => {
    store = new InMemoryIntegrityStore();
    checker = new MemoryIntegrityChecker(store);
  });

  test("passes when content is unchanged", async () => {
    await checker.hashAndStore(makeEntry("e1", "safe content"));
    const report = await checker.runIntegrityCheck();
    expect(report.failedEntries).toHaveLength(0);
    expect(report.passedEntries).toBe(1);
  });

  test("fails when content is modified after hashing", async () => {
    await checker.hashAndStore(makeEntry("tampered", "original content"));
    // Tamper: overwrite content without updating hash
    const original = await store.get("tampered");
    await store.put({ ...original!, content: "TAMPERED content" });

    const report = await checker.runIntegrityCheck();
    expect(report.failedEntries).toHaveLength(1);
    expect(report.failedEntries[0].id).toBe("tampered");
  });

  test("IntegrityReport has correct structure", async () => {
    await checker.hashAndStore(makeEntry("e1"));
    const report = await checker.runIntegrityCheck();
    expect(report).toHaveProperty("totalEntries");
    expect(report).toHaveProperty("passedEntries");
    expect(report).toHaveProperty("failedEntries");
    expect(report).toHaveProperty("checkDurationMs");
    expect(typeof report.checkDurationMs).toBe("number");
  });

  test("totalEntries = passedEntries + failedEntries.length", async () => {
    await checker.hashAndStore(makeEntry("ok", "clean"));
    await checker.hashAndStore(makeEntry("bad", "original"));
    const bad = await store.get("bad");
    await store.put({ ...bad!, content: "tampered" });

    const report = await checker.runIntegrityCheck();
    expect(report.totalEntries).toBe(report.passedEntries + report.failedEntries.length);
  });

  test("empty store produces zero-entry report", async () => {
    const report = await checker.runIntegrityCheck();
    expect(report.totalEntries).toBe(0);
    expect(report.passedEntries).toBe(0);
    expect(report.failedEntries).toHaveLength(0);
  });

  test("FailedEntry includes storedHash, computedHash, content, createdAt", async () => {
    await checker.hashAndStore(makeEntry("drift", "before"));
    const stored = await store.get("drift");
    await store.put({ ...stored!, content: "after" });
    const report = await checker.runIntegrityCheck();
    const failed = report.failedEntries[0];
    expect(failed.storedHash).toBeDefined();
    expect(failed.computedHash).toBeDefined();
    expect(failed.storedHash).not.toBe(failed.computedHash);
    expect(failed.content).toBe("after");
    expect(failed.createdAt).toBeGreaterThan(0);
  });

  test("multiple tampered entries all appear in failedEntries", async () => {
    for (let i = 0; i < 3; i++) {
      await checker.hashAndStore(makeEntry(`e${i}`, `original-${i}`));
      const e = await store.get(`e${i}`);
      await store.put({ ...e!, content: `tampered-${i}` });
    }
    const report = await checker.runIntegrityCheck();
    expect(report.failedEntries).toHaveLength(3);
  });
});

// ─── fixHashes ────────────────────────────────────────────────────────────────

describe("MemoryIntegrityChecker.fixHashes()", () => {
  test("re-hashes drifted entries so check passes afterwards", async () => {
    const store = new InMemoryIntegrityStore();
    const checker = new MemoryIntegrityChecker(store);
    await checker.hashAndStore(makeEntry("fix-me", "original"));
    const e = await store.get("fix-me");
    await store.put({ ...e!, content: "updated content" });

    // Check should fail before fix
    const before = await checker.runIntegrityCheck();
    expect(before.failedEntries).toHaveLength(1);

    // Fix
    const { fixed } = await checker.fixHashes();
    expect(fixed).toBe(1);

    // Check should pass after fix
    const after = await checker.runIntegrityCheck();
    expect(after.failedEntries).toHaveLength(0);
  });

  test("returns fixed=0 when nothing is drifted", async () => {
    const store = new InMemoryIntegrityStore();
    const checker = new MemoryIntegrityChecker(store);
    await checker.hashAndStore(makeEntry("ok", "clean"));
    const { fixed } = await checker.fixHashes();
    expect(fixed).toBe(0);
  });
});

// ─── crossModelVerify ─────────────────────────────────────────────────────────

describe("MemoryIntegrityChecker.crossModelVerify()", () => {
  let store: InMemoryIntegrityStore;
  let checker: MemoryIntegrityChecker;

  beforeEach(() => {
    store = new InMemoryIntegrityStore();
    checker = new MemoryIntegrityChecker(store);
  });

  test("returns agreement=true when all 3 models agree", async () => {
    const models = [
      mockProvider("m1", "YES"),
      mockProvider("m2", "YES"),
      mockProvider("m3", "YES"),
    ];
    const result = await checker.crossModelVerify("content", models, "Is this safe?");
    expect(result.agreement).toBe(true);
    expect(result.agreementCount).toBe(3);
    expect(result.majorityAnswer).toBe("YES");
  });

  test("returns agreement=true on 2-of-3 majority", async () => {
    const models = [
      mockProvider("m1", "YES"),
      mockProvider("m2", "YES"),
      mockProvider("m3", "NO"),
    ];
    const result = await checker.crossModelVerify("content", models, "Safe?");
    expect(result.agreement).toBe(true);
    expect(result.agreementCount).toBe(2);
    expect(result.disagreements).toContain("m3");
  });

  test("returns agreement=false when models split evenly 1-1-1", async () => {
    const models = [
      mockProvider("m1", "YES"),
      mockProvider("m2", "NO"),
      mockProvider("m3", "MAYBE"),
    ];
    const result = await checker.crossModelVerify("content", models, "Safe?");
    // No majority > 50%
    expect(result.agreement).toBe(false);
  });

  test("handles failing providers gracefully (still counts successful ones)", async () => {
    const models = [
      mockProvider("m1", "YES"),
      mockProvider("m2", "YES"),
      failingProvider("m3"),
    ];
    const result = await checker.crossModelVerify("content", models, "Safe?");
    expect(result.totalModels).toBe(2); // only 2 answered
    expect(result.agreement).toBe(true); // 2-of-2 agree
  });

  test("returns agreement=false with empty models list", async () => {
    const result = await checker.crossModelVerify("content", [], "Safe?");
    expect(result.agreement).toBe(false);
    expect(result.totalModels).toBe(0);
    expect(result.majorityAnswer).toBeNull();
  });

  test("VerificationResult has correct structure", async () => {
    const models = [mockProvider("m1", "YES"), mockProvider("m2", "YES")];
    const result = await checker.crossModelVerify("data", models, "question");
    expect(result).toHaveProperty("agreement");
    expect(result).toHaveProperty("agreementCount");
    expect(result).toHaveProperty("totalModels");
    expect(result).toHaveProperty("majorityAnswer");
    expect(result).toHaveProperty("answers");
    expect(result).toHaveProperty("disagreements");
  });

  test("answers record contains all responding model ids", async () => {
    const models = [mockProvider("hermes", "YES"), mockProvider("anthropic", "YES")];
    const result = await checker.crossModelVerify("data", models, "q");
    expect(Object.keys(result.answers)).toContain("hermes");
    expect(Object.keys(result.answers)).toContain("anthropic");
  });

  test("case-insensitive comparison (yes == YES == Yes)", async () => {
    const models = [
      mockProvider("m1", "YES"),
      mockProvider("m2", "yes"),
      mockProvider("m3", "Yes"),
    ];
    const result = await checker.crossModelVerify("data", models, "q");
    expect(result.agreement).toBe(true);
    expect(result.agreementCount).toBe(3);
  });
});
