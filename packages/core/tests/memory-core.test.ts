/**
 * MemoryCore Tests
 *
 * Tests the self-healing, versioned memory system.
 * OTT Cybersecurity LLC
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { MemoryCore } from "../src/memory/memory-core";
import { existsSync, rmSync } from "fs";
import { join } from "path";

const TEST_MEMORY_PATH = join(process.env.HOME ?? "/tmp", ".lyrie-test", "memory");

function cleanup() {
  const testDir = join(process.env.HOME ?? "/tmp", ".lyrie-test");
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true });
  }
}

describe("MemoryCore", () => {
  let memory: MemoryCore;

  beforeEach(async () => {
    cleanup();
    memory = new MemoryCore(TEST_MEMORY_PATH);
    await memory.initialize();
  });

  afterEach(() => {
    cleanup();
  });

  it("initializes successfully and creates directory structure", () => {
    expect(existsSync(TEST_MEMORY_PATH)).toBe(true);
    expect(existsSync(join(TEST_MEMORY_PATH, "master"))).toBe(true);
    expect(existsSync(join(TEST_MEMORY_PATH, "archive"))).toBe(true);
    expect(existsSync(join(TEST_MEMORY_PATH, "vector"))).toBe(true);
  });

  it("creates MASTER-MEMORY.md on fresh init", () => {
    const masterFile = join(TEST_MEMORY_PATH, "master", "MASTER-MEMORY.md");
    expect(existsSync(masterFile)).toBe(true);

    const { readFileSync } = require("fs");
    const content = readFileSync(masterFile, "utf-8");
    expect(content).toContain("LYRIE AGENT");
    expect(content.length).toBeGreaterThan(100);
  });

  it("stores a memory entry and returns an ID", async () => {
    const id = await memory.store(
      "test:hello",
      { message: "hello world" },
      "medium",
      "system"
    );

    expect(id).toBeTruthy();
    expect(id).toMatch(/^lyrie_/);
  });

  it("recalls stored entries by keyword", async () => {
    await memory.store("project:lyrie", { name: "Lyrie Agent", status: "building" }, "high", "user");
    await memory.store("project:other", { name: "Other Project", status: "done" }, "low", "user");

    const results = await memory.recall("Lyrie");
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].key).toBe("project:lyrie");
  });

  it("returns results sorted by importance", async () => {
    await memory.store("a:low", { data: "query match" }, "low", "system");
    await memory.store("b:critical", { data: "query match" }, "critical", "system");
    await memory.store("c:medium", { data: "query match" }, "medium", "system");

    const results = await memory.recall("query match");
    expect(results[0].importance).toBe("critical");
  });

  it("respects limit on recall", async () => {
    for (let i = 0; i < 20; i++) {
      await memory.store(`test:${i}`, { index: i, needle: "findme" }, "medium", "system");
    }

    const limited = await memory.recall("findme", { limit: 5 });
    expect(limited.length).toBeLessThanOrEqual(5);
  });

  it("returns empty array when no matches found", async () => {
    await memory.store("something:else", { value: "unrelated" }, "low", "system");

    const results = await memory.recall("xyzzy_no_match_abc");
    expect(results).toEqual([]);
  });

  it("reports status correctly after initialization", () => {
    const status = memory.status();
    expect(status).toContain("🟢");
    expect(status).toContain("Active");
    expect(status).toContain("self-healing");
  });

  it("stores entry with tags", async () => {
    const id = await memory.store(
      "tagged:entry",
      { content: "cybersecurity alert" },
      "high",
      "agent",
      ["security", "alert", "urgent"]
    );

    expect(id).toBeTruthy();
    const results = await memory.recall("cybersecurity alert");
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].tags).toContain("security");
  });

  it("self-heals when master file is missing", async () => {
    // Delete the master file
    const masterFile = join(TEST_MEMORY_PATH, "master", "MASTER-MEMORY.md");
    rmSync(masterFile);
    expect(existsSync(masterFile)).toBe(false);

    // Initialize a new instance — should recover
    const recovered = new MemoryCore(TEST_MEMORY_PATH);
    await recovered.initialize();

    expect(existsSync(masterFile)).toBe(true);
  });
});
