/**
 * SkillManager Tests
 *
 * Tests the self-improving skill system — loading, matching, registration.
 * Modernized for the v0.1.x SkillDefinition API.
 *
 * OTT Cybersecurity LLC
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SkillManager } from "../src/skills/skill-manager";
import type { SkillDefinition } from "../src/skills/skill-manager";

let storeDir: string;

function makeBuilt(id: string, triggers: string[]): SkillDefinition {
  const now = new Date().toISOString();
  return {
    id,
    name: id,
    description: "test",
    version: 1,
    triggerPatterns: triggers,
    executionSteps: [{ action: "noop", description: "noop" }],
    tags: [],
    builtIn: false,
    successRate: 1,
    timesUsed: 0,
    timesSucceeded: 0,
    timesFailed: 0,
    createdAt: now,
    updatedAt: now,
  };
}

describe("SkillManager", () => {
  let skills: SkillManager;

  beforeEach(async () => {
    storeDir = mkdtempSync(join(tmpdir(), "lyrie-skill-test-"));
    skills = new SkillManager(storeDir);
    await skills.initialize();
  });

  afterEach(() => {
    rmSync(storeDir, { recursive: true, force: true });
  });

  // ─── Initialization ────────────────────────────────────────────────────────

  it("initializes and loads built-in skills", () => {
    const all = skills.getAll();
    expect(all.length).toBeGreaterThan(0);
  });

  it("includes the core cybersecurity skills", () => {
    const ids = skills.getAll().map((s) => s.id);
    expect(ids).toContain("web-search");
    expect(ids).toContain("threat-scan");
    expect(ids).toContain("vulnerability-check");
    expect(ids).toContain("device-protect");
  });

  it("each built-in skill has all required fields", () => {
    for (const skill of skills.getBuiltIn()) {
      expect(skill.id).toBeTruthy();
      expect(skill.name).toBeTruthy();
      expect(skill.description).toBeTruthy();
      expect(skill.version).toBeGreaterThan(0);
      expect(Array.isArray(skill.triggerPatterns)).toBe(true);
      expect(skill.successRate).toBeGreaterThanOrEqual(0);
      expect(skill.successRate).toBeLessThanOrEqual(1);
      expect(skill.timesUsed).toBeGreaterThanOrEqual(0);
    }
  });

  // ─── Matching ──────────────────────────────────────────────────────────────

  it("finds the web-search skill for search queries", () => {
    const match = skills.findSkill("search the web for the latest CVEs");
    expect(match).not.toBeNull();
    expect(match?.skill.id).toBe("web-search");
  });

  it("finds the threat-scan skill for security requests", () => {
    const match = skills.findSkill("scan this URL for threats");
    expect(match).not.toBeNull();
    expect(match?.skill.id).toBe("threat-scan");
  });

  it("finds vulnerability-check skill for CVE queries", () => {
    const match = skills.findSkill("check for vulnerabilities in my dependencies");
    expect(match).not.toBeNull();
    expect(match?.skill.id).toBe("vulnerability-check");
  });

  it("finds device-protect skill for protection requests", () => {
    const match = skills.findSkill("defend and protect my device");
    expect(match).not.toBeNull();
    expect(match?.skill.id).toBe("device-protect");
  });

  it("returns null for unmatched input", () => {
    const match = skills.findSkill("xyzzy-no-match-unique-string-1234");
    expect(match).toBeNull();
  });

  // ─── Custom Skill Registration ────────────────────────────────────────────

  it("registers a custom skill", () => {
    const before = skills.getAll().length;
    skills.register(makeBuilt("custom-summarizer", ["summarize", "tl;dr"]));
    expect(skills.getAll().length).toBe(before + 1);
  });

  it("matches a custom registered skill", () => {
    skills.register(makeBuilt("test-custom", ["unique_test_trigger_keyword"]));
    const match = skills.findSkill("please run unique_test_trigger_keyword now");
    expect(match).not.toBeNull();
    expect(match?.skill.id).toBe("test-custom");
  });

  it("supports multi-word string-based triggers", () => {
    skills.register(makeBuilt("string-trigger-skill", ["deploy to production"]));
    const match = skills.findSkill("we need to deploy to production now");
    expect(match).not.toBeNull();
    expect(match?.skill.id).toBe("string-trigger-skill");
  });

  // ─── Skill Execution ──────────────────────────────────────────────────────

  it("executes a skill via registerExecutor without throwing", async () => {
    skills.registerExecutor("threat-scan", async (ctx) => ({
      success: true,
      output: { threats: [], clean: true, target: ctx.target ?? "unknown" },
      duration: 0,
    }));

    const result = await skills.execute("threat-scan", { target: "/tmp", type: "file" });
    expect(result.success).toBe(true);
  });

  it("execute returns an error when no executor is registered", async () => {
    const result = await skills.execute("device-protect", {});
    expect(result.success).toBe(false);
    expect(result.error).toContain("No executor registered");
  });

  // ─── Self-Improvement ─────────────────────────────────────────────────────

  it("checkForImprovement runs without throwing", async () => {
    const result = await skills.checkForImprovement("test input", { ok: true });
    // checkForImprovement returns either null or a SkillExtractionCandidate;
    // we just want to make sure it doesn't throw
    expect(result === null || typeof result === "object").toBe(true);
  });
});
