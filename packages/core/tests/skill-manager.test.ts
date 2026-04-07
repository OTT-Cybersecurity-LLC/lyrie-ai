/**
 * SkillManager Tests
 *
 * Tests the self-improving skill system — loading, matching, and improvement tracking.
 * OTT Cybersecurity LLC
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { SkillManager } from "../src/skills/skill-manager";

describe("SkillManager", () => {
  let skills: SkillManager;

  beforeEach(async () => {
    skills = new SkillManager();
    await skills.initialize();
  });

  // ─── Initialization ────────────────────────────────────────────────────────

  it("initializes and loads built-in skills", () => {
    const all = skills.getAll();
    expect(all.length).toBeGreaterThan(0);
  });

  it("includes the core cybersecurity skills", () => {
    const all = skills.getAll();
    const ids = all.map((s) => s.id);

    expect(ids).toContain("web-search");
    expect(ids).toContain("threat-scan");
    expect(ids).toContain("vulnerability-check");
    expect(ids).toContain("device-protect");
  });

  it("each built-in skill has all required fields", () => {
    const all = skills.getAll();
    for (const skill of all) {
      expect(skill.id).toBeTruthy();
      expect(skill.name).toBeTruthy();
      expect(skill.description).toBeTruthy();
      expect(skill.version).toBeGreaterThan(0);
      expect(skill.trigger).toBeDefined();
      expect(typeof skill.execute).toBe("function");
      expect(skill.successRate).toBeGreaterThanOrEqual(0);
      expect(skill.successRate).toBeLessThanOrEqual(1);
      expect(skill.timesUsed).toBeGreaterThanOrEqual(0);
    }
  });

  // ─── Skill Matching ────────────────────────────────────────────────────────

  it("finds the web-search skill for search queries", () => {
    const skill = skills.findSkill("search for news about AI");
    expect(skill).not.toBeNull();
    expect(skill?.id).toBe("web-search");
  });

  it("finds the threat-scan skill for security requests", () => {
    const skill = skills.findSkill("scan this file for malware");
    expect(skill).not.toBeNull();
    expect(skill?.id).toBe("threat-scan");
  });

  it("finds vulnerability-check skill for CVE queries", () => {
    const skill = skills.findSkill("check for vulnerabilities in my system");
    expect(skill).not.toBeNull();
    expect(skill?.id).toBe("vulnerability-check");
  });

  it("finds device-protect skill for protection requests", () => {
    // Use a trigger that hits \bprotect\b without containing 'scan', 'threat', 'malware', 'virus'
    const skill = skills.findSkill("defend and guard my device");
    expect(skill).not.toBeNull();
    expect(skill?.id).toBe("device-protect");
  });

  it("returns null for unmatched input", () => {
    const skill = skills.findSkill("xyzzy-no-match-unique-string-1234");
    expect(skill).toBeNull();
  });

  // ─── Custom Skill Registration ────────────────────────────────────────────

  it("registers a custom skill", () => {
    const before = skills.getAll().length;

    skills.register({
      id: "custom-summarizer",
      name: "Text Summarizer",
      description: "Summarize long text into key points",
      version: 1,
      trigger: /summarize|tl;dr|brief|summary/i,
      execute: async (context) => ({ summary: "..." }),
      successRate: 1.0,
      timesUsed: 0,
    });

    expect(skills.getAll().length).toBe(before + 1);
  });

  it("matches custom registered skill", () => {
    skills.register({
      id: "test-custom",
      name: "Test Custom",
      description: "Test",
      version: 1,
      trigger: /unique_test_trigger_keyword/i,
      execute: async () => ({}),
      successRate: 1.0,
      timesUsed: 0,
    });

    const found = skills.findSkill("unique_test_trigger_keyword");
    expect(found).not.toBeNull();
    expect(found?.id).toBe("test-custom");
  });

  it("supports string-based triggers", () => {
    skills.register({
      id: "string-trigger-skill",
      name: "String Trigger",
      description: "Test string trigger",
      version: 1,
      trigger: "deploy to production",
      execute: async () => ({ deployed: true }),
      successRate: 1.0,
      timesUsed: 0,
    });

    const found = skills.findSkill("we need to deploy to production now");
    expect(found).not.toBeNull();
    expect(found?.id).toBe("string-trigger-skill");
  });

  // ─── Skill Execution ──────────────────────────────────────────────────────

  it("executes threat-scan skill without throwing", async () => {
    const skill = skills.findSkill("scan for threats");
    expect(skill).not.toBeNull();

    const result = await skill!.execute({ target: "/tmp", type: "file" });
    expect(result).toBeDefined();
    expect(result).toHaveProperty("threats");
    expect(result).toHaveProperty("clean");
  });

  it("executes device-protect skill without throwing", async () => {
    const skill = skills.findSkill("protect my device");
    expect(skill).not.toBeNull();

    const result = await skill!.execute({});
    expect(result).toBeDefined();
    expect(result).toHaveProperty("status");
  });

  // ─── Self-Improvement ─────────────────────────────────────────────────────

  it("checkForImprovement runs without throwing", async () => {
    const input = { role: "user", content: "search for AI news", timestamp: Date.now() };
    const output = { role: "assistant", content: "Here are the results...", timestamp: Date.now() };

    // Should not throw — improvement is opportunistic
    await expect(skills.checkForImprovement(input, output)).resolves.toBeUndefined();
  });
});
