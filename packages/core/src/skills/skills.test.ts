/**
 * SKILL.md Runtime — Test Suite
 *
 * Covers:
 *   - SkillLoader: discover, load, frontmatter parsing, fallbacks
 *   - SkillRegistry: loadAll, get, search, list, system prompt
 *   - SkillRunner: activate, error on missing skill
 *   - SkillSearch: scoring, partial match, empty query
 *   - OpenClaw compatibility: loads from ~/.openclaw/workspace/skills/
 *   - CLI output shape
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

import { SkillLoader } from "./skill-loader";
import { SkillRegistry } from "./skill-registry";
import { SkillRunner } from "./skill-runner";
import { SkillSearch } from "./skill-search";
import type { SkillManifest } from "./skill-types";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "lyrie-skill-test-"));
}

function writeSkillMd(dir: string, name: string, content: string): string {
  const skillDir = join(dir, name);
  mkdirSync(skillDir, { recursive: true });
  const path = join(skillDir, "SKILL.md");
  writeFileSync(path, content, "utf-8");
  return path;
}

function makeSkillMd(opts: {
  name?: string;
  description?: string;
  version?: string;
  author?: string;
  tools?: string[];
  channels?: string[];
  triggers?: string[];
  body?: string;
}): string {
  const lines: string[] = ["---"];
  if (opts.name) lines.push(`name: ${opts.name}`);
  if (opts.description) lines.push(`description: "${opts.description}"`);
  if (opts.version) lines.push(`version: ${opts.version}`);
  if (opts.author) lines.push(`author: ${opts.author}`);
  if (opts.tools?.length) {
    lines.push("tools:");
    opts.tools.forEach((t) => lines.push(`  - ${t}`));
  }
  if (opts.channels?.length) {
    lines.push("channels:");
    opts.channels.forEach((c) => lines.push(`  - ${c}`));
  }
  if (opts.triggers?.length) {
    lines.push("triggers:");
    opts.triggers.forEach((t) => lines.push(`  - ${t}`));
  }
  lines.push("---");
  lines.push("");
  lines.push(opts.body ?? "# Skill body\n\nDo the thing.");
  return lines.join("\n");
}

// ─── SkillLoader Tests ───────────────────────────────────────────────────────

describe("SkillLoader", () => {
  let dir: string;
  const loader = new SkillLoader();

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  test("discovers SKILL.md files recursively", async () => {
    writeSkillMd(dir, "skill-a", makeSkillMd({ name: "skill-a" }));
    writeSkillMd(dir, "skill-b", makeSkillMd({ name: "skill-b" }));
    const found = await loader.discover(dir);
    expect(found.length).toBe(2);
    expect(found.map((m) => m.name).sort()).toEqual(["skill-a", "skill-b"]);
  });

  test("returns empty array for non-existent directory", async () => {
    const found = await loader.discover("/no/such/dir/xyz123");
    expect(found).toEqual([]);
  });

  test("loads and parses YAML frontmatter correctly", async () => {
    const path = writeSkillMd(dir, "ga4", makeSkillMd({
      name: "ga4-analytics",
      description: "Google Analytics 4 toolkit",
      version: "1.2.0",
      author: "Lyrie Engineering",
      tools: ["browser", "web_fetch"],
      channels: ["telegram", "slack"],
      triggers: ["check traffic", "analytics"],
      body: "## GA4 Instructions\n\nUse the GA4 API to fetch metrics.",
    }));

    const m = await loader.load(path);
    expect(m.name).toBe("ga4-analytics");
    expect(m.description).toBe("Google Analytics 4 toolkit");
    expect(m.version).toBe("1.2.0");
    expect(m.author).toBe("Lyrie Engineering");
    expect(m.tools).toEqual(["browser", "web_fetch"]);
    expect(m.channels).toEqual(["telegram", "slack"]);
    expect(m.triggers).toEqual(["check traffic", "analytics"]);
    expect(m.content).toContain("GA4 Instructions");
    expect(m.location).toBe(path);
  });

  test("falls back gracefully when frontmatter is missing", async () => {
    const skillDir = join(dir, "bare-skill");
    mkdirSync(skillDir, { recursive: true });
    const path = join(skillDir, "SKILL.md");
    writeFileSync(path, "# No frontmatter\n\nJust plain markdown.", "utf-8");

    const m = await loader.load(path);
    expect(m.name).toBe("bare-skill"); // fallback: directory name
    expect(m.description).toBeUndefined();
    expect(m.content).toContain("No frontmatter");
  });

  test("falls back gracefully when frontmatter is incomplete", async () => {
    const content = "---\ndescription: Only description\n---\n\n# Body";
    const skillDir = join(dir, "partial-fm");
    mkdirSync(skillDir, { recursive: true });
    const path = join(skillDir, "SKILL.md");
    writeFileSync(path, content, "utf-8");

    const m = await loader.load(path);
    expect(m.name).toBe("partial-fm");
    expect(m.description).toBe("Only description");
    expect(m.content).toContain("# Body");
  });

  test("throws for non-existent SKILL.md path", async () => {
    await expect(loader.load("/no/such/SKILL.md")).rejects.toThrow("not found");
  });

  test("handles inline array syntax in frontmatter", async () => {
    const content = `---\nname: inline-skill\ntools: [exec, read, write]\n---\n\n# Body`;
    const skillDir = join(dir, "inline-skill");
    mkdirSync(skillDir, { recursive: true });
    const path = join(skillDir, "SKILL.md");
    writeFileSync(path, content, "utf-8");

    const m = await loader.load(path);
    expect(m.tools).toEqual(["exec", "read", "write"]);
  });

  test("strips frontmatter from content body", async () => {
    const path = writeSkillMd(dir, "clean-skill", makeSkillMd({
      name: "clean-skill",
      body: "# Clean body\n\nOnly this should appear.",
    }));
    const m = await loader.load(path);
    expect(m.content).not.toContain("---");
    expect(m.content).toContain("Clean body");
  });

  test("discovers nested skill directories", async () => {
    const nested = join(dir, "category", "deep-skill");
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(nested, "SKILL.md"), makeSkillMd({ name: "deep-skill" }), "utf-8");

    const found = await loader.discover(dir);
    expect(found.some((m) => m.name === "deep-skill")).toBe(true);
  });
});

// ─── SkillRegistry Tests ─────────────────────────────────────────────────────

describe("SkillRegistry", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    SkillRegistry.reset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    SkillRegistry.reset();
  });

  test("loadAll discovers and indexes skills", async () => {
    writeSkillMd(dir, "skill-one", makeSkillMd({ name: "skill-one", description: "First skill" }));
    writeSkillMd(dir, "skill-two", makeSkillMd({ name: "skill-two", description: "Second skill" }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    expect(reg.size).toBe(2);
    expect(reg.get("skill-one")).toBeDefined();
    expect(reg.get("skill-two")).toBeDefined();
  });

  test("get is case-insensitive", async () => {
    writeSkillMd(dir, "my-skill", makeSkillMd({ name: "My-Skill" }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    expect(reg.get("my-skill")).toBeDefined();
    expect(reg.get("MY-SKILL")).toBeDefined();
    expect(reg.get("My-Skill")).toBeDefined();
  });

  test("list returns skills sorted alphabetically", async () => {
    writeSkillMd(dir, "zebra", makeSkillMd({ name: "zebra" }));
    writeSkillMd(dir, "apple", makeSkillMd({ name: "apple" }));
    writeSkillMd(dir, "mango", makeSkillMd({ name: "mango" }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const names = reg.list().map((m) => m.name);
    expect(names).toEqual([...names].sort());
  });

  test("search finds skills by partial name", async () => {
    writeSkillMd(dir, "ga4-analytics", makeSkillMd({ name: "ga4-analytics", description: "Google Analytics 4" }));
    writeSkillMd(dir, "calendar-manager", makeSkillMd({ name: "calendar-manager", description: "Manage calendars" }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const results = reg.search("analytics");
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe("ga4-analytics");
  });

  test("search finds skills by description keyword", async () => {
    writeSkillMd(dir, "seo-tool", makeSkillMd({ name: "seo-tool", description: "SEO keyword research and optimization" }));
    writeSkillMd(dir, "unrelated", makeSkillMd({ name: "unrelated", description: "Something completely different" }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const results = reg.search("SEO keyword");
    expect(results[0].name).toBe("seo-tool");
  });

  test("getSystemPromptFor returns injection block", async () => {
    writeSkillMd(dir, "test-skill", makeSkillMd({
      name: "test-skill",
      description: "A test skill",
      body: "## Instructions\n\nDo the thing.",
    }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const prompt = reg.getSystemPromptFor("test-skill");
    expect(prompt).toContain("## Active Skill: test-skill");
    expect(prompt).toContain("A test skill");
    expect(prompt).toContain("Do the thing.");
  });

  test("getSystemPromptFor returns empty string for unknown skill", async () => {
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);
    expect(reg.getSystemPromptFor("nonexistent-skill")).toBe("");
  });

  test("duplicate names: first one wins", async () => {
    writeSkillMd(dir, "alpha", makeSkillMd({ name: "alpha", description: "First alpha" }));
    const dir2 = tmpDir();
    try {
      writeSkillMd(dir2, "alpha", makeSkillMd({ name: "alpha", description: "Second alpha" }));

      const reg = SkillRegistry.getInstance();
      await reg.loadAll([dir, dir2]);

      const m = reg.get("alpha");
      expect(m?.description).toBe("First alpha");
    } finally {
      rmSync(dir2, { recursive: true, force: true });
    }
  });

  test("loadAll can be called multiple times to add more skills", async () => {
    writeSkillMd(dir, "first", makeSkillMd({ name: "first" }));
    const dir2 = tmpDir();
    try {
      writeSkillMd(dir2, "second", makeSkillMd({ name: "second" }));

      const reg = SkillRegistry.getInstance();
      await reg.loadAll([dir]);
      expect(reg.size).toBe(1);

      await reg.loadAll([dir2]);
      expect(reg.size).toBe(2);
    } finally {
      rmSync(dir2, { recursive: true, force: true });
    }
  });
});

// ─── SkillRunner Tests ───────────────────────────────────────────────────────

describe("SkillRunner", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    SkillRegistry.reset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    SkillRegistry.reset();
  });

  test("activate returns ActivatedSkill with injection", async () => {
    writeSkillMd(dir, "my-skill", makeSkillMd({
      name: "my-skill",
      description: "My test skill",
      body: "## My Instructions\n\nFollow these steps.",
    }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    const result = await runner.activate("my-skill");

    expect(result.manifest.name).toBe("my-skill");
    expect(result.systemPromptInjection).toContain("## Active Skill: my-skill");
    expect(result.systemPromptInjection).toContain("Follow these steps.");
    expect(result.activatedAt).toBeTruthy();
  });

  test("activate passes context (does not throw)", async () => {
    writeSkillMd(dir, "ctx-skill", makeSkillMd({ name: "ctx-skill" }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    const result = await runner.activate("ctx-skill", {
      message: "test message",
      channel: "telegram",
      metadata: { sessionId: "abc123" },
    });
    expect(result.manifest.name).toBe("ctx-skill");
  });

  test("activate throws for unknown skill", async () => {
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    await expect(runner.activate("does-not-exist")).rejects.toThrow("does-not-exist");
  });

  test("has returns true for loaded skill", async () => {
    writeSkillMd(dir, "present-skill", makeSkillMd({ name: "present-skill" }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    expect(runner.has("present-skill")).toBe(true);
    expect(runner.has("absent-skill")).toBe(false);
  });

  test("activatedAt is an ISO timestamp", async () => {
    writeSkillMd(dir, "ts-skill", makeSkillMd({ name: "ts-skill" }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    const result = await runner.activate("ts-skill");
    expect(new Date(result.activatedAt).toISOString()).toBe(result.activatedAt);
  });
});

// ─── SkillSearch Tests ────────────────────────────────────────────────────────

describe("SkillSearch", () => {
  const manifests: SkillManifest[] = [
    {
      name: "ga4-analytics",
      description: "Google Analytics 4 and Search Console toolkit",
      triggers: ["check traffic", "analytics report"],
      location: "/fake/ga4/SKILL.md",
      content: "GA4 content",
    },
    {
      name: "calendar-manager",
      description: "Read and write calendar events",
      triggers: ["add event", "check schedule"],
      location: "/fake/cal/SKILL.md",
      content: "Calendar content",
    },
    {
      name: "seo-content-writer",
      description: "Write SEO-optimised blog posts and landing pages",
      location: "/fake/seo/SKILL.md",
      content: "SEO content",
    },
    {
      name: "linkedin-automator",
      description: "Automate LinkedIn outreach and posting",
      location: "/fake/li/SKILL.md",
      content: "LinkedIn content",
    },
  ];

  test("returns matching results sorted by score", () => {
    const results = SkillSearch.search(manifests, "analytics");
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].manifest.name).toBe("ga4-analytics");
  });

  test("returns empty array when no match above minScore", () => {
    const results = SkillSearch.search(manifests, "zzz_no_match_xyz", { minScore: 50 });
    expect(results).toEqual([]);
  });

  test("returns all results (up to limit) on empty query", () => {
    const results = SkillSearch.search(manifests, "", { limit: 10 });
    expect(results.length).toBe(manifests.length);
  });

  test("respects limit parameter", () => {
    const results = SkillSearch.search(manifests, "a", { limit: 2 });
    expect(results.length).toBeLessThanOrEqual(2);
  });

  test("finds by description keyword", () => {
    const results = SkillSearch.search(manifests, "SEO");
    expect(results[0].manifest.name).toBe("seo-content-writer");
  });

  test("finds by trigger keyword", () => {
    const results = SkillSearch.search(manifests, "check schedule");
    expect(results[0].manifest.name).toBe("calendar-manager");
  });

  test("partial name match works", () => {
    const results = SkillSearch.search(manifests, "linkedin");
    expect(results[0].manifest.name).toBe("linkedin-automator");
  });
});

// ─── OpenClaw Compatibility Tests ────────────────────────────────────────────

describe("OpenClaw compatibility", () => {
  test("default paths includes ~/.openclaw/workspace/skills/", () => {
    const paths = SkillLoader.defaultPaths();
    const home = homedir();
    const expected = join(home, ".openclaw", "workspace", "skills");
    expect(paths).toContain(expected);
  });

  test("can load skills from ~/.openclaw/workspace/skills/ if present", async () => {
    const ocPath = join(homedir(), ".openclaw", "workspace", "skills");
    if (!existsSync(ocPath)) {
      // Skip gracefully — OpenClaw not installed in this environment
      console.log("  Skipping: ~/.openclaw/workspace/skills/ not present");
      return;
    }

    const loader = new SkillLoader();
    const skills = await loader.discover(ocPath);
    // We expect to find at least some skills if OpenClaw is installed
    expect(skills.length).toBeGreaterThan(0);
    // Every loaded skill should have a name
    for (const s of skills) {
      expect(typeof s.name).toBe("string");
      expect(s.name.length).toBeGreaterThan(0);
    }
  });

  test("SkillLoader.defaultPaths() returns at least 2 paths", () => {
    expect(SkillLoader.defaultPaths().length).toBeGreaterThanOrEqual(2);
  });
});

// ─── CLI Output Shape Tests ───────────────────────────────────────────────────

describe("CLI output shape (lyrie skills list)", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    SkillRegistry.reset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    SkillRegistry.reset();
  });

  test("list() output has name and optional description", async () => {
    writeSkillMd(dir, "skill-x", makeSkillMd({ name: "skill-x", description: "Does X" }));
    writeSkillMd(dir, "skill-y", makeSkillMd({ name: "skill-y" }));

    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);
    const all = reg.list();

    expect(all.length).toBe(2);
    for (const m of all) {
      expect(typeof m.name).toBe("string");
      expect(typeof m.location).toBe("string");
      expect(typeof m.content).toBe("string");
    }
  });

  test("skill count reported correctly", async () => {
    for (let i = 0; i < 5; i++) {
      writeSkillMd(dir, `skill-${i}`, makeSkillMd({ name: `skill-${i}` }));
    }
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);
    expect(reg.size).toBe(5);
    expect(reg.list().length).toBe(5);
  });
});

// ─── System Prompt Injection Tests ───────────────────────────────────────────

describe("System prompt injection", () => {
  let dir: string;

  beforeEach(() => {
    dir = tmpDir();
    SkillRegistry.reset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    SkillRegistry.reset();
  });

  test("injection includes the skill name header", async () => {
    writeSkillMd(dir, "inject-test", makeSkillMd({
      name: "inject-test",
      body: "## Step 1\n\nDo something.",
    }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    const activated = await runner.activate("inject-test");
    expect(activated.systemPromptInjection).toContain("## Active Skill: inject-test");
  });

  test("injection includes the full skill body", async () => {
    const body = "## Detailed instructions\n\nStep 1: Do A.\nStep 2: Do B.\nStep 3: Profit.";
    writeSkillMd(dir, "full-body", makeSkillMd({ name: "full-body", body }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    const activated = await runner.activate("full-body");
    expect(activated.systemPromptInjection).toContain("Step 1: Do A.");
    expect(activated.systemPromptInjection).toContain("Step 3: Profit.");
  });

  test("injection includes description when present", async () => {
    writeSkillMd(dir, "with-desc", makeSkillMd({
      name: "with-desc",
      description: "This skill does something special",
      body: "# Body",
    }));
    const reg = SkillRegistry.getInstance();
    await reg.loadAll([dir]);

    const runner = new SkillRunner(reg);
    const activated = await runner.activate("with-desc");
    expect(activated.systemPromptInjection).toContain("This skill does something special");
  });
});
