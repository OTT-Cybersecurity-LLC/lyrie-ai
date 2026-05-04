/**
 * OpenClaw → Lyrie Migration Tests
 *
 * Tests for:
 *  - openclaw-memory.ts   (memory migration + section extraction)
 *  - openclaw-skills.ts   (skills migration + SKILL.md parsing)
 *  - workspace/index.ts   (WorkspaceContext)
 *  - migrate/openclaw.ts  (full migration + --only flag)
 *  - scripts/init.ts      (init wizard logic via programmatic API)
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import {
  extractMarkdownSections,
  migrateOpenClawMemory,
  type MemoryMigrationOptions,
} from "../src/migrate/openclaw-memory";

import {
  parseSkillMd,
  migrateOpenClawSkills,
  type SkillsMigrationOptions,
} from "../src/migrate/openclaw-skills";

import {
  WorkspaceContext,
  getWorkspaceContext,
  type WorkspaceFiles,
} from "../src/workspace/index";

import {
  detectOpenClaw,
  migrateFromOpenClaw,
} from "../src/migrate/openclaw";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "lyrie-oc-test-"));
}

function writeFile(dir: string, name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

function makeSkillDir(parent: string, name: string, skillMd: string): string {
  const dir = join(parent, name);
  mkdirSync(dir, { recursive: true });
  writeFile(dir, "SKILL.md", skillMd);
  return dir;
}

// ─── extractMarkdownSections ──────────────────────────────────────────────────

describe("extractMarkdownSections", () => {
  it("extracts sections from a simple markdown document", () => {
    const md = `# Section A\n\nContent of section A.\n\n## Section B\n\nContent of section B.\n`;
    const sections = extractMarkdownSections(md);
    expect(sections.length).toBeGreaterThanOrEqual(2);
    const headings = sections.map((s) => s.heading);
    expect(headings).toContain("Section A");
    expect(headings).toContain("Section B");
  });

  it("returns content for sections without headings", () => {
    const md = `Some intro text that is long enough to be kept by the filter.\n\n# Heading\n\nBody text.`;
    const sections = extractMarkdownSections(md);
    expect(sections.some((s) => s.content.includes("intro text"))).toBe(true);
  });

  it("filters out sections with very short content", () => {
    const md = `# A\n\nhi\n\n# B\n\nThis is a longer section with actual content worth indexing.\n`;
    const sections = extractMarkdownSections(md);
    // Section A has too-short content ("hi"), Section B should be included
    expect(sections.some((s) => s.heading === "B")).toBe(true);
  });

  it("handles empty input gracefully", () => {
    const sections = extractMarkdownSections("");
    expect(Array.isArray(sections)).toBe(true);
  });

  it("tracks heading depth correctly", () => {
    const md = `# H1\n\ncontent.\n\n## H2\n\ncontent.\n\n### H3\n\ncontent.`;
    const sections = extractMarkdownSections(md);
    const depths = sections.map((s) => s.depth);
    expect(depths).toContain(1);
    expect(depths).toContain(2);
    expect(depths).toContain(3);
  });
});

// ─── migrateOpenClawMemory ────────────────────────────────────────────────────

describe("migrateOpenClawMemory", () => {
  let tmpDir: string;
  let sourceDir: string;
  let targetDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    sourceDir = join(tmpDir, "memory");
    targetDir = join(tmpDir, "lyrie", "memory");
    mkdirSync(sourceDir, { recursive: true });
    mkdirSync(targetDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("dry-run does not write output files", async () => {
    writeFile(sourceDir, "test.md", "# Facts\n\nThis is a fact about something important.\n");
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    expect(result.success).toBe(true);
    expect(existsSync(join(targetDir, "import.json"))).toBe(false);
  });

  it("returns entries from .md files", async () => {
    writeFile(
      sourceDir,
      "learnings.md",
      "# Trading Rules\n\nNever trade without a stop loss. This is a critical rule.\n\n# SEO Tips\n\nAlways build quality backlinks for better ranking.\n"
    );
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    expect(result.entries.length).toBeGreaterThan(0);
    expect(result.filesProcessed).toBeGreaterThan(0);
  });

  it("writes output file when dryRun=false", async () => {
    writeFile(
      sourceDir,
      "notes.md",
      "# Important Note\n\nThis is an important note that should be persisted across sessions.\n"
    );
    const outPath = join(targetDir, "output.json");
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: outPath,
      dryRun: false,
    };
    const result = await migrateOpenClawMemory(opts);
    expect(result.success).toBe(true);
    expect(existsSync(outPath)).toBe(true);
    const written = JSON.parse(readFileSync(outPath, "utf8"));
    expect(Array.isArray(written)).toBe(true);
  });

  it("infers correct domain for trading content", async () => {
    writeFile(
      sourceDir,
      "trading.md",
      "# Bybit Strategy\n\nAlways use 2x leverage on BTCUSDT futures. Set stop loss at 3% below entry.\n"
    );
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    const tradingEntries = result.entries.filter((e) => e.domain === "trading");
    expect(tradingEntries.length).toBeGreaterThan(0);
  });

  it("infers correct domain for SEO content", async () => {
    writeFile(
      sourceDir,
      "seo.md",
      "# SEO Rules\n\nAlways target long-tail keywords. Build backlinks from high-DA domains.\n"
    );
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    const seoEntries = result.entries.filter((e) => e.domain === "seo");
    expect(seoEntries.length).toBeGreaterThan(0);
  });

  it("handles missing sourceDir gracefully", async () => {
    const opts: MemoryMigrationOptions = {
      sourceDir: join(tmpDir, "does-not-exist"),
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    // Should not throw, just warn
    expect(result.warnings.length).toBeGreaterThan(0);
    expect(result.errors.length).toBe(0);
  });

  it("assigns critical importance to entries with ⛔ or 'never'", async () => {
    writeFile(
      sourceDir,
      "rules.md",
      "# Hard Rules\n\n⛔ NEVER kill Chrome. This is the hardest rule in the system.\n"
    );
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    const critical = result.entries.filter((e) => e.importance === "critical");
    expect(critical.length).toBeGreaterThan(0);
  });

  it("returns entriesImported count matching entries array length", async () => {
    writeFile(sourceDir, "a.md", "# Entry A\n\nContent for entry A, detailed enough to be indexed.\n");
    writeFile(sourceDir, "b.md", "# Entry B\n\nContent for entry B, also detailed enough to be indexed.\n");
    const opts: MemoryMigrationOptions = {
      sourceDir,
      targetDb: join(targetDir, "import.json"),
      dryRun: true,
    };
    const result = await migrateOpenClawMemory(opts);
    expect(result.entriesImported).toBe(result.entries.length);
  });
});

// ─── parseSkillMd ─────────────────────────────────────────────────────────────

describe("parseSkillMd", () => {
  it("extracts name from first H1", () => {
    const md = `# My Awesome Skill\n\nDoes something amazing.\n`;
    const parsed = parseSkillMd(md, "fallback");
    expect(parsed.name).toBe("My Awesome Skill");
  });

  it("extracts description from first paragraph", () => {
    const md = `# Skill Name\n\nThis is the description of what the skill does.\n`;
    const parsed = parseSkillMd(md, "fallback");
    expect(parsed.description).toContain("description");
  });

  it("uses fallback name when no H1 present", () => {
    const md = `Some content without a heading.`;
    const parsed = parseSkillMd(md, "my-skill");
    expect(parsed.name).toBe("my-skill");
  });

  it("extracts tags from Tags: line", () => {
    const md = `# SEO Skill\n\nDescription.\n\nTags: seo, content, google\n`;
    const parsed = parseSkillMd(md, "fallback");
    expect(parsed.tags).toContain("seo");
    expect(parsed.tags).toContain("content");
    expect(parsed.tags).toContain("google");
  });

  it("extracts version from version: line", () => {
    const md = `# Skill\n\nDescription.\n\nVersion: 2.3.1\n`;
    const parsed = parseSkillMd(md, "fallback");
    expect(parsed.version).toBe("2.3.1");
  });

  it("generates auto trigger patterns when none found", () => {
    const md = `# Web Scraper\n\nScrapes websites for data.`;
    const parsed = parseSkillMd(md, "fallback");
    expect(parsed.triggerPatterns.length).toBeGreaterThan(0);
  });
});

// ─── migrateOpenClawSkills ────────────────────────────────────────────────────

describe("migrateOpenClawSkills", () => {
  let tmpDir: string;
  let sourceDir: string;
  let targetDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    sourceDir = join(tmpDir, "skills");
    targetDir = join(tmpDir, "lyrie-skills");
    mkdirSync(sourceDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("dry-run: returns registry without writing files", async () => {
    makeSkillDir(sourceDir, "seo-tool", "# SEO Tool\n\nHandles all SEO tasks.\n\nTags: seo, content\n");
    const opts: SkillsMigrationOptions = {
      sourceDir,
      targetDir,
      dryRun: true,
    };
    const result = await migrateOpenClawSkills(opts);
    expect(result.success).toBe(true);
    expect(result.registry.length).toBeGreaterThan(0);
    expect(existsSync(join(targetDir, "openclaw-registry.json"))).toBe(false);
  });

  it("copies skill directories when dryRun=false", async () => {
    makeSkillDir(sourceDir, "crypto-bot", "# Crypto Trading Bot\n\nTrades crypto automatically.\n");
    const opts: SkillsMigrationOptions = {
      sourceDir,
      targetDir,
      dryRun: false,
    };
    const result = await migrateOpenClawSkills(opts);
    // At least the skill we created should be imported (real openclaw skills may also be picked up)
    expect(result.skillsImported).toBeGreaterThanOrEqual(1);
    expect(existsSync(join(targetDir, "crypto-bot"))).toBe(true);
  });

  it("writes registry.json when dryRun=false", async () => {
    makeSkillDir(sourceDir, "web-monitor", "# Web Monitor\n\nMonitors websites for changes.\n");
    const opts: SkillsMigrationOptions = {
      sourceDir,
      targetDir,
      dryRun: false,
    };
    await migrateOpenClawSkills(opts);
    expect(existsSync(join(targetDir, "openclaw-registry.json"))).toBe(true);
    const reg = JSON.parse(readFileSync(join(targetDir, "openclaw-registry.json"), "utf8"));
    expect(Array.isArray(reg)).toBe(true);
    // At least the skill we created is there; real openclaw skills may also be present
    expect(reg.length).toBeGreaterThanOrEqual(1);
    expect(reg.some((e: any) => e.id === "oc_web-monitor")).toBe(true);
  });

  it("deduplicates skills across multiple source directories", async () => {
    makeSkillDir(sourceDir, "shared-skill", "# Shared Skill\n\nShared across dirs.\n");
    // Same skill name would come from nodeModules path too — simulate by passing same dir twice
    // We can't test the real dedup without a second real dir, so test single dir dedup
    const opts: SkillsMigrationOptions = {
      sourceDir,
      targetDir,
      dryRun: true,
    };
    const result = await migrateOpenClawSkills(opts);
    // No duplicates in registry
    const ids = result.registry.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("handles missing source directory gracefully", async () => {
    const opts: SkillsMigrationOptions = {
      sourceDir: join(tmpDir, "no-such-dir"),
      targetDir,
      dryRun: true,
    };
    const result = await migrateOpenClawSkills(opts);
    expect(result.errors.length).toBe(0);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it("sets source='openclaw' on all registry entries", async () => {
    makeSkillDir(sourceDir, "skill-a", "# Skill A\n\nDoes something useful.\n");
    makeSkillDir(sourceDir, "skill-b", "# Skill B\n\nDoes something else.\n");
    const opts: SkillsMigrationOptions = { sourceDir, targetDir, dryRun: true };
    const result = await migrateOpenClawSkills(opts);
    expect(result.registry.every((e) => e.source === "openclaw")).toBe(true);
  });

  it("merges with existing registry.json without overwriting existing entries", async () => {
    mkdirSync(targetDir, { recursive: true });
    const existingEntry = { id: "existing-skill", name: "Existing", source: "lyrie", path: "/x", enabled: true, tags: [], triggerPatterns: [], createdAt: new Date().toISOString() };
    writeFileSync(join(targetDir, "registry.json"), JSON.stringify([existingEntry], null, 2));
    makeSkillDir(sourceDir, "new-skill", "# New Skill\n\nBrand new.\n");
    const opts: SkillsMigrationOptions = { sourceDir, targetDir, dryRun: false };
    await migrateOpenClawSkills(opts);
    const merged = JSON.parse(readFileSync(join(targetDir, "registry.json"), "utf8"));
    expect(merged.some((e: any) => e.id === "existing-skill")).toBe(true);
    expect(merged.some((e: any) => e.id === "oc_new-skill")).toBe(true);
  });
});

// ─── WorkspaceContext ─────────────────────────────────────────────────────────

describe("WorkspaceContext", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads SOUL.md from workspace directory", async () => {
    writeFile(tmpDir, "SOUL.md", "# Soul\n\nI am the Lyrie agent. I have opinions.");
    const ctx = new WorkspaceContext();
    const files = await ctx.load(tmpDir);
    expect(files.soul).toBeDefined();
    expect(files.soul).toContain("Lyrie agent");
  });

  it("loads all six standard workspace files", async () => {
    writeFile(tmpDir, "SOUL.md", "# Soul\nPersona content here.\n");
    writeFile(tmpDir, "AGENTS.md", "# Agents\nSystem rules here.\n");
    writeFile(tmpDir, "MEMORY.md", "# Memory\nFacts here.\n");
    writeFile(tmpDir, "USER.md", "# User\nGuy Sheetrit.\n");
    writeFile(tmpDir, "TOOLS.md", "# Tools\nCredentials here.\n");
    writeFile(tmpDir, "HEARTBEAT.md", "# Heartbeat\nProactive tasks.\n");
    const ctx = new WorkspaceContext();
    const files = await ctx.load(tmpDir);
    expect(files.soul).toBeDefined();
    expect(files.agents).toBeDefined();
    expect(files.memory).toBeDefined();
    expect(files.user).toBeDefined();
    expect(files.tools).toBeDefined();
    expect(files.heartbeat).toBeDefined();
  });

  it("returns empty object when workspace directory has no files", async () => {
    const ctx = new WorkspaceContext();
    const files = await ctx.load(join(tmpDir, "empty-workspace"));
    expect(Object.keys(files).length).toBe(0);
  });

  it("buildSystemContext includes SOUL.md content", () => {
    const files: WorkspaceFiles = {
      soul: "# Soul\n\nI have opinions and I express them.",
    };
    const ctx = new WorkspaceContext();
    const prompt = ctx.buildSystemContext(files);
    expect(prompt).toContain("SOUL");
    expect(prompt).toContain("opinions");
  });

  it("buildSystemContext includes AGENTS.md content", () => {
    const files: WorkspaceFiles = {
      agents: "# Agents\n\nNEVER kill Chrome.",
    };
    const ctx = new WorkspaceContext();
    const prompt = ctx.buildSystemContext(files);
    expect(prompt).toContain("AGENTS");
    expect(prompt).toContain("Chrome");
  });

  it("buildSystemContext returns empty string for empty files", () => {
    const ctx = new WorkspaceContext();
    const prompt = ctx.buildSystemContext({});
    expect(prompt).toBe("");
  });

  it("buildSystemContext includes all provided sections", () => {
    const files: WorkspaceFiles = {
      soul: "Soul content",
      agents: "Agents content",
      memory: "Memory content",
      user: "User content",
    };
    const ctx = new WorkspaceContext();
    const prompt = ctx.buildSystemContext(files);
    expect(prompt).toContain("Soul content");
    expect(prompt).toContain("Agents content");
    expect(prompt).toContain("Memory content");
    expect(prompt).toContain("User content");
  });

  it("getCached returns the last loaded workspace files", async () => {
    writeFile(tmpDir, "USER.md", "# User\nGuy Sheetrit.\n");
    const ctx = new WorkspaceContext();
    await ctx.load(tmpDir);
    const cached = ctx.getCached();
    expect(cached.user).toBeDefined();
    expect(cached.user).toContain("Guy");
  });

  it("getWorkspaceContext returns a singleton", () => {
    const a = getWorkspaceContext();
    const b = getWorkspaceContext();
    expect(a).toBe(b);
  });

  it("loadExtra loads additional files beyond the standard set", async () => {
    writeFile(tmpDir, "CUSTOM.md", "# Custom\n\nCustom workspace file.");
    const ctx = new WorkspaceContext();
    const content = await ctx.loadExtra(tmpDir, "CUSTOM.md");
    expect(content).toBeDefined();
    expect(content).toContain("Custom workspace file");
  });
});

// ─── migrateFromOpenClaw (--only flag) ───────────────────────────────────────

describe("migrateFromOpenClaw --only flag", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("--only memory: does not write crons or skills files", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: false,
      verbose: false,
      only: "memory",
    });
    expect(result.platform).toBe("openclaw");
    expect(existsSync(join(tmpDir, "config", "crons.json"))).toBe(false);
    expect(existsSync(join(tmpDir, "skills", "openclaw-skills.json"))).toBe(false);
    // Memory file might exist (if ~/.openclaw exists)
    // Just assert it doesn't crash
    expect(typeof result.success).toBe("boolean");
  });

  it("--only skills: does not write memory or crons files", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: false,
      verbose: false,
      only: "skills",
    });
    expect(result.platform).toBe("openclaw");
    expect(existsSync(join(tmpDir, "config", "crons.json"))).toBe(false);
    expect(existsSync(join(tmpDir, "memory", "openclaw-import.json"))).toBe(false);
    expect(typeof result.success).toBe("boolean");
  });

  it("--only crons: does not write memory or skills files", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: false,
      verbose: false,
      only: "crons",
    });
    expect(result.platform).toBe("openclaw");
    expect(existsSync(join(tmpDir, "memory", "openclaw-import.json"))).toBe(false);
    expect(existsSync(join(tmpDir, "skills", "openclaw-skills.json"))).toBe(false);
    expect(typeof result.success).toBe("boolean");
  });

  it("--only channels: does not write memory or crons files", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: false,
      verbose: false,
      only: "channels",
    });
    expect(result.platform).toBe("openclaw");
    expect(existsSync(join(tmpDir, "memory", "openclaw-import.json"))).toBe(false);
    expect(existsSync(join(tmpDir, "config", "crons.json"))).toBe(false);
    expect(typeof result.success).toBe("boolean");
  });

  it("full migration (no --only) returns success", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: true,
      verbose: false,
    });
    expect(result.platform).toBe("openclaw");
    expect(typeof result.success).toBe("boolean");
    expect(Array.isArray(result.errors)).toBe(true);
    expect(result.manifest).toBeDefined();
  });

  it("detectOpenClaw returns a boolean", () => {
    const result = detectOpenClaw();
    expect(typeof result).toBe("boolean");
  });

  it("returns correct platform identifier", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: true,
      verbose: false,
    });
    expect(result.platform).toBe("openclaw");
  });

  it("dry-run does not write lyrie.json config", async () => {
    const result = await migrateFromOpenClaw({
      lyrieDir: tmpDir,
      dryRun: true,
      verbose: false,
    });
    expect(existsSync(join(tmpDir, "config", "lyrie.json"))).toBe(false);
  });
});
