/**
 * Lyrie Agent — OpenClaw Skills Migration
 *
 * Copies skill directories from ~/.openclaw/workspace/skills/ to Lyrie's
 * skill registry format, converting SKILL.md metadata into SkillDefinition
 * entries registered in ~/.lyrie/skills/registry.json.
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import {
  existsSync,
  readdirSync,
  readFileSync,
  mkdirSync,
  writeFileSync,
  cpSync,
  statSync,
} from "fs";
import { join, basename, extname } from "path";
import { homedir } from "os";

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface SkillRegistryEntry {
  id: string;
  name: string;
  description: string;
  version: string;
  source: "openclaw" | "lyrie" | "custom";
  /** Absolute path to the skill directory in ~/.lyrie/skills/ */
  path: string;
  enabled: boolean;
  tags: string[];
  triggerPatterns: string[];
  createdAt: string;
  importedFrom?: string;
}

export interface SkillsMigrationOptions {
  /** ~/.openclaw/workspace/skills/ */
  sourceDir: string;
  /** ~/.lyrie/skills/ */
  targetDir: string;
  dryRun: boolean;
  verbose?: boolean;
}

export interface SkillsMigrationResult {
  success: boolean;
  skillsImported: number;
  skillsSkipped: number;
  errors: string[];
  warnings: string[];
  registry: SkillRegistryEntry[];
}

// ─── SKILL.md parser ──────────────────────────────────────────────────────────

interface ParsedSkillMd {
  name: string;
  description: string;
  version: string;
  tags: string[];
  triggerPatterns: string[];
}

export function parseSkillMd(markdown: string, fallbackName: string): ParsedSkillMd {
  const lines = markdown.split("\n");
  let name = "";
  let description = "";
  const tags: string[] = [];
  const triggerPatterns: string[] = [];
  let version = "1.0.0";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Name from first H1
    if (!name && line.startsWith("# ")) {
      name = line.slice(2).trim();
      continue;
    }

    // Description from first paragraph-ish line after heading
    if (!description && line.length > 10 && !line.startsWith("#") && !line.startsWith("-")) {
      description = line.replace(/^[*_]|[*_]$/g, "").trim();
      continue;
    }

    // Version
    const versionMatch = line.match(/version[:\s]+([0-9]+\.[0-9]+\.[0-9]+)/i);
    if (versionMatch) {
      version = versionMatch[1];
    }

    // Tags from lines like: Tags: seo, search, content
    const tagsMatch = line.match(/^tags?:\s*(.+)/i);
    if (tagsMatch) {
      tags.push(
        ...tagsMatch[1]
          .split(/[,;]/)
          .map((t) => t.trim().toLowerCase())
          .filter(Boolean)
      );
    }

    // Trigger patterns from bullet points near "trigger" or "when to use" sections
    if (/trigger|when to use|activation/i.test(line)) {
      // Look ahead for bullet points
      for (let j = i + 1; j < Math.min(i + 10, lines.length); j++) {
        const bullet = lines[j].trim();
        if (bullet.startsWith("-") || bullet.startsWith("*")) {
          triggerPatterns.push(bullet.replace(/^[-*]\s*/, "").trim());
        } else if (bullet.startsWith("#") && j > i + 1) {
          break;
        }
      }
    }
  }

  // Fallback description from first non-empty non-heading line
  if (!description) {
    for (const line of lines) {
      const t = line.trim();
      if (t && !t.startsWith("#") && t.length > 10) {
        description = t;
        break;
      }
    }
  }

  // Auto-generate trigger patterns if none found
  if (triggerPatterns.length === 0 && name) {
    triggerPatterns.push(name.toLowerCase());
    if (description) {
      // Extract key nouns
      const words = description.toLowerCase().match(/\b[a-z]{4,}\b/g) ?? [];
      triggerPatterns.push(...words.slice(0, 3));
    }
  }

  // Auto-tags from name
  if (tags.length === 0) {
    tags.push(
      ...name
        .toLowerCase()
        .split(/[-_\s]+/)
        .filter((t) => t.length > 2)
    );
  }

  return { name: name || fallbackName, description, version, tags: [...new Set(tags)], triggerPatterns: [...new Set(triggerPatterns)] };
}

// ─── Main migration function ──────────────────────────────────────────────────

export async function migrateOpenClawSkills(
  options: SkillsMigrationOptions
): Promise<SkillsMigrationResult> {
  const { sourceDir, targetDir, dryRun, verbose = false } = options;

  const registry: SkillRegistryEntry[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  let skillsImported = 0;
  let skillsSkipped = 0;

  function log(msg: string) {
    if (verbose) console.log(`  [skills] ${msg}`);
  }

  // ── Check additional skill dirs ────────────────────────────────────────────

  const sourceDirs = [sourceDir];

  // Also check the built-in openclaw node_modules skills
  const nodeModulesSkills = join(
    homedir(),
    ".nvm/versions/node/v22.21.1/lib/node_modules/openclaw/skills"
  );
  if (existsSync(nodeModulesSkills) && !sourceDirs.includes(nodeModulesSkills)) {
    sourceDirs.push(nodeModulesSkills);
  }

  const seenSkills = new Set<string>();

  for (const dir of sourceDirs) {
    if (!existsSync(dir)) {
      warnings.push(`Skills source directory not found: ${dir}`);
      continue;
    }

    let skillNames: string[];
    try {
      skillNames = readdirSync(dir).filter((entry) => {
        try {
          return statSync(join(dir, entry)).isDirectory();
        } catch {
          return false;
        }
      });
    } catch (err: any) {
      errors.push(`Failed to read skills directory ${dir}: ${err?.message}`);
      continue;
    }

    for (const skillName of skillNames) {
      // Deduplicate across source dirs
      if (seenSkills.has(skillName)) {
        skillsSkipped++;
        log(`Skip duplicate: ${skillName}`);
        continue;
      }
      seenSkills.add(skillName);

      const skillSrcDir = join(dir, skillName);
      const skillDstDir = join(targetDir, skillName);
      const skillMdPath = join(skillSrcDir, "SKILL.md");
      const pkgJsonPath = join(skillSrcDir, "package.json");

      // Parse SKILL.md
      let parsed: ParsedSkillMd = {
        name: skillName,
        description: "",
        version: "1.0.0",
        tags: [],
        triggerPatterns: [],
      };

      if (existsSync(skillMdPath)) {
        try {
          const md = readFileSync(skillMdPath, "utf8");
          parsed = parseSkillMd(md, skillName);
        } catch (err: any) {
          warnings.push(`Could not parse SKILL.md for ${skillName}: ${err?.message}`);
        }
      } else if (existsSync(pkgJsonPath)) {
        try {
          const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
          parsed.name = pkg.name ?? skillName;
          parsed.description = pkg.description ?? "";
          parsed.version = pkg.version ?? "1.0.0";
          if (Array.isArray(pkg.keywords)) {
            parsed.tags = pkg.keywords.map((k: string) => k.toLowerCase());
          }
        } catch {
          // Use defaults
        }
      } else {
        warnings.push(`No SKILL.md or package.json for skill: ${skillName}`);
      }

      // Copy skill directory to target
      if (!dryRun) {
        try {
          mkdirSync(skillDstDir, { recursive: true });
          cpSync(skillSrcDir, skillDstDir, { recursive: true, force: false, errorOnExist: false });
        } catch (err: any) {
          errors.push(`Failed to copy skill ${skillName}: ${err?.message}`);
          continue;
        }
      }

      registry.push({
        id: `oc_${skillName}`,
        name: parsed.name || skillName,
        description: parsed.description,
        version: parsed.version,
        source: "openclaw",
        path: skillDstDir,
        enabled: true,
        tags: parsed.tags,
        triggerPatterns: parsed.triggerPatterns,
        createdAt: new Date().toISOString(),
        importedFrom: skillSrcDir,
      });

      skillsImported++;
      log(`Imported: ${skillName} (${parsed.tags.join(", ")})`);
    }
  }

  // ── Write registry JSON ───────────────────────────────────────────────────

  if (!dryRun && registry.length > 0) {
    try {
      mkdirSync(targetDir, { recursive: true });
      const registryPath = join(targetDir, "openclaw-registry.json");
      writeFileSync(registryPath, JSON.stringify(registry, null, 2) + "\n", "utf8");

      // Merge into main registry if it exists
      const mainRegistryPath = join(targetDir, "registry.json");
      let mainRegistry: SkillRegistryEntry[] = [];
      if (existsSync(mainRegistryPath)) {
        try {
          mainRegistry = JSON.parse(readFileSync(mainRegistryPath, "utf8"));
        } catch {
          mainRegistry = [];
        }
      }

      // Merge, no duplicates by id
      const existingIds = new Set(mainRegistry.map((e) => e.id));
      const newEntries = registry.filter((e) => !existingIds.has(e.id));
      const merged = [...mainRegistry, ...newEntries];
      writeFileSync(mainRegistryPath, JSON.stringify(merged, null, 2) + "\n", "utf8");

      log(`Registry written: ${registry.length} skills`);
    } catch (err: any) {
      errors.push(`Failed to write skills registry: ${err?.message}`);
    }
  }

  return {
    success: errors.length === 0,
    skillsImported,
    skillsSkipped,
    errors,
    warnings,
    registry,
  };
}
