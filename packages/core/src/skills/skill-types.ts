/**
 * Skill Types — Interfaces for the SKILL.md runtime.
 *
 * These types represent OpenClaw-format skills (SKILL.md files with YAML
 * frontmatter + markdown instructions). Lyrie can load and execute all 129
 * installed OpenClaw skills without any migration needed.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Manifest ────────────────────────────────────────────────────────────────

/**
 * Parsed from a SKILL.md file. The frontmatter is YAML; the body is the
 * markdown instructions that get injected into the agent's system prompt.
 */
export interface SkillManifest {
  /** Human-readable skill name (from frontmatter `name:`) */
  name: string;
  /** Short description used for search / list display */
  description?: string;
  /** Semver string, e.g. "1.0.0" */
  version?: string;
  /** Author or team */
  author?: string;
  /** Required tool names the agent needs to run this skill */
  tools?: string[];
  /** Channel names where this skill is applicable (e.g. "telegram", "slack") */
  channels?: string[];
  /** Keywords / phrases that activate this skill */
  triggers?: string[];
  /** Absolute path to the SKILL.md file */
  location: string;
  /** Full SKILL.md content (the system-prompt instructions) */
  content: string;
}

// ─── Context ─────────────────────────────────────────────────────────────────

/** Runtime context available when a skill is activated. */
export interface SkillContext {
  /** The incoming user message or task description */
  message?: string;
  /** The channel the request arrived on */
  channel?: string;
  /** Additional key-value metadata (model, session id, etc.) */
  metadata?: Record<string, unknown>;
}

// ─── Activated Skill ─────────────────────────────────────────────────────────

/**
 * Result of SkillRunner.activate() — ready to inject into the agent's
 * system prompt.
 */
export interface ActivatedSkill {
  /** The manifest that was activated */
  manifest: SkillManifest;
  /** The text to inject as an additional system-prompt section */
  systemPromptInjection: string;
  /** ISO timestamp when the skill was activated */
  activatedAt: string;
}
