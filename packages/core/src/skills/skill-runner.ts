/**
 * SkillRunner — Activates a skill by injecting its SKILL.md instructions
 * into the agent's context.
 *
 * This mirrors how OpenClaw works: skills are not code executors, they are
 * system-prompt injections that give the agent specialised instructions for
 * a particular task domain.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { SkillContext, ActivatedSkill } from "./skill-types";
import { SkillRegistry, buildSystemPromptBlock } from "./skill-registry";

// ─── SkillRunner ─────────────────────────────────────────────────────────────

export class SkillRunner {
  private registry: SkillRegistry;

  constructor(registry?: SkillRegistry) {
    this.registry = registry ?? SkillRegistry.getInstance();
  }

  /**
   * Activate a skill by name. Looks up the manifest, builds the system-prompt
   * injection, and returns an ActivatedSkill ready to prepend to the next
   * agent turn.
   *
   * Throws if the skill is not found in the registry.
   */
  async activate(skillName: string, context: SkillContext = {}): Promise<ActivatedSkill> {
    const manifest = this.registry.get(skillName);
    if (!manifest) {
      throw new Error(
        `Skill "${skillName}" not found. Run \`lyrie skills list\` to see available skills.`
      );
    }

    const systemPromptInjection = buildSystemPromptBlock(manifest);

    return {
      manifest,
      systemPromptInjection,
      activatedAt: new Date().toISOString(),
    };
  }

  /**
   * Check whether the registry contains a skill with the given name.
   */
  has(skillName: string): boolean {
    return this.registry.get(skillName) !== undefined;
  }
}
