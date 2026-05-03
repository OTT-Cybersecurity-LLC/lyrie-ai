/**
 * Lyrie System-Prompt Building Blocks.
 *
 * Re-exports the canonical static-prompt sections so any caller (engine,
 * sub-agent, daemon, verifier) can compose system prompts consistently.
 *
 * The Anti-False-Claims rule is mandatory in EVERY Lyrie system prompt.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export {
  LYRIE_PROMPT_CACHE_BOUNDARY,
  LYRIE_ANTI_FALSE_CLAIMS_RULE,
  LYRIE_IDENTITY,
  LYRIE_SHIELD_RULES,
  LYRIE_SECURITY_RULES,
  LYRIE_TASK_DISCIPLINE,
  PromptBuilder,
} from "./prompt-builder";

export type { SessionContext, PromptBuildOptions } from "./prompt-builder";

export { LYRIE_TICK_PROMPT } from "./daemon";
export { LYRIE_VERIFIER_PROMPT } from "../agents/verifier";
export { COORDINATOR_PROMPT, COORDINATOR_ALLOWED_TOOLS } from "../agents/coordinator";

/**
 * Cyber-risk gate (mirrors Anthropic's CYBER_RISK_INSTRUCTION).
 * Injected into every Lyrie system prompt that touches offensive tooling.
 */
export const LYRIE_CYBER_RISK_INSTRUCTION = `IMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Refuse requests for destructive techniques, DoS attacks, mass targeting, supply-chain compromise, or detection-evasion for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.`;

/**
 * Build a minimal system prompt for ad-hoc callers (no SessionContext).
 * Always includes the Anti-False-Claims rule.
 */
import {
  LYRIE_ANTI_FALSE_CLAIMS_RULE,
  LYRIE_IDENTITY,
  LYRIE_SECURITY_RULES,
  LYRIE_SHIELD_RULES,
  LYRIE_TASK_DISCIPLINE,
} from "./prompt-builder";

export function buildMinimalSystemPrompt(extras?: string): string {
  return [
    LYRIE_IDENTITY,
    LYRIE_SHIELD_RULES,
    LYRIE_SECURITY_RULES,
    LYRIE_TASK_DISCIPLINE,
    LYRIE_ANTI_FALSE_CLAIMS_RULE,
    LYRIE_CYBER_RISK_INSTRUCTION,
    ...(extras ? [extras] : []),
  ].join("\n\n");
}
