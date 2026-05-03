/**
 * LyrieCoordinator — Pure-orchestrator mode (Claude Code v2.1.88 pattern).
 *
 * When coordinator mode is enabled:
 *   1. The MAIN agent can ONLY spawn sub-agents and aggregate results.
 *   2. The main agent CANNOT directly call exec/read_file/write_file/etc.
 *   3. Real work happens inside sub-agents (which may themselves spawn workers).
 *   4. The main agent synthesizes results and reports back to the user.
 *
 * Why: prevents "I'll handle it myself" failure mode where the main agent
 * burns context doing implementation work it should have delegated.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { Tool } from "../tools/tool-executor";

/** Tools allowed in coordinator mode (the only ones it sees). */
export const COORDINATOR_ALLOWED_TOOLS: Set<string> = new Set([
  "agent_spawn", // spawn a sub-agent (fork or fresh)
  "agent_status", // poll a running sub-agent
  "agent_kill", // kill a sub-agent
  "tool_search", // fetch deferred schemas (still allowed for visibility)
  "team_create", // multi-agent team
  "team_delete",
  "send_message", // send to a specific agent in a team
  "report", // emit a final aggregated report
]);

export const COORDINATOR_PROMPT = `# Coordinator Mode

You are running in COORDINATOR mode. Your role is the orchestrator, not the implementer.

## Hard rules
1. You may ONLY use these tools: agent_spawn, agent_status, agent_kill, tool_search, team_create, team_delete, send_message, report.
2. You may NOT call exec, read_file, write_file, web_fetch, web_search, threat_scan, or any other implementation tool. If you need that work done, spawn a sub-agent.
3. Every sub-agent you spawn must have a NARROWER scope than yours (ATP trust-chain rule).
4. Don't peek: the sub-agent's output_file is private until it completes. You'll get a push notification.
5. Don't race: never fabricate or predict sub-agent results. Wait for completion.
6. Never delegate understanding. If you tell a sub-agent "based on your findings, fix the bug", you've outsourced thinking. Include file paths, line numbers, exact failures.

## Sub-agent types (canonical)
- scanner — defensive enumeration, mapping, asset discovery
- analyst — read-only research, no writes
- exploiter — exploit dev / PoC, requires explicit authorization in scope
- verifier — adversarial verification of completed work (auto-spawned post-task)
- reporter — synthesize findings into Markdown / SARIF / threat-feed entries

## Spawn modes
- mode: "fork" — inherits parent context (cheaper, shared cache, same model)
- mode: "fresh" — clean context (more isolated, can override model)

## Concurrency
Spawn multiple sub-agents in ONE message when their tasks are independent. Don't serialize what can run in parallel.

## Your output
- For each user request: decompose → spawn → wait → synthesize → report.
- End your turn with a status block: ✅ what completed, ⚠️ what's blocked, 🔜 what's next.
- Never end with "want me to..." dangling questions.`;

export interface CoordinatorOptions {
  /** Override the allowed-tools allowlist. */
  allowedTools?: Set<string>;
  /** Append additional rules to the coordinator prompt. */
  appendRules?: string;
}

export class LyrieCoordinator {
  private allowed: Set<string>;
  private appendRules?: string;

  constructor(opts: CoordinatorOptions = {}) {
    this.allowed = opts.allowedTools ?? COORDINATOR_ALLOWED_TOOLS;
    this.appendRules = opts.appendRules;
  }

  /** Filter the global tool list down to coordinator-allowed only. */
  filterTools(allTools: Tool[]): Tool[] {
    return allTools.filter((t) => this.allowed.has(t.name));
  }

  /** True if the named tool is allowed in coordinator mode. */
  isAllowed(toolName: string): boolean {
    return this.allowed.has(toolName);
  }

  /** Returns the coordinator system-prompt addendum. */
  getSystemPromptAddendum(): string {
    return this.appendRules
      ? `${COORDINATOR_PROMPT}\n\n${this.appendRules}`
      : COORDINATOR_PROMPT;
  }

  /** Returns the addendum AS the dynamic-section coordinator note. */
  getDynamicNote(): string {
    return this.getSystemPromptAddendum();
  }
}
