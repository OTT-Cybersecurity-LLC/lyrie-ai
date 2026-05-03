/**
 * @lyrie/agt-bridge — AGTBridge
 *
 * The main integration class. Sits between Lyrie's ShieldManager and the
 * Microsoft Agent Governance Toolkit. Provides:
 *
 *   1. `validateToolCall()` — deterministic, sub-ms enforcement of all 10
 *      OWASP ASI 2026 controls when AGT is available; graceful degradation
 *      to Lyrie's native ShieldGuard (7/10) when it's not.
 *
 *   2. `generatePolicy()` — translate a Lyrie ATP ScopeDeclaration to an
 *      AGT-compatible policy document.
 *
 *   3. `isAvailable()` — whether the AGT binary is on PATH.
 *
 * Coverage:
 *   With AGT:    10/10 OWASP ASI 2026 (deterministic, <1 ms per call)
 *   Without AGT:  7/10 (Lyrie ShieldGuard regex, <0.1 ms per call)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { execSync } from "node:child_process";
import { PolicyGenerator } from "./policy";
import { ToolCallValidator } from "./validator";
import type {
  AGTAvailabilityInfo,
  AGTPolicy,
  AgentContext,
  ScopeDeclaration,
  ValidationResult,
} from "./types";

// ─── AGTBridge ────────────────────────────────────────────────────────────────

export class AGTBridge {
  private readonly policyGenerator: PolicyGenerator;
  private readonly validator: ToolCallValidator;

  /** Cached availability check result (evaluated once at construction) */
  private readonly availability: AGTAvailabilityInfo;

  /** In-memory policy store keyed by agentId */
  private readonly policies = new Map<string, AGTPolicy>();

  constructor() {
    this.policyGenerator = new PolicyGenerator();
    this.validator = new ToolCallValidator();
    this.availability = this.checkAGTAvailability();

    if (!this.availability.available) {
      console.warn(
        "[agt-bridge] WARNING: Microsoft Agent Governance Toolkit (AGT) is not installed. " +
          "Lyrie is running in standalone mode with 7/10 OWASP ASI 2026 coverage. " +
          "Run `lyrie governance agt --install-guide` for installation instructions."
      );
    } else {
      console.log(
        `[agt-bridge] ✓ AGT ${this.availability.version ?? ""} detected at ${this.availability.binaryPath}. ` +
          "10/10 OWASP ASI 2026 coverage active."
      );
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Validate a proposed tool call against the agent's AGT policy.
   *
   * @param agentId - The agent ID whose policy to consult
   * @param tool    - The tool being called (e.g. "exec", "web_fetch")
   * @param params  - Parameters the model wants to pass to the tool
   * @param context - Runtime context (callsThisTurn, sessionId, etc.)
   * @returns Validation result including allow/deny decision and latency
   */
  async validateToolCall(
    agentId: string,
    tool: string,
    params: Record<string, unknown>,
    context: AgentContext
  ): Promise<ValidationResult> {
    const policy = this.getPolicyForAgent(agentId);
    return this.validator.validate(
      tool,
      params,
      policy,
      { ...context, agentId },
      this.availability.available
    );
  }

  /**
   * Generate an AGT-compatible policy from a Lyrie ScopeDeclaration.
   * The generated policy is cached in memory so subsequent `validateToolCall`
   * calls for the same agentId use it.
   *
   * @param scope - ATP ScopeDeclaration
   * @returns Generated AGT policy
   */
  generatePolicy(scope: ScopeDeclaration): AGTPolicy {
    const policy = this.policyGenerator.generate(scope);
    this.policies.set(scope.agentId, policy);
    return policy;
  }

  /**
   * Register a pre-built AGT policy for an agent.
   * Useful when loading policy documents from disk.
   */
  registerPolicy(policy: AGTPolicy): void {
    this.policies.set(policy.agent.id, policy);
  }

  /**
   * Whether the Microsoft AGT binary is available on this system.
   * When true: 10/10 OWASP ASI 2026 coverage (deterministic AGT engine).
   * When false: 7/10 coverage (Lyrie ShieldGuard native mode).
   */
  isAvailable(): boolean {
    return this.availability.available;
  }

  /**
   * Full availability info: binary path, version, and a message.
   */
  getAvailabilityInfo(): AGTAvailabilityInfo {
    return { ...this.availability };
  }

  /**
   * Return coverage percentage based on AGT availability.
   * Used in `lyrie doctor` and README-generation scripts.
   */
  coverageScore(): { owasp_asi_controls: number; percentage: number } {
    return this.availability.available
      ? { owasp_asi_controls: 10, percentage: 100 }
      : { owasp_asi_controls: 7, percentage: 70 };
  }

  // ─── Internal ───────────────────────────────────────────────────────────────

  /**
   * Look up or create a default policy for an agent.
   * If no policy has been registered, a permissive default is returned.
   */
  private getPolicyForAgent(agentId: string): AGTPolicy {
    const existing = this.policies.get(agentId);
    if (existing) return existing;

    // Lazy-create a default permissive policy for unknown agents.
    const defaultPolicy = this.policyGenerator.generate({ agentId });
    this.policies.set(agentId, defaultPolicy);
    return defaultPolicy;
  }

  /**
   * Check whether the AGT binary is available on the system.
   * Tries `agt version` and `agent-governance-toolkit version`.
   */
  private checkAGTAvailability(): AGTAvailabilityInfo {
    const candidates = ["agt", "agent-governance-toolkit"];

    for (const bin of candidates) {
      try {
        const output = execSync(`${bin} version 2>/dev/null`, {
          encoding: "utf8",
          timeout: 2000,
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();

        // Extract version string (e.g. "1.0.0" or "agt v1.0.0")
        const versionMatch = output.match(/v?(\d+\.\d+\.\d+)/);
        const version = versionMatch ? versionMatch[1] : output;

        const binaryPath = this.resolveBinaryPath(bin);

        return {
          available: true,
          binaryPath,
          version,
          message: `AGT ${version} is available at ${binaryPath}`,
        };
      } catch {
        // Not found or errored — try next candidate
      }
    }

    return {
      available: false,
      message:
        "Microsoft Agent Governance Toolkit is not installed. " +
        "Install it with: npm install -g @microsoft/agent-governance-toolkit\n" +
        "Or visit: https://github.com/microsoft/agent-governance-toolkit\n" +
        "Without AGT, Lyrie operates at 7/10 OWASP ASI 2026 coverage.",
    };
  }

  private resolveBinaryPath(bin: string): string {
    try {
      return execSync(`which ${bin} 2>/dev/null`, {
        encoding: "utf8",
        timeout: 1000,
      }).trim();
    } catch {
      return bin;
    }
  }
}

// ─── Convenience factory ──────────────────────────────────────────────────────

let _instance: AGTBridge | undefined;

/**
 * Get (or create) a process-scoped singleton AGTBridge.
 * Use this in production code to avoid repeated availability checks.
 */
export function getAGTBridge(): AGTBridge {
  if (!_instance) {
    _instance = new AGTBridge();
  }
  return _instance;
}

/**
 * Reset the singleton (useful in tests to force a fresh availability check).
 */
export function resetAGTBridge(): void {
  _instance = undefined;
}
