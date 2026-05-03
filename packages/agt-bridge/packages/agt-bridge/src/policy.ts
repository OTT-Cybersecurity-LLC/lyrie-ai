/**
 * @lyrie/agt-bridge — Policy translator
 *
 * Converts a Lyrie ATP ScopeDeclaration into an AGT-compatible policy
 * document. This is the bridge between Lyrie's native SDL and the AGT
 * enforcement runtime.
 *
 * Design choices:
 * - ALL 10 OWASP ASI 2026 controls are enabled by default. Operators may
 *   disable specific controls via `scope.controls`, but this is discouraged
 *   and logged as a warning.
 * - The `requireApproval` list in ScopeDeclaration becomes
 *   `agent.requireHumanApproval` in AGT policy.
 * - If no allowedTools are declared, the policy uses a wildcard approach
 *   (empty allowedTools list means "all not-denied tools are allowed").
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import type { AGTPolicy, ScopeDeclaration } from "./types";

// ─── Defaults ─────────────────────────────────────────────────────────────────

const DEFAULT_MAX_CALLS_PER_TURN = 25;

/**
 * Default set of tools that always require human approval unless explicitly
 * overridden by the operator. These are the highest-risk tool classes.
 */
const HIGH_RISK_TOOLS_REQUIRING_APPROVAL: ReadonlyArray<string> = [
  // Shell execution
  "exec",
  "shell",
  "bash",
  "run_command",
  // Destructive file ops
  "delete_file",
  "write_file",
  // Network
  "web_fetch",
  "http_request",
  // Credential / secret access
  "get_secret",
  "read_credentials",
  // Sub-agent spawn
  "spawn_agent",
  "create_subagent",
];

/**
 * Default set of tools that are denied unless the operator explicitly
 * allows them. These represent capabilities that should never be available
 * to an untrusted agent.
 */
const DEFAULT_DENIED_TOOLS: ReadonlyArray<string> = [
  // Privilege escalation
  "sudo",
  "su",
  "pkexec",
  // Direct system manipulation
  "load_kernel_module",
  "raw_socket",
  // Clipboard / screen capture (potential exfil)
  "capture_screen",
  "read_clipboard",
];

// ─── All-controls-on baseline ─────────────────────────────────────────────────

const ALL_CONTROLS_ENABLED: AGTPolicy["controls"] = {
  asi01_prompt_injection: true,
  asi02_resource_overuse: true,
  asi03_tool_misuse: true,
  asi04_excessive_agency: true,
  asi05_sensitive_data_exposure: true,
  asi06_memory_poisoning: true,
  asi07_uncontrolled_subagents: true,
  asi08_trust_boundary_violation: true,
  asi09_unverified_outputs: true,
  asi10_audit_evasion: true,
};

// ─── PolicyGenerator ─────────────────────────────────────────────────────────

export class PolicyGenerator {
  /**
   * Generate an AGT-compatible policy from a Lyrie ScopeDeclaration.
   *
   * @param scope - The Lyrie ATP scope declaration
   * @returns Full AGT policy document ready for consumption by the AGT runtime
   */
  generate(scope: ScopeDeclaration): AGTPolicy {
    this.validateScope(scope);

    const allowedTools = scope.allowedTools ?? [];
    const deniedTools = [
      ...DEFAULT_DENIED_TOOLS.filter(
        (t) => !(scope.allowedTools ?? []).includes(t)
      ),
      ...(scope.deniedTools ?? []),
    ];

    // De-duplicate denied list
    const uniqueDenied = [...new Set(deniedTools)];

    // Human approval list: operator's explicit list + defaults for high-risk
    // tools that are in the allowed set.
    const requireHumanApproval = this.buildApprovalList(
      scope.requireApproval,
      allowedTools
    );

    // Controls: start with all-enabled baseline, then apply overrides.
    const controls = this.buildControls(scope.controls);

    return {
      version: "1.0",
      agent: {
        id: scope.agentId,
        allowedTools,
        deniedTools: uniqueDenied,
        maxCallsPerTurn: scope.maxCallsPerTurn ?? DEFAULT_MAX_CALLS_PER_TURN,
        requireHumanApproval,
      },
      controls,
    };
  }

  /**
   * Serialize an AGT policy to a YAML-like string suitable for writing
   * to disk or passing to the AGT binary via stdin.
   */
  serialize(policy: AGTPolicy): string {
    return JSON.stringify(policy, null, 2);
  }

  /**
   * Validate a ScopeDeclaration and throw if it is obviously malformed.
   */
  private validateScope(scope: ScopeDeclaration): void {
    if (!scope.agentId || typeof scope.agentId !== "string") {
      throw new TypeError("ScopeDeclaration.agentId must be a non-empty string");
    }
    if (scope.agentId.trim() === "") {
      throw new TypeError("ScopeDeclaration.agentId must not be blank");
    }
    if (
      scope.maxCallsPerTurn !== undefined &&
      (typeof scope.maxCallsPerTurn !== "number" || scope.maxCallsPerTurn < 1)
    ) {
      throw new TypeError("ScopeDeclaration.maxCallsPerTurn must be a positive number");
    }
    // Warn if any ASI controls are disabled
    if (scope.controls) {
      for (const [key, value] of Object.entries(scope.controls)) {
        if (value === false) {
          console.warn(
            `[agt-bridge] WARNING: OWASP ASI control ${key} is disabled in scope "${scope.agentId}". ` +
              `This reduces coverage below 10/10. Only disable if you have a compensating control.`
          );
        }
      }
    }
  }

  private buildApprovalList(
    operatorList: string[] | undefined,
    allowedTools: string[]
  ): string[] {
    const base = new Set<string>(operatorList ?? []);

    // Automatically require approval for high-risk tools that are explicitly
    // allowed by the operator.
    if (allowedTools.length > 0) {
      for (const tool of allowedTools) {
        if (HIGH_RISK_TOOLS_REQUIRING_APPROVAL.includes(tool)) {
          base.add(tool);
        }
      }
    } else {
      // Wildcard allowed — add all high-risk defaults to approval list
      for (const tool of HIGH_RISK_TOOLS_REQUIRING_APPROVAL) {
        base.add(tool);
      }
    }

    return [...base].sort();
  }

  private buildControls(
    overrides: Partial<AGTPolicy["controls"]> | undefined
  ): AGTPolicy["controls"] {
    if (!overrides) return { ...ALL_CONTROLS_ENABLED };
    return { ...ALL_CONTROLS_ENABLED, ...overrides };
  }
}

// ─── Convenience singleton ────────────────────────────────────────────────────

export const policyGenerator = new PolicyGenerator();
