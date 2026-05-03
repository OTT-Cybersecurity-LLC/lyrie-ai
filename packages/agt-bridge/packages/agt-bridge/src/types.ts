/**
 * @lyrie/agt-bridge — Shared types
 *
 * These types mirror the public Microsoft Agent Governance Toolkit (AGT)
 * policy format so that Lyrie's policy translator produces documents that
 * the AGT runtime can consume without modification.
 *
 * Reference: https://github.com/microsoft/agent-governance-toolkit
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

// ─── AGT Policy Format ────────────────────────────────────────────────────────

/**
 * Full AGT-compatible policy document generated from a Lyrie
 * ScopeDeclaration (ATP SDL).
 */
export interface AGTPolicy {
  version: "1.0";
  agent: {
    id: string;
    allowedTools: string[];
    deniedTools: string[];
    maxCallsPerTurn: number;
    requireHumanApproval: string[];
  };
  controls: {
    /** Prompt injection detection & mitigation */
    asi01_prompt_injection: boolean;
    /** Resource overuse prevention */
    asi02_resource_overuse: boolean;
    /** Tool misuse detection */
    asi03_tool_misuse: boolean;
    /** Excessive agency restriction */
    asi04_excessive_agency: boolean;
    /** Sensitive data exposure prevention */
    asi05_sensitive_data_exposure: boolean;
    /** Memory poisoning detection */
    asi06_memory_poisoning: boolean;
    /** Uncontrolled sub-agent restriction */
    asi07_uncontrolled_subagents: boolean;
    /** Trust boundary violation detection */
    asi08_trust_boundary_violation: boolean;
    /** Unverified output detection */
    asi09_unverified_outputs: boolean;
    /** Audit evasion prevention */
    asi10_audit_evasion: boolean;
  };
}

// ─── Lyrie ATP SDL types ───────────────────────────────────────────────────────

/**
 * Lyrie Agent Trust Profile — Scope Declaration Language (ATP SDL).
 * This is Lyrie's native way of expressing what an agent is allowed to do.
 * The AGTBridge translates it to AGT policy format.
 */
export interface ScopeDeclaration {
  /** Stable identifier for the agent (e.g. "lyrie-core", "pentest-runner") */
  agentId: string;

  /** Human-readable description of the agent's purpose */
  description?: string;

  /** Tools that this agent is explicitly permitted to use */
  allowedTools?: string[];

  /** Tools that this agent is explicitly forbidden from using */
  deniedTools?: string[];

  /**
   * Tools that require human approval before execution.
   * Typically high-risk tools: exec, file write, network calls, etc.
   */
  requireApproval?: string[];

  /** Maximum tool calls allowed in a single turn (default: 25) */
  maxCallsPerTurn?: number;

  /** OWASP ASI 2026 controls override. All default to true. */
  controls?: Partial<AGTPolicy["controls"]>;

  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

// ─── Agent context ─────────────────────────────────────────────────────────────

/**
 * Runtime context passed to AGTBridge.validateToolCall.
 * Provides the enforcement engine with enough information to make
 * a deterministic policy decision.
 */
export interface AgentContext {
  /** The agent whose policy should be consulted */
  agentId: string;
  /** Number of tool calls already made this turn */
  callsThisTurn?: number;
  /** Session ID for audit tracing */
  sessionId?: string;
  /** Optional caller-supplied metadata */
  metadata?: Record<string, unknown>;
}

// ─── Validation result ─────────────────────────────────────────────────────────

export interface ValidationResult {
  /** Whether the tool call is allowed to proceed */
  allowed: boolean;
  /** Human-readable reason for the decision */
  reason?: string;
  /** Wall-clock enforcement latency in milliseconds */
  latencyMs: number;
  /** Which ASI controls triggered a block (if any) */
  triggeredControls?: Array<keyof AGTPolicy["controls"]>;
}

// ─── AGT availability ──────────────────────────────────────────────────────────

export interface AGTAvailabilityInfo {
  available: boolean;
  /** Path to the AGT binary if found */
  binaryPath?: string;
  /** AGT version string */
  version?: string;
  /** Human-readable message (e.g. install instructions when unavailable) */
  message: string;
}
