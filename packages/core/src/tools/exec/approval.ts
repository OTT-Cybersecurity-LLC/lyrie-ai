/**
 * approval.ts — Risk detection and approval workflow for LyrieExec.
 *
 * Auto-detects dangerous commands and raises ApprovalRequired before
 * any subprocess is spawned. Better than OpenClaw's passive ask=on-miss
 * pattern — Lyrie actively analyzes the command.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Patterns ────────────────────────────────────────────────────────────────

/**
 * Commands that unconditionally require human approval.
 * Ordered from most specific to most general.
 */
export const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /rm\s+-[a-z]*r[a-z]*f[a-z]*\s*\//, reason: "recursive delete from root" },
  { pattern: /rm\s+-[a-z]*f[a-z]*r[a-z]*\s*\//, reason: "recursive delete from root" },
  { pattern: /rm\s+--no-preserve-root/, reason: "no-preserve-root flag" },
  { pattern: /curl[^|]*\|\s*(ba)?sh/, reason: "piped shell execution (curl|sh)" },
  { pattern: /wget[^|]*\|\s*(ba)?sh/, reason: "piped shell execution (wget|sh)" },
  { pattern: /fetch[^|]*\|\s*(ba)?sh/, reason: "piped shell execution (fetch|sh)" },
  { pattern: /dd\s+if=/, reason: "dd disk write" },
  { pattern: /mkfs\./, reason: "filesystem formatting" },
  { pattern: /:\(\)\s*\{.*:\|:&.*\}/, reason: "fork bomb" },
  { pattern: />\s*\/dev\/(s|h|vd|xvd|nvme)[a-z0-9]+/, reason: "write to raw block device" },
  { pattern: /shred\s+/, reason: "secure delete tool" },
  { pattern: /chmod\s+-R\s+777\s+\//, reason: "chmod 777 on root" },
  { pattern: /chown\s+-R\s+.*\s+\//, reason: "chown on root" },
  { pattern: /iptables\s+-F/, reason: "flush iptables rules" },
  { pattern: /systemctl\s+(disable|stop|mask)\s+(ssh|sshd)/, reason: "disabling SSH" },
  { pattern: /cryptsetup\s+luksFormat/, reason: "LUKS encryption format" },
  { pattern: /wipefs\s+-a/, reason: "wipe filesystem signatures" },
  { pattern: /eval\s+['"`]\$\(/, reason: "eval with command substitution" },
  { pattern: /base64\s+-d.*\|\s*(ba)?sh/, reason: "base64-decoded shell execution" },
];

/**
 * Commands that require approval in elevated/root context only.
 * (Not currently enforced at the pattern level — reserved for future use.)
 */
export const ELEVATED_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /sudo\s+rm/, reason: "sudo rm" },
  { pattern: /sudo\s+dd/, reason: "sudo dd" },
];

// ─── Types ───────────────────────────────────────────────────────────────────

export class ApprovalRequired extends Error {
  constructor(
    public readonly command: string,
    public readonly reason: string,
  ) {
    super(`Command requires approval: ${reason}\nCommand: ${command}`);
    this.name = "ApprovalRequired";
  }
}

export interface RiskAssessment {
  needsApproval: boolean;
  reason?: string;
  risk: "safe" | "moderate" | "dangerous";
}

// ─── Functions ───────────────────────────────────────────────────────────────

/**
 * Assess the risk level of a shell command.
 * Returns needsApproval=true if the command matches any dangerous pattern.
 */
export function assessRisk(command: string): RiskAssessment {
  // Strip comments and normalise whitespace for matching
  const normalised = command
    .replace(/#[^\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  for (const { pattern, reason } of DANGEROUS_PATTERNS) {
    if (pattern.test(normalised)) {
      return { needsApproval: true, reason, risk: "dangerous" };
    }
  }

  // Moderate risk heuristics (warn but don't block)
  const moderatePatterns = [
    /sudo\s/,
    /pkill|killall/,
    /truncate\s+/,
    />\s*\/etc\//,
  ];
  for (const p of moderatePatterns) {
    if (p.test(normalised)) {
      return { needsApproval: false, risk: "moderate" };
    }
  }

  return { needsApproval: false, risk: "safe" };
}

/**
 * Convenience: returns true if the command needs approval.
 * Throws nothing — callers decide what to do with the result.
 */
export function needsApproval(command: string): boolean {
  return assessRisk(command).needsApproval;
}

/**
 * Throws ApprovalRequired if the command is dangerous.
 * Call this before spawning any subprocess.
 */
export function requireApprovalCheck(command: string): void {
  const assessment = assessRisk(command);
  if (assessment.needsApproval) {
    throw new ApprovalRequired(command, assessment.reason!);
  }
}
