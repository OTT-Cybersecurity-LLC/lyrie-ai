/**
 * exec/index.ts — Public exports for LyrieExec tool package.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export { lyrieExecTool, processManager, EXEC_TOOL_SCHEMA } from "./exec-tool";
export { ProcessManager } from "./process-manager";
export type { ExecOptions, ExecResult, PollResult, SessionInfo, SessionStatus } from "./process-manager";
export { assessRisk, needsApproval, requireApprovalCheck, ApprovalRequired, DANGEROUS_PATTERNS } from "./approval";
export type { RiskAssessment } from "./approval";
