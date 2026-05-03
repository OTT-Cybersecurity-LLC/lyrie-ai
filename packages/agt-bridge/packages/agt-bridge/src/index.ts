/**
 * @lyrie/agt-bridge
 *
 * Microsoft Agent Governance Toolkit integration for Lyrie v1.0.0.
 *
 * Usage:
 *
 *   import { AGTBridge, getAGTBridge } from '@lyrie/agt-bridge';
 *
 *   const bridge = getAGTBridge();
 *
 *   // Generate a policy from a Lyrie scope declaration
 *   const policy = bridge.generatePolicy({
 *     agentId: 'lyrie-core',
 *     allowedTools: ['read', 'web_fetch'],
 *     deniedTools: [],
 *     maxCallsPerTurn: 25,
 *   });
 *
 *   // Validate a tool call
 *   const result = await bridge.validateToolCall(
 *     'lyrie-core',
 *     'exec',
 *     { command: 'ls -la' },
 *     { agentId: 'lyrie-core', callsThisTurn: 3 }
 *   );
 *
 *   if (!result.allowed) {
 *     console.error(`Blocked: ${result.reason}`);
 *   }
 *
 * Coverage:
 *   With AGT:    10/10 OWASP ASI 2026 controls (deterministic, sub-ms)
 *   Without AGT:  7/10 (Lyrie ShieldGuard native mode)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

export { AGTBridge, getAGTBridge, resetAGTBridge } from "./bridge";
export { PolicyGenerator, policyGenerator } from "./policy";
export { ToolCallValidator, toolCallValidator } from "./validator";
export type {
  AGTPolicy,
  AGTAvailabilityInfo,
  AgentContext,
  ScopeDeclaration,
  ValidationResult,
} from "./types";
