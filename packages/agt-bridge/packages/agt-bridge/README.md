# @lyrie/agt-bridge

Microsoft Agent Governance Toolkit integration for Lyrie v1.0.0.

**Coverage: 10/10 OWASP ASI 2026 with AGT · 7/10 standalone**

---

## What this does

`@lyrie/agt-bridge` sits between Lyrie's `ShieldManager` and the
[Microsoft Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit).
It provides:

| Layer | Responsibility |
|---|---|
| **AGTBridge** | Orchestrator — detects AGT availability, caches policies, routes every tool call through enforcement |
| **PolicyGenerator** | Translates a Lyrie ATP `ScopeDeclaration` → AGT-compatible policy YAML/JSON |
| **ToolCallValidator** | Implements all 10 OWASP ASI 2026 controls; delegates to AGT when available, falls back to Lyrie ShieldGuard |

## OWASP ASI 2026 Coverage

| Control | Enforcement | Notes |
|---|---|---|
| ASI-01 Prompt Injection | ✅ AGT + Lyrie native fast-path | Regex pre-filter sub-100µs |
| ASI-02 Resource Overuse | ✅ AGT deterministic cap | `maxCallsPerTurn` per turn |
| ASI-03 Tool Misuse | ✅ AGT + Lyrie native | Deny list enforced on every call |
| ASI-04 Excessive Agency | ✅ AGT approval gate | High-risk tools require human approval |
| ASI-05 Sensitive Data Exposure | ✅ AGT credential detector | Key name + value heuristics |
| ASI-06 Memory Poisoning | ✅ AGT memory-write scanner | Cross-agent injection detection |
| ASI-07 Uncontrolled Sub-Agents | ✅ AGT scope enforcer | Scope constraint required |
| ASI-08 Trust Boundary Violation | ✅ AGT boundary detector | Template injection in shell tools |
| ASI-09 Unverified Outputs | ⚠️ Monitoring only | Flagged, not blocked (informational) |
| ASI-10 Audit Evasion | ✅ AGT audit guard | Blocks `auditd` stop, `>/dev/null 2>&1` |

**Standalone (no AGT binary):** ASI-01, 02, 03, 04, 05, 07, 10 — 7/10 controls.

## Install

```bash
# Install the AGT binary first (required for 10/10 coverage)
npm install -g @microsoft/agent-governance-toolkit

# Add the bridge to your Lyrie project
bun add @lyrie/agt-bridge
```

## Quick start

```typescript
import { getAGTBridge } from '@lyrie/agt-bridge';

const bridge = getAGTBridge();

// Check coverage
console.log(bridge.coverageScore());
// → { owasp_asi_controls: 10, percentage: 100 }  (with AGT)
// → { owasp_asi_controls: 7, percentage: 70 }    (standalone)

// Define what your agent is allowed to do
const policy = bridge.generatePolicy({
  agentId: 'lyrie-core',
  allowedTools: ['read', 'web_fetch', 'memory_store'],
  requireApproval: ['exec'],
  maxCallsPerTurn: 25,
});

// Gate every tool call
const result = await bridge.validateToolCall(
  'lyrie-core',
  'exec',
  { command: 'ls -la' },
  { agentId: 'lyrie-core', callsThisTurn: 3, sessionId: 'abc123' }
);

if (!result.allowed) {
  console.error(`Blocked (${result.latencyMs.toFixed(2)}ms): ${result.reason}`);
  // Blocked (0.12ms): AGT ASI-04: tool "exec" requires human approval before execution
}
```

## ScopeDeclaration reference

```typescript
interface ScopeDeclaration {
  agentId: string;           // required — stable agent identifier
  description?: string;      // optional human label
  allowedTools?: string[];   // empty = wildcard (all non-denied tools allowed)
  deniedTools?: string[];    // merged with Lyrie's hardcoded deny list
  requireApproval?: string[]; // tools needing human gate before exec
  maxCallsPerTurn?: number;  // default 25
  controls?: Partial<AGTPolicy['controls']>; // override specific ASI controls
}
```

## Integration with ShieldManager

`AGTBridge` implements the `ShieldGuardLike` interface so it plugs directly
into `ShieldManager`:

```typescript
import { ShieldManager } from '@lyrie/core';
import { getAGTBridge } from '@lyrie/agt-bridge';

const shield = new ShieldManager();
await shield.initialize({ agtBridge: getAGTBridge() });
```

## lyrie governance agt

```bash
# Check AGT availability and coverage
lyrie governance agt status

# Print install guide
lyrie governance agt --install-guide

# Generate a policy YAML from a scope declaration file
lyrie governance agt generate-policy --scope scope.json --out policy.json
```

## Tests

```bash
bun test packages/agt-bridge
```

---

© OTT Cybersecurity LLC — https://lyrie.ai — MIT License
