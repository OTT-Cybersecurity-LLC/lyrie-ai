/**
 * @lyrie/agt-bridge — CLI handler for `lyrie governance agt`
 *
 * Subcommands:
 *   lyrie governance agt status             — show AGT availability + coverage
 *   lyrie governance agt --install-guide    — print installation instructions
 *   lyrie governance agt generate-policy    — translate scope.json → AGT policy
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { writeFileSync, readFileSync } from "node:fs";
import { AGTBridge } from "./bridge";
import { PolicyGenerator } from "./policy";
import type { ScopeDeclaration } from "./types";

export async function runAGTCLI(args: string[]): Promise<void> {
  const subCmd = args[0];

  if (!subCmd || subCmd === "status") {
    return cmdStatus();
  }

  if (args.includes("--install-guide")) {
    return cmdInstallGuide();
  }

  if (subCmd === "generate-policy") {
    return cmdGeneratePolicy(args.slice(1));
  }

  console.error(`Unknown agt subcommand: ${subCmd}`);
  console.error("Usage: lyrie governance agt [status|generate-policy|--install-guide]");
  process.exit(1);
}

// ─── status ──────────────────────────────────────────────────────────────────

function cmdStatus(): void {
  const bridge = new AGTBridge();
  const info = bridge.getAvailabilityInfo();
  const score = bridge.coverageScore();

  console.log("\n🛡️  Lyrie AGT Bridge — Status");
  console.log("─────────────────────────────────────────────");

  if (info.available) {
    console.log(`✅ AGT:      ${info.version ?? "installed"} at ${info.binaryPath}`);
  } else {
    console.log(`❌ AGT:      Not installed (standalone mode)`);
  }

  console.log(
    `📊 Coverage: ${score.owasp_asi_controls}/10 OWASP ASI 2026 controls (${score.percentage}%)`
  );
  console.log("");

  console.log("OWASP ASI 2026 control status:");
  const controls = [
    ["ASI-01", "Prompt Injection", true],
    ["ASI-02", "Resource Overuse", true],
    ["ASI-03", "Tool Misuse", true],
    ["ASI-04", "Excessive Agency", true],
    ["ASI-05", "Sensitive Data Exposure", true],
    ["ASI-06", "Memory Poisoning", info.available],
    ["ASI-07", "Uncontrolled Sub-Agents", true],
    ["ASI-08", "Trust Boundary Violation", info.available],
    ["ASI-09", "Unverified Outputs", info.available],
    ["ASI-10", "Audit Evasion", true],
  ] as const;

  for (const [id, name, active] of controls) {
    const icon = active ? "✅" : "⚠️ ";
    const mode = active
      ? info.available
        ? "(AGT + Lyrie)"
        : "(Lyrie native)"
      : "(AGT required)";
    console.log(`  ${icon} ${id}: ${name} ${mode}`);
  }

  if (!info.available) {
    console.log("\n💡 Run `lyrie governance agt --install-guide` for install instructions.");
  }

  console.log("");
}

// ─── install guide ────────────────────────────────────────────────────────────

function cmdInstallGuide(): void {
  console.log(`
🛡️  Microsoft Agent Governance Toolkit — Install Guide
═══════════════════════════════════════════════════════

The AGT binary provides deterministic enforcement of all 10 OWASP ASI 2026
controls. Without it, Lyrie operates at 7/10 coverage.

Option 1 — npm (recommended):
  npm install -g @microsoft/agent-governance-toolkit
  agt version  # verify install

Option 2 — GitHub Releases:
  https://github.com/microsoft/agent-governance-toolkit/releases

Option 3 — Build from source:
  git clone https://github.com/microsoft/agent-governance-toolkit
  cd agent-governance-toolkit && npm ci && npm run build
  npm link

After install, restart Lyrie — it will auto-detect the AGT binary at startup.

Coverage comparison:
  With AGT:    10/10 OWASP ASI 2026 (deterministic, sub-ms enforcement)
  Without AGT:  7/10 (Lyrie ShieldGuard native mode, regex + heuristic)
`);
}

// ─── generate-policy ─────────────────────────────────────────────────────────

function cmdGeneratePolicy(args: string[]): void {
  function getFlag(flag: string): string | undefined {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
  }

  const scopePath = getFlag("--scope");
  const outPath = getFlag("--out");

  if (!scopePath) {
    console.error("Usage: lyrie governance agt generate-policy --scope <scope.json> [--out policy.json]");
    process.exit(1);
  }

  let scope: ScopeDeclaration;
  try {
    const raw = readFileSync(scopePath, "utf8");
    scope = JSON.parse(raw) as ScopeDeclaration;
  } catch (err: any) {
    console.error(`Failed to read scope file: ${err.message}`);
    process.exit(1);
  }

  const gen = new PolicyGenerator();
  const policy = gen.generate(scope);
  const serialized = gen.serialize(policy);

  if (outPath) {
    writeFileSync(outPath, serialized, "utf8");
    console.log(`✅ Policy written to ${outPath}`);
    console.log(`   Agent: ${policy.agent.id}`);
    console.log(`   Controls: 10/10 OWASP ASI 2026`);
    console.log(`   Max calls/turn: ${policy.agent.maxCallsPerTurn}`);
    console.log(`   Denied tools: ${policy.agent.deniedTools.length}`);
    console.log(`   Requires approval: ${policy.agent.requireHumanApproval.length} tools`);
  } else {
    console.log(serialized);
  }
}
