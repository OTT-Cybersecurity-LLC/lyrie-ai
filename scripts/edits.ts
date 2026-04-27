#!/usr/bin/env bun
/**
 * lyrie edits — operator CLI for diff-view file edits.
 *
 * Usage:
 *   bun run scripts/edits.ts list
 *   bun run scripts/edits.ts review <planId>
 *   bun run scripts/edits.ts approve <planId>
 *   bun run scripts/edits.ts log
 *
 * Operates on the same JSON ledger the agent uses (~/.lyrie/edits.json).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { EditEngine } from "../packages/core/src/edits/edit-engine";

const args = process.argv.slice(2);
const cmd = args[0];

const eng = new EditEngine({ defaultMode: "require-approval" });

function usage(): never {
  console.error("Usage:");
  console.error("  lyrie edits list");
  console.error("  lyrie edits review  <planId>");
  console.error("  lyrie edits approve <planId>");
  console.error("  lyrie edits log");
  process.exit(2);
}

switch (cmd) {
  case "list": {
    const pending = eng.pending();
    if (pending.length === 0) {
      console.log("No pending edits.");
      break;
    }
    for (const p of pending) {
      const flags: string[] = [];
      if (p.shielded) flags.push("🛡️ shielded");
      if (!p.applicable) flags.push("⚠️ not applicable");
      console.log(
        `${p.id.slice(0, 8)}…  ${p.path}  ${p.editCount} edit(s)  ${flags.join(" ")}  ${p.description ?? ""}`,
      );
    }
    break;
  }
  case "review": {
    const id = args[1];
    if (!id) usage();
    const plan = eng.pending().find((p) => p.id === id || p.id.startsWith(id));
    if (!plan) {
      console.error(`✗ No pending plan with id ${id}`);
      process.exit(1);
    }
    console.log(`Plan ${plan.id}`);
    console.log(`File: ${plan.path}`);
    console.log(`Mode: ${plan.mode}`);
    if (plan.description) console.log(`Description: ${plan.description}`);
    if (plan.shielded) console.log(`🛡️  Shield: ${plan.shieldReason ?? "blocked"}`);
    console.log("");
    console.log(plan.unifiedDiff || "(no diff)");
    console.log("");
    console.log(`To apply: lyrie edits approve ${plan.id}`);
    break;
  }
  case "approve": {
    const id = args[1];
    if (!id) usage();
    const plan = eng.pending().find((p) => p.id === id || p.id.startsWith(id));
    if (!plan) {
      console.error(`✗ No pending plan with id ${id}`);
      process.exit(1);
    }
    const applied = eng.approve(plan.id);
    if (!applied) {
      console.error("✗ Apply failed (file drifted, Shield blocked, or dry-run).");
      process.exit(1);
    }
    console.log(`✅ Applied ${plan.path} (${applied.bytesBefore} → ${applied.bytesAfter} bytes)`);
    break;
  }
  case "log": {
    const log = eng.applied();
    if (log.length === 0) {
      console.log("No applied edits.");
      break;
    }
    for (const a of log) {
      console.log(
        `${a.appliedAt}  ${a.id.slice(0, 8)}…  ${a.path}  ${a.bytesBefore}→${a.bytesAfter} bytes  ${a.description ?? ""}`,
      );
    }
    break;
  }
  default:
    usage();
}
