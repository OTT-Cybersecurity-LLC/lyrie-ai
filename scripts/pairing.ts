#!/usr/bin/env bun
/**
 * lyrie pairing — operator CLI for DM pairing approvals
 *
 * Usage:
 *   bun run scripts/pairing.ts list
 *   bun run scripts/pairing.ts approve <channel> <code>
 *   bun run scripts/pairing.ts revoke  <channel> <senderId>
 *
 * Operates on the same JSON store the gateway uses (~/.lyrie/pairing.json).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { DmPairingManager } from "../packages/gateway/src/security/dm-pairing";

const args = process.argv.slice(2);
const cmd = args[0];

const m = new DmPairingManager();

function usage(): never {
  console.error("Usage:");
  console.error("  lyrie pairing list");
  console.error("  lyrie pairing approve <channel> <code>");
  console.error("  lyrie pairing revoke  <channel> <senderId>");
  process.exit(2);
}

switch (cmd) {
  case "list": {
    const store = m.list();
    console.log("\nPending:");
    if (store.pending.length === 0) console.log("  (none)");
    for (const p of store.pending) {
      console.log(
        `  - ${p.channel}  ${p.senderId} (${p.senderName ?? "unknown"})  code=${p.code}  requested=${p.requestedAt}`,
      );
    }
    console.log("\nApproved:");
    if (store.approved.length === 0) console.log("  (none)");
    for (const a of store.approved) {
      console.log(
        `  - ${a.channel}  ${a.senderId} (${a.senderName ?? "unknown"})  approved=${a.approvedAt}`,
      );
    }
    console.log("");
    break;
  }
  case "approve": {
    const channel = args[1] as any;
    const code = args[2];
    if (!channel || !code) usage();
    const r = m.approve(channel, code);
    if (!r) {
      console.error(`✗ No pending pairing for channel=${channel} code=${code}`);
      process.exit(1);
    }
    console.log(`✅ Approved ${channel} ${r.senderId} (${r.senderName ?? "unknown"})`);
    break;
  }
  case "revoke": {
    const channel = args[1] as any;
    const senderId = args[2];
    if (!channel || !senderId) usage();
    const ok = m.revoke(channel, senderId);
    if (!ok) {
      console.error(`✗ No approved pairing for channel=${channel} sender=${senderId}`);
      process.exit(1);
    }
    console.log(`✅ Revoked ${channel} ${senderId}`);
    break;
  }
  default:
    usage();
}
