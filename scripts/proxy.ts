#!/usr/bin/env bun
/**
 * `lyrie proxy` — operator CLI for the Lyrie HTTP Proxy.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run scripts/proxy.ts send <METHOD> <URL>       # capture a single exchange
 *   bun run scripts/proxy.ts scan <URL>                # send GET, classify, dump signals
 *   bun run scripts/proxy.ts headers <URL>             # security-header audit only
 *
 * Operates entirely in-memory; nothing persisted to disk.
 */

import { LyrieHttpProxy } from "../packages/core/src/pentest/proxy";

const cmd = process.argv[2];
const arg1 = process.argv[3];
const arg2 = process.argv[4];

function header() {
  console.log("");
  console.log("🛡️  Lyrie HTTP Proxy  ·  Lyrie.ai by OTT Cybersecurity LLC");
  console.log("─────────────────────────────────────────────────────────────────");
}

function fmtSignal(s: { severity: string; description: string; evidence?: string }) {
  const badge = ({
    critical: "🟥",
    high: "🟧",
    medium: "🟨",
    low: "🟩",
    info: "⬜",
  } as Record<string, string>)[s.severity] ?? "⬜";
  let line = `  ${badge} [${s.severity.toUpperCase().padEnd(8)}] ${s.description}`;
  if (s.evidence) line += `\n              evidence: ${s.evidence.slice(0, 120)}`;
  return line;
}

async function send(method: string, url: string) {
  if (!url) {
    console.error("Usage: lyrie proxy send <METHOD> <URL>");
    process.exit(2);
  }
  const proxy = new LyrieHttpProxy();
  const ex = await proxy.send(method.toUpperCase() as any, url);

  header();
  console.log(`  ${ex.request.method} ${ex.request.url}`);
  console.log(`  surface:    ${ex.request.surface ?? "unknown"}`);
  console.log(`  status:     ${ex.response?.status ?? "—"}`);
  console.log(`  duration:   ${ex.response?.durationMs ?? "—"}ms`);
  if (ex.response?.shielded) {
    console.log(`  🛡️  Shield: redacted response body (${ex.response.shieldReason ?? "unsafe"})`);
  }
  console.log("");
  if (ex.signals && ex.signals.length > 0) {
    console.log("📡 Lyrie security signals");
    for (const s of ex.signals) console.log(fmtSignal(s));
    console.log("");
  } else {
    console.log("✅  No security signals raised.");
    console.log("");
  }
}

async function scan(url: string) {
  await send("GET", url);
}

async function headers(url: string) {
  await send("GET", url);
}

switch (cmd) {
  case "send":
    await send(arg1, arg2);
    break;
  case "scan":
    await scan(arg1);
    break;
  case "headers":
    await headers(arg1);
    break;
  default:
    console.error("Usage:");
    console.error("  lyrie proxy send <METHOD> <URL>");
    console.error("  lyrie proxy scan <URL>");
    console.error("  lyrie proxy headers <URL>");
    process.exit(2);
}
