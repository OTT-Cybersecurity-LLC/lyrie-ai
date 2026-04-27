#!/usr/bin/env bun
/**
 * `lyrie intel` — operator CLI for the Lyrie Threat-Intel feed.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run scripts/intel.ts list                    # list cached advisories
 *   bun run scripts/intel.ts refresh                 # force-refresh from research.lyrie.ai
 *   bun run scripts/intel.ts lookup <CVE>            # look up a single CVE
 *   bun run scripts/intel.ts scan-deps               # match against current package.json
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { ThreatIntelClient, type ThreatAdvisory } from "../packages/core/src/pentest/threat-intel";
import type { DependencyEntry } from "../packages/core/src/pentest/attack-surface";

const cmd = process.argv[2];

const client = new ThreatIntelClient({
  offline: process.env.LYRIE_INTEL_OFFLINE === "1",
});

function header() {
  console.log("");
  console.log("🛡️  Lyrie Threat-Intel  ·  Lyrie.ai by OTT Cybersecurity LLC");
  console.log("─────────────────────────────────────────────────────────────────");
}

async function listAdvisories() {
  header();
  const ads = await client.getAdvisories();
  if (ads.length === 0) {
    console.log("  (no advisories — feed unreachable or empty)");
    console.log("");
    return;
  }
  console.log(`  ${ads.length} advisor${ads.length === 1 ? "y" : "ies"} cached from research.lyrie.ai`);
  console.log("");
  for (const a of ads.slice(0, 25)) {
    console.log(formatAdvisory(a));
  }
  console.log("");
}

async function lookupCve(cve: string) {
  header();
  const ads = await client.getAdvisories();
  const match = ads.find((a) => a.cve.toLowerCase() === cve.toLowerCase());
  if (!match) {
    console.error(`✗ ${cve} not found in the Lyrie Threat-Intel feed.`);
    process.exit(1);
  }
  console.log(formatAdvisory(match, true));
  console.log("");
}

async function scanDeps() {
  header();
  const pkgPath = join(process.cwd(), "package.json");
  if (!existsSync(pkgPath)) {
    console.error("✗ No package.json found in current directory.");
    process.exit(1);
  }
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  const deps: DependencyEntry[] = [];
  for (const section of ["dependencies", "devDependencies", "peerDependencies"]) {
    const s = (pkg[section] ?? {}) as Record<string, string>;
    for (const [name, version] of Object.entries(s)) {
      deps.push({ name, version, manifest: "package.json", ecosystem: "npm" });
    }
  }
  console.log(`  scanning ${deps.length} npm dependenc${deps.length === 1 ? "y" : "ies"}…`);
  console.log("");

  const matches = await client.matchDependencies(deps);
  if (matches.length === 0) {
    console.log("✅  No advisories match your dependency tree.");
    console.log("");
    return;
  }
  console.log(`⚠️  ${matches.length} advisory match${matches.length === 1 ? "" : "es"}`);
  console.log("");
  for (const m of matches) {
    console.log(`  ${m.matchedOn}`);
    console.log("  " + formatAdvisory(m.advisory).split("\n").join("\n  "));
    console.log("");
  }
}

function formatAdvisory(a: ThreatAdvisory, full = false): string {
  const kev = a.kev.inKev ? " 🚨 CISA KEV" : "";
  const cvss = a.cvss ? `  CVSS ${a.cvss}` : "";
  const lines = [
    `  ${a.cve}  [${a.severity.toUpperCase()}]${cvss}${kev}`,
    `    ${a.title}`,
    `    ${a.url}`,
  ];
  if (full) {
    if (a.product) lines.push(`    product:   ${a.product}${a.affectedRange ? ` ${a.affectedRange}` : ""}`);
    if (a.patchedVersion) lines.push(`    patched:   ${a.patchedVersion}`);
    if (a.summary) lines.push(`    summary:   ${a.summary}`);
    if (a.verdict) lines.push(`    verdict:   ${a.verdict}`);
    if (a.kev.inKev && a.kev.dateAdded) lines.push(`    KEV since: ${a.kev.dateAdded}`);
    if (a.kev.dueDate) lines.push(`    KEV due:   ${a.kev.dueDate}`);
  }
  return lines.join("\n");
}

switch (cmd) {
  case "list":
    await listAdvisories();
    break;
  case "refresh":
    header();
    await client.refresh();
    console.log("  refreshed.");
    console.log("");
    break;
  case "lookup": {
    const cve = process.argv[3];
    if (!cve) {
      console.error("Usage: lyrie intel lookup <CVE>");
      process.exit(2);
    }
    await lookupCve(cve);
    break;
  }
  case "scan-deps":
    await scanDeps();
    break;
  default:
    console.error("Usage:");
    console.error("  lyrie intel list");
    console.error("  lyrie intel refresh");
    console.error("  lyrie intel lookup <CVE>");
    console.error("  lyrie intel scan-deps");
    process.exit(2);
}
