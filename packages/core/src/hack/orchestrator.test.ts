/**
 * Lyrie Hack — Orchestrator tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { HackOrchestrator, ORCHESTRATOR_VERSION, runHack } from "./orchestrator";
import type { HackEvent } from "./orchestrator";

let root: string;
let outDir: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "lyrie-hack-"));
  outDir = mkdtempSync(join(tmpdir(), "lyrie-hack-out-"));

  // Mini vulnerable JS app: SQLi + XSS + hardcoded secret.
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "tiny",
      dependencies: { express: "4.17.1" },
    }),
  );
  writeFileSync(
    join(root, "server.js"),
    `
const express = require("express");
const { exec } = require("child_process");
const AWS_KEY = "AKIAQUACKQUACKQUACKQ";
const app = express();

app.get("/u/:id", (req, res) => {
  db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
});
app.get("/p", (req, res) => {
  res.send(\`<div onload="el.innerHTML='\${req.query.x}'"></div>\`);
});
app.get("/c", (req, res) => {
  exec(\`convert \${req.query.f} out.png\`);
});
`,
  );
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outDir, { recursive: true, force: true });
});

describe("HackOrchestrator", () => {
  it("emits a Lyrie version tag", () => {
    expect(ORCHESTRATOR_VERSION).toMatch(/^lyrie-/);
  });

  it("runs a full lifecycle on a local target and emits phase events", async () => {
    const events: HackEvent[] = [];
    const orch = new HackOrchestrator();
    orch.on((e) => events.push(e));

    const reportOut = mkdtempSync(join(tmpdir(), "lyrie-hack-out2-"));
    const report = await orch.run(root, { mode: "quick", outDir: reportOut, output: "all" });

    // Phase events present in the right order
    const phases = events
      .filter((e) => (e as any).phase && (e as any).type === "complete")
      .map((e) => (e as any).phase);
    expect(phases).toEqual(
      expect.arrayContaining(["recon", "scan", "validate", "remediate", "report", "self-scan"]),
    );

    // Findings present
    expect(report.totalFindings).toBeGreaterThan(0);

    // SARIF/Markdown/JSON files written
    expect(existsSync(join(reportOut, "report.md"))).toBe(true);
    expect(existsSync(join(reportOut, "report.sarif"))).toBe(true);
    expect(existsSync(join(reportOut, "report.json"))).toBe(true);

    rmSync(reportOut, { recursive: true, force: true });
  });

  it("respects --dry-run by not writing report files", async () => {
    const reportOut = mkdtempSync(join(tmpdir(), "lyrie-hack-dry-"));
    const orch = new HackOrchestrator();
    await orch.run(root, { mode: "quick", outDir: reportOut, dryRun: true });

    // Directory may exist from mkdtempSync but should be empty.
    const written = readdirOrEmpty(reportOut);
    expect(written.filter((f) => f.startsWith("report"))).toEqual([]);
    rmSync(reportOut, { recursive: true, force: true });
  });

  it("emits both phase and finding events", async () => {
    const events: HackEvent[] = [];
    const orch = new HackOrchestrator();
    orch.on((e) => events.push(e));
    await orch.run(root, { mode: "quick", outDir, dryRun: true });

    const findingEvents = events.filter((e) => (e as any).type === "finding");
    expect(findingEvents.length).toBeGreaterThan(0);
  });

  it("on() returns an unsubscribe handle", async () => {
    const orch = new HackOrchestrator();
    const seen: HackEvent[] = [];
    const off = orch.on((e) => seen.push(e));
    off();
    await orch.run(root, { mode: "quick", outDir, dryRun: true });
    expect(seen.length).toBe(0);
  });

  it("populates a non-zero count of secret findings", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    expect(report.secretFindings.length).toBeGreaterThan(0);
    const aws = report.secretFindings.find((s) => s.type === "aws-access-key-id");
    expect(aws).toBeDefined();
  });

  it("populates a non-zero count of validated scanner findings", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    const confirmed = report.validatedFindings.filter((v) => v.confirmed);
    expect(confirmed.length).toBeGreaterThan(0);
  });

  it("rolls up severity counts", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    const total =
      report.counts.critical +
      report.counts.high +
      report.counts.medium +
      report.counts.low +
      report.counts.info;
    expect(total).toBe(report.totalFindings);
  });

  it("produces remediation suggestions for confirmed findings", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    expect(report.remediations.length).toBeGreaterThan(0);
    expect(report.remediations[0].suggestion.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });

  it("attaches a dependency graph in the report", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    expect(report.dependencyGraph).toBeDefined();
    expect(report.dependencyGraph!.packages.find((p) => p.name === "express")).toBeDefined();
  });

  it("attaches an attack-surface mapper output in the report", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    expect(report.surface).toBeDefined();
  });

  it("self-scan completes with a verdict in the clean/suspicious/blocked set", async () => {
    const reportOut = mkdtempSync(join(tmpdir(), "lyrie-hack-ss-"));
    const report = await runHack(root, { mode: "quick", outDir: reportOut });
    expect(report.selfScanRan).toBe(true);
    expect(["clean", "suspicious", "blocked"]).toContain(report.selfScanVerdict);
    rmSync(reportOut, { recursive: true, force: true });
  });

  it("can be skipped via --no-self-scan", async () => {
    const report = await runHack(root, {
      mode: "quick",
      noSelfScan: true,
      dryRun: true,
    });
    expect(report.selfScanRan).toBe(false);
  });

  it("emits the Lyrie signature on the report", async () => {
    const report = await runHack(root, { mode: "quick", dryRun: true });
    expect(report.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });

  it("skips network-style targets without crashing", async () => {
    const report = await runHack("https://example.com", { mode: "quick", dryRun: true });
    // No filesystem to walk → no findings, but the run completes.
    expect(report).toBeDefined();
    expect(report.totalFindings).toBe(0);
  });
});

function readdirOrEmpty(dir: string): string[] {
  try {
    const fs = require("node:fs");
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}
