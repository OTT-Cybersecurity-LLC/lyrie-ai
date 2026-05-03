/**
 * Lyrie Hack — integration test against the bundled vulnerable-app fixture.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runHack } from "../../packages/core/src/hack";

const FIXTURE = join(__dirname, "fixtures", "vulnerable-app");

const reportOut = mkdtempSync(join(tmpdir(), "lyrie-hack-int-"));

afterAll(() => {
  rmSync(reportOut, { recursive: true, force: true });
});

describe("lyrie hack ./tests/hack/fixtures/vulnerable-app/", () => {
  it("reports at least 3 findings and a hardcoded secret", async () => {
    const report = await runHack(FIXTURE, {
      mode: "standard",
      outDir: reportOut,
      noSelfScan: true,
    });
    expect(report.totalFindings).toBeGreaterThanOrEqual(3);
    const aws = report.secretFindings.find((s) => s.type === "aws-access-key-id");
    expect(aws).toBeDefined();
  });

  it("attaches CWE-shaped categories on at least one validated finding", async () => {
    const report = await runHack(FIXTURE, {
      mode: "standard",
      outDir: reportOut,
      noSelfScan: true,
    });
    const cwes = report.validatedFindings
      .filter((v) => v.confirmed)
      .map((v) => v.finding.cwe)
      .filter(Boolean);
    expect(cwes.length).toBeGreaterThan(0);
  });

  it("emits a Lyrie-signed JSON report", async () => {
    const report = await runHack(FIXTURE, {
      mode: "standard",
      outDir: reportOut,
      noSelfScan: true,
    });
    expect(report.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });

  it("includes a dependency graph entry for express", async () => {
    const report = await runHack(FIXTURE, {
      mode: "standard",
      outDir: reportOut,
      noSelfScan: true,
    });
    const express = report.dependencyGraph?.packages.find((p) => p.name === "express");
    expect(express).toBeDefined();
    expect(express?.version).toBe("4.17.1");
  });

  it("produces at least one remediation suggestion", async () => {
    const report = await runHack(FIXTURE, {
      mode: "standard",
      outDir: reportOut,
      noSelfScan: true,
    });
    expect(report.remediations.length).toBeGreaterThan(0);
  });
});
