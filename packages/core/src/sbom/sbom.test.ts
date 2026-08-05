/**
 * sbom.test.ts — living-SBOM generation, exploitability revalidation, delta
 * detection, and re-attestation (Feature 5). Threat intel is seeded directly
 * (offline client) so no network is touched.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { ThreatIntelClient } from "../pentest/threat-intel/client";
import type { ThreatAdvisory } from "../pentest/threat-intel/types";
import { generateSbom, SbomStore, toPurl, sha256 } from "./generate";
import { revalidateSbom, computeDeltas, reattest } from "./revalidate";
import { runScheduledRevalidation } from "./scheduler";
import type { SbomManifest, SbomExploitabilitySnapshot } from "./types";

const MANIFEST: SbomManifest = {
  name: "demo-app",
  components: [
    { name: "lodash", version: "4.17.20", ecosystem: "npm" },
    { name: "express", version: "4.18.2", ecosystem: "npm" },
  ],
};

function offlineClientWith(advisories: ThreatAdvisory[]): ThreatIntelClient {
  const c = new ThreatIntelClient({ offline: true });
  c.seed(advisories);
  return c;
}

const LODASH_CVE: ThreatAdvisory = {
  cve: "CVE-2021-23337",
  title: "lodash command injection",
  severity: "high",
  cvss: 7.2,
  product: "lodash",
  affectedRange: "<=4.17.20",
  patchedVersion: "4.17.21",
  kev: { inKev: false },
  sources: ["lyrie-research"],
  summary: "Command injection in lodash template.",
  url: "https://research.lyrie.ai/cves/CVE-2021-23337",
  updatedAt: new Date().toISOString(),
};

const LODASH_CRITICAL_KEV: ThreatAdvisory = {
  ...LODASH_CVE,
  cve: "CVE-2099-99999",
  severity: "critical",
  cvss: 9.8,
  kev: { inKev: true },
};

// ─── generation ─────────────────────────────────────────────────────────────

describe("generateSbom", () => {
  test("produces a CycloneDX-style artifact with purls", () => {
    const sbom = generateSbom(MANIFEST, { serialNumber: "urn:uuid:test", timestamp: "2026-01-01T00:00:00Z" });
    expect(sbom.bomFormat).toBe("CycloneDX");
    expect(sbom.specVersion).toBe("1.5");
    expect(sbom.serialNumber).toBe("urn:uuid:test");
    expect(sbom.components).toHaveLength(2);
    expect(sbom.components[0].purl).toBe("pkg:npm/lodash@4.17.20");
    expect(sbom.metadata.component?.name).toBe("demo-app");
  });

  test("toPurl handles ecosystems + missing version", () => {
    expect(toPurl({ name: "requests", version: "2.0.0", ecosystem: "pip" })).toBe("pkg:pypi/requests@2.0.0");
    expect(toPurl({ name: "serde", ecosystem: "cargo" })).toBe("pkg:cargo/serde");
  });

  test("sha256 is stable regardless of key order", () => {
    expect(sha256({ a: 1, b: 2 })).toBe(sha256({ b: 2, a: 1 }));
  });
});

// ─── revalidation ───────────────────────────────────────────────────────────

describe("revalidateSbom", () => {
  test("flags an exploitable component (lodash matches CVE) with score + maturity", async () => {
    const sbom = generateSbom(MANIFEST, { serialNumber: "urn:uuid:reval" });
    const client = offlineClientWith([LODASH_CVE]);
    const report = await revalidateSbom(sbom, client);

    const lodash = report.snapshot.components.find((c) => c.name === "lodash")!;
    const express = report.snapshot.components.find((c) => c.name === "express")!;
    expect(lodash.exploitable).toBe(true);
    expect(lodash.severity).toBe("high");
    expect(lodash.score).toBeGreaterThan(0);
    expect(lodash.cves).toContain("CVE-2021-23337");
    expect(express.exploitable).toBe(false);

    expect(report.summary.exploitable).toBe(1);
    expect(report.summary.highestSeverity).toBe("high");
    // First run: exploitable component reported as newly-exploitable.
    expect(report.deltas.some((d) => d.kind === "newly-exploitable" && d.name === "lodash")).toBe(true);
  });

  test("clean SBOM (no advisories) → nothing exploitable, no deltas", async () => {
    const sbom = generateSbom(MANIFEST, { serialNumber: "urn:uuid:clean" });
    const client = offlineClientWith([]);
    const report = await revalidateSbom(sbom, client);
    expect(report.summary.exploitable).toBe(0);
    expect(report.deltas).toHaveLength(0);
  });
});

// ─── delta detection ────────────────────────────────────────────────────────

describe("computeDeltas", () => {
  function snap(components: SbomExploitabilitySnapshot["components"]): SbomExploitabilitySnapshot {
    return { serialNumber: "urn:uuid:d", assessedAt: "t", components };
  }

  test("detects a component becoming newly exploitable across runs", () => {
    const prev = snap([{ bomRef: "npm:lodash@4.17.20#0", name: "lodash", version: "4.17.20", exploitable: false, severity: "none", score: 0, cves: [], inKev: false }]);
    const cur = snap([{ bomRef: "npm:lodash@4.17.20#0", name: "lodash", version: "4.17.20", exploitable: true, severity: "high", score: 70, cves: ["CVE-2021-23337"], inKev: false }]);
    const deltas = computeDeltas(prev, cur);
    expect(deltas).toHaveLength(1);
    expect(deltas[0].kind).toBe("newly-exploitable");
  });

  test("detects severity increase + decrease + removed", () => {
    const prev = snap([
      { bomRef: "a", name: "a", exploitable: true, severity: "low", score: 20, cves: ["X"], inKev: false },
      { bomRef: "b", name: "b", exploitable: true, severity: "critical", score: 95, cves: ["Y"], inKev: true },
      { bomRef: "gone", name: "gone", exploitable: false, severity: "none", score: 0, cves: [], inKev: false },
    ]);
    const cur = snap([
      { bomRef: "a", name: "a", exploitable: true, severity: "high", score: 70, cves: ["X"], inKev: false },
      { bomRef: "b", name: "b", exploitable: true, severity: "medium", score: 40, cves: ["Y"], inKev: false },
    ]);
    const kinds = computeDeltas(prev, cur).map((d) => d.kind).sort();
    expect(kinds).toEqual(["component-removed", "severity-decreased", "severity-increased"].sort());
  });
});

// ─── re-attestation ─────────────────────────────────────────────────────────

describe("reattest", () => {
  test("clean posture → verdict clean", () => {
    const snapshot: SbomExploitabilitySnapshot = {
      serialNumber: "urn:uuid:att",
      assessedAt: "t",
      components: [{ bomRef: "a", name: "a", exploitable: false, severity: "none", score: 0, cves: [], inKev: false }],
    };
    const att = reattest(snapshot, () => 0);
    expect(att.predicate.verdict).toBe("clean");
    expect(att.digest).toHaveLength(64);
  });

  test("KEV/critical exploitable → action-required", () => {
    const snapshot: SbomExploitabilitySnapshot = {
      serialNumber: "urn:uuid:att2",
      assessedAt: "t",
      components: [{ bomRef: "a", name: "a", exploitable: true, severity: "critical", score: 95, cves: ["Z"], inKev: true }],
    };
    expect(reattest(snapshot, () => 0).predicate.verdict).toBe("action-required");
  });

  test("non-KEV exploitable → action-recommended", () => {
    const snapshot: SbomExploitabilitySnapshot = {
      serialNumber: "urn:uuid:att3",
      assessedAt: "t",
      components: [{ bomRef: "a", name: "a", exploitable: true, severity: "medium", score: 40, cves: ["W"], inKev: false }],
    };
    expect(reattest(snapshot, () => 0).predicate.verdict).toBe("action-recommended");
  });
});

// ─── scheduler hook (living SBOM across runs) ────────────────────────────────

describe("runScheduledRevalidation — living SBOM", () => {
  test("first run reports newly-exploitable; second run (same intel) reports no new deltas", async () => {
    const store = new SbomStore();
    store.put(generateSbom(MANIFEST, { serialNumber: "urn:uuid:live" }));
    const client = offlineClientWith([LODASH_CVE]);

    const first = await runScheduledRevalidation(store, client, () => 1000);
    expect(first).toHaveLength(1);
    expect(first[0].report.deltas.some((d) => d.kind === "newly-exploitable")).toBe(true);
    expect(first[0].reattestation.predicate.exploitableComponents).toBe(1);

    // Second run with identical intel: baseline was persisted, so lodash is
    // still exploitable but no LONGER a *new* delta.
    const second = await runScheduledRevalidation(store, client, () => 2000);
    expect(second[0].report.summary.exploitable).toBe(1);
    expect(second[0].report.deltas.filter((d) => d.kind === "newly-exploitable")).toHaveLength(0);
  });

  test("intel worsening between runs surfaces a new severity delta", async () => {
    const store = new SbomStore();
    store.put(generateSbom(MANIFEST, { serialNumber: "urn:uuid:worsen" }));

    // Run 1: lodash high.
    const first = await runScheduledRevalidation(store, offlineClientWith([LODASH_CVE]), () => 1000);
    expect(first[0].report.summary.highestSeverity).toBe("high");

    // Run 2: a NEW critical KEV advisory also matches lodash.
    const second = await runScheduledRevalidation(store, offlineClientWith([LODASH_CVE, LODASH_CRITICAL_KEV]), () => 2000);
    expect(second[0].report.summary.highestSeverity).toBe("critical");
    expect(second[0].report.deltas.some((d) => d.kind === "severity-increased")).toBe(true);
    expect(second[0].reattestation.predicate.verdict).toBe("action-required");
  });
});
