/**
 * Lyrie Hack — Reachability Analysis tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { extractDependencyGraph } from "./dependency-graph";
import {
  REACHABILITY_VERSION,
  analyzeReachability,
  isVersionInRange,
  type VulnerablePackageEntry,
} from "./reachability";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "lyrie-reachability-"));

  // npm manifest: lodash is directly imported; left-pad is present but never
  // imported anywhere (dead weight); minimist only shows up as a transitive
  // dependency in the lockfile.
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({
      name: "demo",
      dependencies: {
        lodash: "4.17.20",
        "left-pad": "1.3.0",
        express: "4.17.1",
      },
    }),
  );

  writeFileSync(
    join(root, "package-lock.json"),
    JSON.stringify({
      packages: {
        "": { name: "demo" },
        "node_modules/lodash": { version: "4.17.20" },
        "node_modules/left-pad": { version: "1.3.0" },
        "node_modules/express": { version: "4.17.1" },
        "node_modules/minimist": { version: "1.2.5" },
      },
    }),
  );

  mkdirSync(join(root, "src"));
  writeFileSync(
    join(root, "src", "index.js"),
    `const _ = require("lodash");\nconst express = require("express");\n\nfunction run() {\n  return _.chunk([1,2,3], 2);\n}\n\nmodule.exports = { run, express };\n`,
  );

  // Python manifest: flask directly imported via "from flask import Flask";
  // requests present in requirements.txt but never imported (dead).
  writeFileSync(join(root, "requirements.txt"), "flask==2.0.0\nrequests==2.25.0\n");
  writeFileSync(
    join(root, "app.py"),
    `from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.route("/")\ndef index():\n    return "ok"\n`,
  );
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("REACHABILITY_VERSION", () => {
  it("is a lyrie-prefixed version tag", () => {
    expect(REACHABILITY_VERSION).toMatch(/^lyrie-/);
  });
});

describe("isVersionInRange", () => {
  it("matches exact version", () => {
    expect(isVersionInRange("1.2.3", "1.2.3")).toBe(true);
    expect(isVersionInRange("1.2.4", "1.2.3")).toBe(false);
  });

  it("matches single comparators", () => {
    expect(isVersionInRange("1.5.0", ">=1.0.0")).toBe(true);
    expect(isVersionInRange("0.9.0", ">=1.0.0")).toBe(false);
    expect(isVersionInRange("1.9.0", "<2.0.0")).toBe(true);
    expect(isVersionInRange("2.0.0", "<2.0.0")).toBe(false);
    expect(isVersionInRange("2.0.0", "<=2.0.0")).toBe(true);
    expect(isVersionInRange("2.0.1", ">2.0.0")).toBe(true);
  });

  it("matches two-clause AND ranges", () => {
    expect(isVersionInRange("1.5.0", ">=1.0.0 <2.0.0")).toBe(true);
    expect(isVersionInRange("0.5.0", ">=1.0.0 <2.0.0")).toBe(false);
    expect(isVersionInRange("2.0.0", ">=1.0.0 <2.0.0")).toBe(false);
  });

  it("matches dash (inclusive) ranges", () => {
    expect(isVersionInRange("1.5.0", "1.0.0 - 2.0.0")).toBe(true);
    expect(isVersionInRange("2.0.0", "1.0.0 - 2.0.0")).toBe(true);
    expect(isVersionInRange("2.0.1", "1.0.0 - 2.0.0")).toBe(false);
  });

  it("matches caret ranges (same major)", () => {
    expect(isVersionInRange("1.2.3", "^1.2.3")).toBe(true);
    expect(isVersionInRange("1.9.9", "^1.2.3")).toBe(true);
    expect(isVersionInRange("2.0.0", "^1.2.3")).toBe(false);
    expect(isVersionInRange("1.2.2", "^1.2.3")).toBe(false);
  });

  it("matches tilde ranges (same major.minor)", () => {
    expect(isVersionInRange("1.2.5", "~1.2.3")).toBe(true);
    expect(isVersionInRange("1.3.0", "~1.2.3")).toBe(false);
    expect(isVersionInRange("1.2.2", "~1.2.3")).toBe(false);
  });

  it("wildcard/empty range always matches", () => {
    expect(isVersionInRange("9.9.9", "*")).toBe(true);
    expect(isVersionInRange("9.9.9", "")).toBe(true);
  });
});

describe("analyzeReachability", () => {
  it("marks a directly-imported vulnerable package as reachable with high confidence", () => {
    const graph = extractDependencyGraph({ root });
    const vulnPackages: VulnerablePackageEntry[] = [
      {
        name: "lodash",
        ecosystem: "npm",
        vulnerableVersionRange: "<4.17.21",
        cve: "CVE-2021-23337",
        severity: "high",
      },
    ];

    const results = analyzeReachability(graph, vulnPackages, root);
    const lodash = results.find((r) => r.packageName === "lodash");
    expect(lodash).toBeDefined();
    expect(lodash!.reachable).toBe(true);
    expect(lodash!.confidence).toBe("high");
    expect(lodash!.reachedFrom.length).toBeGreaterThan(0);
    expect(lodash!.reachedFrom[0]).toContain("index.js");
    expect(lodash!.cve).toBe("CVE-2021-23337");
  });

  it("marks a manifest-only package with zero import evidence as low-confidence dead weight", () => {
    const graph = extractDependencyGraph({ root });
    const vulnPackages: VulnerablePackageEntry[] = [
      {
        name: "left-pad",
        ecosystem: "npm",
        vulnerableVersionRange: "*",
        cve: "CVE-9999-00001",
        severity: "medium",
      },
    ];

    const results = analyzeReachability(graph, vulnPackages, root);
    const leftPad = results.find((r) => r.packageName === "left-pad");
    expect(leftPad).toBeDefined();
    expect(leftPad!.reachable).toBe(false);
    expect(leftPad!.confidence).toBe("low");
    expect(leftPad!.reachedFrom).toEqual([]);
  });

  it("marks a transitive-only package (lockfile, no direct import) as medium confidence when other direct npm imports are reachable", () => {
    const graph = extractDependencyGraph({ root });
    const vulnPackages: VulnerablePackageEntry[] = [
      {
        name: "minimist",
        ecosystem: "npm",
        vulnerableVersionRange: "<1.2.6",
        cve: "CVE-2021-44906",
        severity: "critical",
      },
    ];

    const results = analyzeReachability(graph, vulnPackages, root);
    const minimist = results.find((r) => r.packageName === "minimist");
    expect(minimist).toBeDefined();
    expect(minimist!.reachable).toBe(false);
    expect(minimist!.confidence).toBe("medium");
  });

  it("filters out matches whose installed version is outside the vulnerable range", () => {
    const graph = extractDependencyGraph({ root });
    const vulnPackages: VulnerablePackageEntry[] = [
      {
        // express is 4.17.1 in the fixture — outside this fixed range.
        name: "express",
        ecosystem: "npm",
        vulnerableVersionRange: ">=5.0.0",
        cve: "CVE-0000-00000",
        severity: "low",
      },
    ];

    const results = analyzeReachability(graph, vulnPackages, root);
    expect(results.find((r) => r.packageName === "express")).toBeUndefined();
  });

  it("handles the Python ecosystem: direct 'from x import y' vs never-imported package", () => {
    const graph = extractDependencyGraph({ root });
    const vulnPackages: VulnerablePackageEntry[] = [
      {
        name: "flask",
        ecosystem: "pip",
        vulnerableVersionRange: "<2.1.0",
        cve: "CVE-2023-30861",
        severity: "high",
      },
      {
        name: "requests",
        ecosystem: "pip",
        vulnerableVersionRange: "*",
        cve: "CVE-9999-00002",
        severity: "medium",
      },
    ];

    const results = analyzeReachability(graph, vulnPackages, root);

    const flask = results.find((r) => r.packageName === "flask");
    expect(flask).toBeDefined();
    expect(flask!.reachable).toBe(true);
    expect(flask!.confidence).toBe("high");
    expect(flask!.reachedFrom.some((f) => f.includes("app.py"))).toBe(true);

    const requests = results.find((r) => r.packageName === "requests");
    expect(requests).toBeDefined();
    expect(requests!.reachable).toBe(false);
    expect(requests!.confidence).toBe("low");
  });

  it("returns no results when no vulnerable packages are supplied", () => {
    const graph = extractDependencyGraph({ root });
    expect(analyzeReachability(graph, [], root)).toEqual([]);
  });

  it("returns no results when the vulnerable package isn't present in the graph at all", () => {
    const graph = extractDependencyGraph({ root });
    const vulnPackages: VulnerablePackageEntry[] = [
      {
        name: "totally-unrelated-package",
        ecosystem: "npm",
        vulnerableVersionRange: "*",
        cve: "CVE-0000-00001",
        severity: "info",
      },
    ];
    expect(analyzeReachability(graph, vulnPackages, root)).toEqual([]);
  });
});
