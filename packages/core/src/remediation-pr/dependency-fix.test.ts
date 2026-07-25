/**
 * dependency-fix.test.ts
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { generateDependencyFix } from "./dependency-fix";
import type { DependencyFixFinding } from "./types";

const manifest = JSON.stringify(
  {
    name: "fixture-app",
    version: "1.0.0",
    dependencies: {
      lodash: "^4.17.20",
      express: "4.18.0",
    },
    devDependencies: {
      typescript: "^5.0.0",
    },
  },
  null,
  2,
);

const finding: DependencyFixFinding = {
  kind: "pinned-dependency-fix-available",
  packageName: "lodash",
  currentVersion: "4.17.20",
  fixedVersion: "4.17.21",
  manifestFile: "package.json",
  cve: "CVE-2021-23337",
};

describe("generateDependencyFix", () => {
  test("bumps the version preserving the range operator", () => {
    const result = generateDependencyFix(finding, manifest);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.diff.newContent).toContain('"lodash": "^4.17.21"');
      expect(result.diff.newContent).not.toContain('"lodash": "^4.17.20"');
    }
  });

  test("preserves an exact-pin (no operator) format", () => {
    const exactFinding: DependencyFixFinding = {
      ...finding,
      packageName: "express",
      currentVersion: "4.18.0",
      fixedVersion: "4.18.2",
    };
    const result = generateDependencyFix(exactFinding, manifest);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.diff.newContent).toContain('"express": "4.18.2"');
    }
  });

  test("result is valid JSON after the fix", () => {
    const result = generateDependencyFix(finding, manifest);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(() => JSON.parse(result.diff.newContent)).not.toThrow();
      const parsed = JSON.parse(result.diff.newContent);
      expect(parsed.dependencies.lodash).toBe("^4.17.21");
      // unrelated fields untouched
      expect(parsed.dependencies.express).toBe("4.18.0");
      expect(parsed.devDependencies.typescript).toBe("^5.0.0");
    }
  });

  test("refuses when package is not found in the manifest", () => {
    const missing: DependencyFixFinding = { ...finding, packageName: "not-a-real-package" };
    const result = generateDependencyFix(missing, manifest);
    expect(result.ok).toBe(false);
  });

  test("refuses when manifest is not valid JSON", () => {
    const result = generateDependencyFix(finding, "{ not json");
    expect(result.ok).toBe(false);
  });

  test("refuses when the manifest's current version does not match the finding's expectation", () => {
    const staleFinding: DependencyFixFinding = { ...finding, currentVersion: "4.10.0" };
    const result = generateDependencyFix(staleFinding, manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("refusing to guess");
    }
  });

  test("PR metadata references the CVE when provided", () => {
    const result = generateDependencyFix(finding, manifest);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.diff.prTitle).toContain("CVE-2021-23337");
      expect(result.diff.branchName).toMatch(/^lyrie-auto-fix\/bump-lodash/);
    }
  });
});
