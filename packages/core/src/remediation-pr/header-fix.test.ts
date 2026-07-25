/**
 * header-fix.test.ts
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { generateHeaderFix } from "./header-fix";
import type { MissingHeaderFinding } from "./types";

const finding: MissingHeaderFinding = {
  kind: "missing-security-header",
  header: "content-security-policy",
  recommendedValue: "default-src 'self'",
  configFile: "packages/ui/next.config.ts",
  configKind: "next-config",
};

describe("generateHeaderFix", () => {
  test("synthesises a fresh config when the file doesn't exist yet", () => {
    const result = generateHeaderFix(finding, undefined);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.diff.newContent).toContain("async headers()");
      expect(result.diff.newContent).toContain("Content-Security-Policy");
      expect(result.diff.newContent).toContain("default-src 'self'");
    }
  });

  test("inserts into an existing config that has no headers() yet", () => {
    const existing = `import type { NextConfig } from "next";\n\nconst nextConfig: NextConfig = {\n  reactStrictMode: true,\n};\n\nexport default nextConfig;\n`;
    const result = generateHeaderFix(finding, existing);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.diff.newContent).toContain("reactStrictMode: true");
      expect(result.diff.newContent).toContain("async headers()");
    }
  });

  test("produces syntactically valid TypeScript (balanced braces/parens)", () => {
    const result = generateHeaderFix(finding, undefined);
    expect(result.ok).toBe(true);
    if (result.ok) {
      const content = result.diff.newContent;
      const opens = (content.match(/\{/g) ?? []).length;
      const closes = (content.match(/\}/g) ?? []).length;
      expect(opens).toBe(closes);
      const parenOpens = (content.match(/\(/g) ?? []).length;
      const parenCloses = (content.match(/\)/g) ?? []).length;
      expect(parenOpens).toBe(parenCloses);
    }
  });

  test("skips (does not attempt) when a headers() function already exists", () => {
    const existing = `const nextConfig = {\n  async headers() {\n    return [];\n  },\n};\nexport default nextConfig;\n`;
    const result = generateHeaderFix(finding, existing);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("already defines a headers()");
    }
  });

  test("skips when the file doesn't match the expected Next.js config shape", () => {
    const weird = "export const somethingElse = 42;\n";
    const result = generateHeaderFix(finding, weird);
    expect(result.ok).toBe(false);
  });

  test("PR metadata includes branch name, title, and body", () => {
    const result = generateHeaderFix(finding, undefined);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.diff.branchName).toMatch(/^lyrie-auto-fix\//);
      expect(result.diff.prTitle).toContain("Content-Security-Policy");
      expect(result.diff.prBody).toContain("mechanical fix");
    }
  });
});
