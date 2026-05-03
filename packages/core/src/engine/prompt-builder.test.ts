/**
 * PromptBuilder static/dynamic boundary tests.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  PromptBuilder,
  LYRIE_PROMPT_CACHE_BOUNDARY,
  LYRIE_ANTI_FALSE_CLAIMS_RULE,
} from "./prompt-builder";

describe("PromptBuilder static/dynamic boundary", () => {
  const pb = new PromptBuilder();

  test("static section ends with cache boundary marker", () => {
    const s = pb.buildStaticSection();
    expect(s.includes(LYRIE_PROMPT_CACHE_BOUNDARY)).toBe(true);
    // boundary should be near the end (last non-empty line)
    const lines = s.trim().split("\n");
    expect(lines[lines.length - 1]).toBe(LYRIE_PROMPT_CACHE_BOUNDARY);
  });

  test("static section is identical across two builds (cache-safe)", () => {
    const a = pb.buildStaticSection();
    const b = pb.buildStaticSection();
    expect(a).toBe(b);
  });

  test("dynamic section CHANGES across sessions (cwd, date)", async () => {
    const a = pb.buildDynamicSection({ cwd: "/projects/a" });
    await new Promise((r) => setTimeout(r, 5));
    const b = pb.buildDynamicSection({ cwd: "/projects/b" });
    expect(a).not.toBe(b);
    expect(a).toContain("/projects/a");
    expect(b).toContain("/projects/b");
  });

  test("anti-false-claims rule is always present in static section", () => {
    const s = pb.buildStaticSection();
    expect(s).toContain("Report Outcomes Faithfully");
    // Must include the anti-rationalization paragraph
    expect(s).toContain("incomplete or broken work as done");
  });

  test("splitForCache returns the two halves separately", () => {
    const full = pb.build({ cwd: "/x" });
    const { staticPart, dynamicPart } = pb.splitForCache(full);
    expect(staticPart.length).toBeGreaterThan(0);
    expect(dynamicPart.length).toBeGreaterThan(0);
    expect(staticPart).not.toContain("/x");
    expect(dynamicPart).toContain("/x");
    expect(staticPart).not.toContain(LYRIE_PROMPT_CACHE_BOUNDARY);
  });

  test("constant export matches builder output", () => {
    expect(LYRIE_ANTI_FALSE_CLAIMS_RULE).toContain("Report Outcomes Faithfully");
  });

  test("tool list shows NAMES only (deferred-schema)", () => {
    const s = pb.buildStaticSection([
      {
        name: "exec",
        description: "Execute",
        parameters: { type: "object", properties: { cmd: { type: "string" } }, required: ["cmd"] },
      },
    ]);
    expect(s).toContain("- exec");
    // Must not contain the parameter schema in the static section
    expect(s).not.toContain('"properties"');
  });
});
