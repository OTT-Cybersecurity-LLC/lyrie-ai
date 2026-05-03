/**
 * System-prompt building blocks — anti-false-claims rule presence.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  buildMinimalSystemPrompt,
  LYRIE_ANTI_FALSE_CLAIMS_RULE,
  LYRIE_CYBER_RISK_INSTRUCTION,
} from "./system-prompt";

describe("Anti-False-Claims rule", () => {
  test("appears in every minimal system prompt", () => {
    const p = buildMinimalSystemPrompt();
    expect(p).toContain("Report Outcomes Faithfully");
    expect(p).toContain("incomplete or broken work as done");
  });

  test("constant export is present and stable", () => {
    expect(LYRIE_ANTI_FALSE_CLAIMS_RULE).toContain("Report Outcomes Faithfully");
    expect(LYRIE_ANTI_FALSE_CLAIMS_RULE).toContain("Equally on the other side");
  });

  test("cyber-risk gate is present in every minimal prompt", () => {
    const p = buildMinimalSystemPrompt();
    expect(p).toContain("authorized security testing");
    expect(p).toContain("Refuse requests for destructive techniques");
    expect(LYRIE_CYBER_RISK_INSTRUCTION).toContain("DoS attacks");
  });

  test("operator addendum is appended", () => {
    const p = buildMinimalSystemPrompt("EXTRA-FLAG");
    expect(p).toContain("EXTRA-FLAG");
    // Anti-false-claims still appears
    expect(p).toContain("Report Outcomes Faithfully");
  });
});
