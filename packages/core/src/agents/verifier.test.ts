/**
 * LyrieVerifier — adversarial verification tests.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { LyrieVerifier } from "./verifier";

describe("LyrieVerifier", () => {
  const v = new LyrieVerifier();

  test("system prompt includes the rationalizations list verbatim", () => {
    const p = v.getSystemPrompt();
    expect(p).toContain("verification specialist");
    expect(p).toMatch(/not\*?\*?\s+to confirm/);
    expect(p).toContain("looks correct based on my reading");
    expect(p).toContain("tests already pass");
    expect(p).toContain("This is probably fine");
    expect(p).toContain("This would take too long");
  });

  test("system prompt requires VERDICT line at end", () => {
    expect(v.getSystemPrompt()).toMatch(/VERDICT: PASS \| FAIL \| PARTIAL/);
  });

  test("a well-formed PASS report is accepted", () => {
    const report = `### Check: GET /healthz
**Command run:**
  curl -s http://localhost:8080/healthz
**Output observed:**
  {"status":"ok","version":"1.2.3"}
**Result: PASS**

### Check: concurrency probe
**Command run:**
  for i in 1..20: curl -s in parallel
**Output observed:**
  20/20 returned 200, no 5xx
**Result: PASS**

VERDICT: PASS`;
    const r = v.parseReport(report);
    expect(r.verdict).toBe("PASS");
    expect(r.probesRun).toBe(2);
    expect(r.failures.length).toBe(0);
    expect(v.acceptsPass(report)).toBe(true);
  });

  test("a PASS without any ### Check block is downgraded to PARTIAL", () => {
    const report = `Looks good to me.

VERDICT: PASS`;
    const r = v.parseReport(report);
    expect(r.verdict).toBe("PARTIAL");
    expect(r.failures.length).toBeGreaterThan(0);
    expect(v.acceptsPass(report)).toBe(false);
  });

  test("rationalizations without command output trigger failure", () => {
    const report = `The code looks correct based on my reading. This is probably fine.

VERDICT: PASS`;
    const r = v.parseReport(report);
    expect(r.failures.some((f) => f.includes("Rationalization detected"))).toBe(true);
    expect(v.acceptsPass(report)).toBe(false);
  });

  test("FAIL verdict propagates", () => {
    const report = `### Check: nope
**Command run:**
  curl http://x
**Output observed:**
  500 internal error
**Result: FAIL**
  Expected: 200
  Actual: 500

VERDICT: FAIL`;
    const r = v.parseReport(report);
    expect(r.verdict).toBe("FAIL");
  });

  test("missing VERDICT line defaults to PARTIAL", () => {
    const r = v.parseReport(`### Check: x\n**Command run:**\n  ls\n**Output observed:**\n  file\n**Result: PASS**\n`);
    expect(r.verdict).toBe("PARTIAL");
  });
});
