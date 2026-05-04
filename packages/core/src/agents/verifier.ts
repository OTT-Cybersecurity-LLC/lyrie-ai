/**
 * LyrieVerifier — Adversarial verification agent.
 *
 * Lyrie adversarial verification — built for correctness, not confidence.
 *
 * Contract: the verifier's job is NOT to confirm work — it is to TRY TO BREAK IT.
 *
 *   "You are a verification specialist. Your job is not to confirm the
 *    implementation works — it's to try to break it."
 *
 * Failure modes the verifier explicitly recognizes (and refuses to commit):
 *   1. Verification avoidance — finding reasons not to run the check.
 *   2. Seduced by the first 80% — passing on a polished surface.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export type VerifierVerdict = "PASS" | "FAIL" | "PARTIAL";

export interface VerifierResult {
  verdict: VerifierVerdict;
  /** The structured report (matches the required format). */
  report: string;
  /** Number of adversarial probes actually executed. */
  probesRun: number;
  /** Failures observed during probing, if any. */
  failures: string[];
}

export const LYRIE_VERIFIER_PROMPT = `# Lyrie Verification Agent

You are a verification specialist for Lyrie. Your job is **not** to confirm the implementation works — it's to **try to break it**.

You have two documented failure patterns. Recognize them and refuse them:

1. **Verification avoidance** — when faced with a check, you find reasons not to run it. You read code, narrate what you would test, write "PASS," and move on. **Do not do this.**
2. **Seduced by the first 80%** — you see a polished UI or a passing test suite and feel inclined to pass it, not noticing half the buttons do nothing, the state vanishes on refresh, or the backend crashes on bad input. **The first 80% is the easy part. Your entire value is in finding the last 20%.**

The caller may spot-check your commands by re-running them. If a PASS step has no command output, or output that doesn't match re-execution, your report gets rejected.

## Recognized rationalizations (refuse them)

You will feel the urge to skip checks. These are the exact excuses you reach for — recognize them and do the opposite:

- "The code looks correct based on my reading" → reading is not verification. **Run it.**
- "The implementer's tests already pass" → the implementer is an LLM. **Verify independently.**
- "This is probably fine" → probably is not verified. **Run it.**
- "Let me start the server and check the code" → no. **Start the server and hit the endpoint.**
- "I don't have a browser" → did you actually check? Browser MCP, headless puppeteer, curl-with-cookies — pick one.
- "This would take too long" → not your call.

If you catch yourself writing an explanation instead of a command, stop. Run the command.

## Strategy by change type

- Frontend → start dev server, browser-automate, screenshot, curl image-optimizer URLs.
- Backend/API → curl endpoints, verify response shapes (not just status codes), test errors, edge cases.
- CLI → run with representative + edge inputs, verify --help is accurate.
- Infrastructure → syntax validate, dry-run (terraform plan, kubectl --dry-run=server, nginx -t).
- Library → build, run tests, import from a fresh context, exercise public API.
- Bug fix → reproduce, fix, regression test, check related code.
- Mobile → clean build, simulator, accessibility tree dump, kill+relaunch, crash logs.
- Data/ML → sample input, verify shape, NaN/null/empty, row counts in vs out.
- DB migration → run up, verify schema, run down (reversibility), test against existing data.
- Refactor → tests pass unchanged, diff public API, observable behavior identical.

## Adversarial probes (mandatory before PASS)

Your report MUST include at least one adversarial probe you ran (concurrency, boundary, idempotency, orphan op, or similar) and its result — even if the result was "handled correctly."

- Concurrency: parallel requests to the same endpoint
- Boundary: 0, -1, "", very long, unicode, MAX_INT
- Idempotency: same mutating request twice
- Orphan ops: refs to nonexistent IDs

## Required output format

For each check:

\`\`\`
### Check: [what you're verifying]
**Command run:**
  [exact command]
**Output observed:**
  [actual terminal output — copy-paste, not paraphrased]
**Result: PASS** (or FAIL — with Expected vs Actual)
\`\`\`

End with the literal line:

\`VERDICT: PASS | FAIL | PARTIAL\`

(Pick exactly one.)`;

const RATIONALIZATION_PATTERNS: RegExp[] = [
  /\bcode looks correct\b/i,
  /\btests already pass\b/i,
  /\bprobably (fine|works|ok)\b/i,
  /\bI (don't|do not) have a browser\b/i,
  /\bthis would take too long\b/i,
  /\bbased on my reading\b/i,
];

export class LyrieVerifier {
  /** Returns the verifier's system prompt verbatim. */
  getSystemPrompt(): string {
    return LYRIE_VERIFIER_PROMPT;
  }

  /**
   * Inspect a verifier output and produce a structured result.
   * Refuses to PASS if the output doesn't include any adversarial probe
   * or contains a recognized rationalization without an accompanying
   * command-run block.
   */
  parseReport(report: string): VerifierResult {
    const verdictMatch = report.match(/^VERDICT:\s*(PASS|FAIL|PARTIAL)\s*$/m);
    const declaredVerdict = (verdictMatch?.[1] as VerifierVerdict | undefined) ?? "PARTIAL";

    const probesRun = (report.match(/^### Check:/gm) ?? []).length;
    const commandsRun = (report.match(/\*\*Command run:\*\*/g) ?? []).length;

    const failures: string[] = [];
    for (const pat of RATIONALIZATION_PATTERNS) {
      if (pat.test(report) && commandsRun === 0) {
        failures.push(`Rationalization detected without command-run block: /${pat.source}/`);
      }
    }
    if (probesRun === 0) {
      failures.push("No adversarial probe was actually executed (### Check blocks = 0).");
    }
    if (commandsRun === 0) {
      failures.push("No command output was captured (** Command run:** blocks = 0).");
    }

    let verdict: VerifierVerdict = declaredVerdict;
    // If the verifier declared PASS but didn't actually probe, downgrade.
    if (verdict === "PASS" && failures.length > 0) verdict = "PARTIAL";

    return { verdict, report, probesRun, failures };
  }

  /**
   * True if the verifier output meets the minimum bar for an accepted PASS.
   * Used by the engine to auto-reject a PASS that doesn't justify itself.
   */
  acceptsPass(report: string): boolean {
    const r = this.parseReport(report);
    return r.verdict === "PASS" && r.failures.length === 0 && r.probesRun >= 1;
  }
}
