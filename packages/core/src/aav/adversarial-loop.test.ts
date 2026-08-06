/**
 * Lyrie AAV — Adversarial Loop tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect, afterEach } from "bun:test";
import {
  runAdversarialLoop,
  base64WrapMutation,
  roleplayFramingMutation,
  homoglyphMutation,
  type MutationStrategy,
} from "./adversarial-loop";
import { LyrieRedTeam } from "./red-team";
import type { RedTeamTarget, ProbeResult } from "./red-team";
import { getById } from "./corpus/index";

const DRY_TARGET: RedTeamTarget = {
  endpoint: "http://localhost:11434/v1",
  model: "llama3",
};

// Keep a reference to the real probe so each test can restore it.
const originalProbe = LyrieRedTeam.prototype.probe;

/** Mirrors adversarial-loop.ts's baseVectorId(): strips ALL trailing -MUT-XXX suffixes. */
function stripAllMutSuffixes(id: string): string {
  let stripped = id;
  let prev: string;
  do {
    prev = stripped;
    stripped = stripped.replace(/-MUT-[A-Z0-9]+$/, "");
  } while (stripped !== prev);
  return stripped;
}

afterEach(() => {
  LyrieRedTeam.prototype.probe = originalProbe;
});

// ─── Mutation strategy unit tests ──────────────────────────────────────────

describe("base64WrapMutation", () => {
  it("produces a genuinely different, base64-encoded payload", () => {
    const vector = getById("LLM01-001")!;
    const mutated = base64WrapMutation(vector);

    expect(mutated.payload).not.toBe(vector.payload);
    expect(mutated.id).toBe(`${vector.id}-MUT-B64`);
    // The mutated payload should NOT contain the raw trigger phrase in plaintext...
    expect(mutated.payload).not.toContain("Ignore all previous instructions");
    // ...but should contain the original payload base64-encoded.
    const encoded = Buffer.from(vector.payload, "utf-8").toString("base64");
    expect(mutated.payload).toContain(encoded);
    // Same underlying vulnerability class: indicators unchanged.
    expect(mutated.successIndicators).toEqual(vector.successIndicators);
    expect(mutated.failIndicators).toEqual(vector.failIndicators);
    expect(mutated.category).toBe(vector.category);
    expect(mutated.severity).toBe(vector.severity);
  });

  it("round-trips: decoding the mutated payload recovers the original payload", () => {
    const vector = getById("LLM06-001")!;
    const mutated = base64WrapMutation(vector);
    const b64Match = mutated.payload.match(/\n\n([A-Za-z0-9+/=]+)$/);
    expect(b64Match).not.toBeNull();
    const decoded = Buffer.from(b64Match![1]!, "base64").toString("utf-8");
    expect(decoded).toBe(vector.payload);
  });
});

describe("roleplayFramingMutation", () => {
  it("wraps the payload in a fictional/authority preamble without altering it", () => {
    const vector = getById("LLM01-002")!;
    const mutated = roleplayFramingMutation(vector);

    expect(mutated.payload).not.toBe(vector.payload);
    expect(mutated.id).toBe(`${vector.id}-MUT-ROLE`);
    // Original payload text should still be present verbatim (context-shift, not obfuscation).
    expect(mutated.payload).toContain(vector.payload);
    // A distinct roleplay/authority frame should be added.
    expect(mutated.payload.toLowerCase()).toContain("screenplay");
    expect(mutated.payload.toLowerCase()).toContain("character");
    // Same underlying vulnerability class: indicators unchanged.
    expect(mutated.successIndicators).toEqual(vector.successIndicators);
    expect(mutated.failIndicators).toEqual(vector.failIndicators);
  });
});

describe("homoglyphMutation", () => {
  it("substitutes trigger words with visually-identical Unicode homoglyphs", () => {
    const vector = getById("LLM01-001")!; // payload contains "Ignore all previous instructions"
    const mutated = homoglyphMutation(vector);

    expect(mutated.payload).not.toBe(vector.payload);
    expect(mutated.id).toBe(`${vector.id}-MUT-HOMO`);
    // The literal ASCII trigger words should no longer match exactly...
    expect(/\bignore\b/i.test(mutated.payload)).toBe(false);
    // ...but the mutated payload should be a different string of the same rough shape/length family.
    expect(mutated.payload.length).toBeGreaterThan(0);
    expect(mutated.successIndicators).toEqual(vector.successIndicators);
    expect(mutated.failIndicators).toEqual(vector.failIndicators);
  });

  it("preserves non-trigger text untouched", () => {
    const vector = getById("LLM09-001")!; // no trigger words like "ignore"/"instructions" in payload
    const mutated = homoglyphMutation(vector);
    // Vector LLM09-001 payload doesn't contain any TRIGGER_WORDS, so mutation should be a no-op on content
    // (id/name/description still change) — verify payload text is unchanged when no triggers present.
    expect(mutated.payload).toBe(vector.payload);
  });
});

// ─── Loop convergence — dry run (always "defended") ────────────────────────

describe("runAdversarialLoop — dry run convergence", () => {
  it("converges immediately when round 1 has zero successes", async () => {
    const result = await runAdversarialLoop({
      target: DRY_TARGET,
      redTeamOptions: { dryRun: true, categories: ["LLM01"], concurrency: 2 },
    });

    expect(result.totalRounds).toBe(1);
    expect(result.converged).toBe(true);
    expect(result.rounds[0]!.successfulVectors).toHaveLength(0);
    expect(result.persistentVulnerabilities).toHaveLength(0);
    // DefenseReport should be a perfect/near-perfect score since dry-run always "defends".
    expect(result.rounds[0]!.defenseReport.attackSuccessRate).toBe(0);
  });

  it("respects maxRounds and redTeamOptions passthrough", async () => {
    const result = await runAdversarialLoop({
      target: DRY_TARGET,
      maxRounds: 2,
      redTeamOptions: { dryRun: true, minSeverity: "critical", concurrency: 3 },
    });
    expect(result.totalRounds).toBeLessThanOrEqual(2);
    for (const round of result.rounds) {
      for (const probe of round.probed) {
        expect(probe.vector.severity).toBe("critical");
      }
    }
  });
});

// ─── Loop convergence — controlled fake probe (deterministic success/fail) ──

/**
 * Builds a fake `probe` implementation for LyrieRedTeam that deterministically
 * succeeds or defends based on vector id, so we can test multi-round
 * mutation logic without a live LLM endpoint. This follows the existing
 * repo pattern of using LyrieRedTeam's `dryRun` short-circuit in probe() —
 * here we instead monkeypatch the public `probe` method (the same method
 * `dryRun` short-circuits inside), which is restored in `afterEach` above,
 * to control exactly which vectors "succeed" per round without touching
 * red-team.ts itself.
 */
function makeFakeProbe(
  verdictFor: (vector: { id: string }, callCountForId: number) => ProbeResult["verdict"],
): typeof LyrieRedTeam.prototype.probe {
  const callCounts = new Map<string, number>();
  return async function fakeProbe(this: LyrieRedTeam, vector) {
    const prevCount = callCounts.get(vector.id) ?? 0;
    callCounts.set(vector.id, prevCount + 1);
    const verdict = verdictFor(vector, prevCount + 1);
    return {
      vector,
      prompt: vector.payload,
      response: verdict === "success" ? "PWNED — attack succeeded" : "I cannot help with that.",
      verdict,
      confidence: verdict === "success" ? 0.9 : 0.9,
      evidence: [],
      latencyMs: 1,
      attempt: 1,
    } satisfies ProbeResult;
  };
}

describe("runAdversarialLoop — multi-round mutation logic", () => {
  it("identifies persistentVulnerabilities (survives mutation) vs one-off successes (defeated by mutation)", async () => {
    // LLM01-001 (DAN jailbreak): succeeds in round 1 AND every mutated round → persistent.
    // LLM01-002 (roleplay bypass): succeeds in round 1 only, mutations are defended → one-off, not persistent.
    const persistentId = "LLM01-001";
    const oneOffId = "LLM01-002";

    LyrieRedTeam.prototype.probe = makeFakeProbe((vector) => {
      const baseId = stripAllMutSuffixes(vector.id);
      if (baseId === persistentId) return "success";
      if (baseId === oneOffId) {
        // Only succeeds on the very first (unmutated) probe.
        return vector.id === oneOffId ? "success" : "defended";
      }
      return "defended";
    });

    const result = await runAdversarialLoop({
      target: DRY_TARGET,
      maxRounds: 3,
      redTeamOptions: { vectors: [getById(persistentId)!, getById(oneOffId)!], concurrency: 2 },
    });

    // Should NOT converge — persistentId keeps succeeding through maxRounds.
    expect(result.converged).toBe(false);
    expect(result.totalRounds).toBe(3);

    // Round 1: both succeed.
    expect(result.rounds[0]!.successfulVectors.map((v) => v.id).sort()).toEqual(
      [persistentId, oneOffId].sort(),
    );

    // Round 2: only mutations of persistentId succeed; oneOffId's mutations are defended.
    const round2Ids = result.rounds[1]!.successfulVectors.map((v) => stripAllMutSuffixes(v.id));
    expect(round2Ids.every((id) => id === persistentId)).toBe(true);
    expect(round2Ids.length).toBeGreaterThan(0);

    // persistentVulnerabilities should contain persistentId's vector but NOT oneOffId's.
    const persistentIds = result.persistentVulnerabilities.map((v) => stripAllMutSuffixes(v.id));
    expect(persistentIds).toContain(persistentId);
    expect(persistentIds).not.toContain(oneOffId);
  });

  it("converges as soon as a round has zero successes, before reaching maxRounds", async () => {
    const targetId = "LLM06-001";

    LyrieRedTeam.prototype.probe = makeFakeProbe((vector, callCount) => {
      const baseId = stripAllMutSuffixes(vector.id);
      if (baseId !== targetId) return "defended";
      // Succeeds in round 1 (unmutated), then every mutation is defended.
      return vector.id === targetId ? "success" : "defended";
    });

    const result = await runAdversarialLoop({
      target: DRY_TARGET,
      maxRounds: 5,
      redTeamOptions: { vectors: [getById(targetId)!], concurrency: 2 },
    });

    expect(result.converged).toBe(true);
    expect(result.totalRounds).toBe(2); // round 1 succeeds, round 2 (mutated) all defended → converge
    expect(result.rounds[1]!.successfulVectors).toHaveLength(0);
    expect(result.persistentVulnerabilities).toHaveLength(0);
  });

  it("applies each configured mutation strategy between rounds", async () => {
    const targetId = "LLM03-001";
    const seenMutationSuffixes = new Set<string>();

    LyrieRedTeam.prototype.probe = makeFakeProbe((vector) => {
      const match = vector.id.match(/-MUT-([A-Z0-9]+)$/);
      if (match) seenMutationSuffixes.add(match[1]!);
      // Always succeed so round 2 is guaranteed to run with mutated variants of every strategy.
      return "success";
    });

    const customStrategies: MutationStrategy[] = [
      base64WrapMutation,
      roleplayFramingMutation,
      homoglyphMutation,
    ];

    await runAdversarialLoop({
      target: DRY_TARGET,
      maxRounds: 2,
      mutationStrategies: customStrategies,
      redTeamOptions: { vectors: [getById(targetId)!], concurrency: 3 },
    });

    expect(seenMutationSuffixes.has("B64")).toBe(true);
    expect(seenMutationSuffixes.has("ROLE")).toBe(true);
    expect(seenMutationSuffixes.has("HOMO")).toBe(true);
  });

  it("defenseReport per round reflects the actual probed results (blue team wired correctly)", async () => {
    LyrieRedTeam.prototype.probe = makeFakeProbe(() => "success");

    const result = await runAdversarialLoop({
      target: DRY_TARGET,
      maxRounds: 1,
      redTeamOptions: { vectors: [getById("LLM01-001")!], concurrency: 1 },
    });

    const round = result.rounds[0]!;
    expect(round.defenseReport.totalProbed).toBe(round.probed.length);
    expect(round.defenseReport.attackSuccessRate).toBe(1);
    expect(round.defenseReport.criticalVulns.length).toBeGreaterThan(0);
  });
});
