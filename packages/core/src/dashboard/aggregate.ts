/**
 * dashboard/aggregate.ts — anonymization + aggregation pipeline for the
 * public Agentic-Attack-Compression live feed (Feature 3).
 *
 * The daemon's `_checkAgenticThreats` emits `AttackCompressionSignature`s
 * that describe HOW an attack is compressing across the automation ↔ autonomy
 * spectrum (phases observed, compression ratio, TTP entropy, threat level).
 * Those raw signatures can carry host-specific / operator-specific context
 * (tool fingerprints, finding ids, descriptions). This module strips all of
 * that and reduces each signal to a small, non-identifying aggregate suitable
 * for a PUBLIC radar-style feed:
 *
 *   - channel bucket (1=automation, 2=augmentation, 3=autonomy)
 *   - attack-phase counts (Recon/Execution/Exfiltration/…)
 *   - threat-level bucket + coarse compression/entropy bands
 *   - a coarse (minute-floored) time bucket
 *
 * No host names, no IPs, no tool fingerprints, no finding ids, no free-text
 * descriptions ever cross this boundary. `anonymizeSignal()` is the single
 * chokepoint — the store only ever receives its output.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  AttackCompressionSignature,
  AttackPhase,
} from "../engine/agentic-threat-bridge";

export type ThreatLevel = "None" | "Low" | "Medium" | "High" | "Critical";

/** Coarse band for a continuous value so exact figures can't fingerprint a host. */
export type Band = "none" | "low" | "moderate" | "high" | "severe";

/**
 * A fully anonymized, aggregate-ready compression signal. Contains NOTHING
 * that can identify a host, operator, tool, or specific finding.
 */
export interface AnonymizedSignal {
  /** Minute-floored unix ms (coarsens exact timing). */
  timeBucketMs: number;
  /** Channel: 1=Automation, 2=Augmentation, 3=Autonomy. */
  channel: 1 | 2 | 3;
  /** Threat level bucket. */
  threatLevel: ThreatLevel;
  /** Distinct attack phases observed, sorted, de-duplicated. */
  phases: AttackPhase[];
  /** Per-phase occurrence counts. */
  phaseCounts: Partial<Record<AttackPhase, number>>;
  /** Coarse band for compression ratio (findings/min). */
  compressionBand: Band;
  /** Coarse band for TTP entropy. */
  entropyBand: Band;
  /** Coarse band for detector confidence. */
  confidenceBand: Band;
}

const MINUTE_MS = 60_000;

function clampChannel(c: number): 1 | 2 | 3 {
  if (c <= 1) return 1;
  if (c >= 3) return 3;
  return 2;
}

/** Compression ratio (findings/min) → coarse band. */
function compressionToBand(ratio: number): Band {
  if (ratio <= 0) return "none";
  if (ratio < 1) return "low";
  if (ratio < 3) return "moderate";
  if (ratio < 6) return "high";
  return "severe";
}

/** TTP entropy (0..~3+) → coarse band. */
function entropyToBand(entropy: number): Band {
  if (entropy <= 0) return "none";
  if (entropy < 0.5) return "low";
  if (entropy < 1.2) return "moderate";
  if (entropy < 2) return "high";
  return "severe";
}

/** Confidence (0..1) → coarse band. */
function confidenceToBand(conf: number): Band {
  if (conf <= 0) return "none";
  if (conf < 0.3) return "low";
  if (conf < 0.6) return "moderate";
  if (conf < 0.85) return "high";
  return "severe";
}

/**
 * Reduce a raw compression signature to an `AnonymizedSignal`. This is the
 * ONLY sanctioned way a raw signal may enter the public feed store.
 *
 * @param sig  Raw signature from the agentic-threat bridge.
 * @param nowMs Wall-clock (test-injectable) for the time bucket.
 */
export function anonymizeSignal(
  sig: AttackCompressionSignature,
  nowMs: number = Date.now(),
): AnonymizedSignal {
  const phaseCounts: Partial<Record<AttackPhase, number>> = {};
  for (const p of sig.phases_observed) {
    phaseCounts[p] = (phaseCounts[p] ?? 0) + 1;
  }
  const phases = [...new Set(sig.phases_observed)].sort() as AttackPhase[];

  return {
    timeBucketMs: Math.floor(nowMs / MINUTE_MS) * MINUTE_MS,
    channel: clampChannel(sig.channel),
    threatLevel: sig.threat_level,
    phases,
    phaseCounts,
    compressionBand: compressionToBand(sig.compression_ratio),
    entropyBand: entropyToBand(sig.ttp_entropy),
    confidenceBand: confidenceToBand(sig.confidence),
  };
}

// ─── Feed-level aggregation ─────────────────────────────────────────────────────

export interface FeedAggregate {
  /** Total anonymized signals in the window. */
  total: number;
  /** Count per channel. */
  byChannel: Record<1 | 2 | 3, number>;
  /** Count per threat level. */
  byThreatLevel: Record<ThreatLevel, number>;
  /** Total occurrences per attack phase across all signals. */
  byPhase: Partial<Record<AttackPhase, number>>;
  /** Earliest / latest time bucket present (unix ms), or null when empty. */
  windowStartMs: number | null;
  windowEndMs: number | null;
}

const EMPTY_CHANNELS = (): Record<1 | 2 | 3, number> => ({ 1: 0, 2: 0, 3: 0 });
const EMPTY_LEVELS = (): Record<ThreatLevel, number> => ({
  None: 0,
  Low: 0,
  Medium: 0,
  High: 0,
  Critical: 0,
});

/** Compute a roll-up over a set of anonymized signals for the radar UI. */
export function aggregateFeed(signals: AnonymizedSignal[]): FeedAggregate {
  const byChannel = EMPTY_CHANNELS();
  const byThreatLevel = EMPTY_LEVELS();
  const byPhase: Partial<Record<AttackPhase, number>> = {};
  let windowStartMs: number | null = null;
  let windowEndMs: number | null = null;

  for (const s of signals) {
    byChannel[s.channel] += 1;
    byThreatLevel[s.threatLevel] += 1;
    for (const [phase, count] of Object.entries(s.phaseCounts)) {
      const p = phase as AttackPhase;
      byPhase[p] = (byPhase[p] ?? 0) + (count ?? 0);
    }
    if (windowStartMs === null || s.timeBucketMs < windowStartMs) windowStartMs = s.timeBucketMs;
    if (windowEndMs === null || s.timeBucketMs > windowEndMs) windowEndMs = s.timeBucketMs;
  }

  return {
    total: signals.length,
    byChannel,
    byThreatLevel,
    byPhase,
    windowStartMs,
    windowEndMs,
  };
}
