/**
 * watch/run-once.ts — Single-tick, cron-friendly entry point for posture
 * monitoring: probe once, persist, diff against the previous snapshot, and
 * classify overall drift severity.
 *
 * `WatchEngine` (engine.ts) already does exactly this probe→diff→persist
 * sequence per tick, but it is wrapped in `DaemonEngine`'s tick-loop/event
 * machinery (`start()`, `on("alert"|"idle"|"action", ...)`, interval sleeps)
 * — the right shape for a long-running daemon process, but overkill for a
 * cron job or a script that just wants "run one check, get one result,
 * exit". `runWatchTick()` is that thin, loop-free wrapper: it calls the
 * exact same `probeDomain` / `loadLastSnapshot` / `diffPostureSnapshots` /
 * `saveSnapshot` primitives WatchEngine uses internally, with no engine
 * instantiation, no event emitter, and no interval — just one awaited call
 * a cron scheduler's isolated turn (or `scripts/watch-once.ts`) can invoke.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { AdapterFinding } from "../engine/daemon";
import { classifyDriftSeverity, type DriftSeverityResult } from "./drift-severity";
import { diffPostureSnapshots } from "./diff";
import { probeDomain } from "./probe";
import { loadLastSnapshot, saveSnapshot, watchDir } from "./store";
import type { PostureSnapshot, ProbeOptions } from "./types";

export interface RunWatchTickOptions {
  /** Probe hooks (fetch/tls/subdomain injection — see probe.ts's ProbeOptions). */
  probeOptions?: ProbeOptions;
  /** Snapshot storage directory override (tests use a tmp dir; defaults to watchDir()). */
  storeDir?: string;
  /** When false, skip persisting the new snapshot (dry-run / preview mode). Default true. */
  persist?: boolean;
}

export interface RunWatchTickResult {
  snapshot: PostureSnapshot;
  /** Diff findings vs. the previous snapshot, or `undefined` on a first-ever run (no baseline to diff against). */
  diff: AdapterFinding[] | undefined;
  /** Overall drift-severity verdict for this tick, or `undefined` when `diff` is `undefined` (nothing to classify yet). */
  driftSeverity: DriftSeverityResult | undefined;
}

/**
 * Run exactly one posture-watch tick for `domain`: probe → diff against the
 * last stored snapshot (if any) → classify overall drift severity → persist
 * the new snapshot as the baseline for the next tick.
 *
 * Never throws for probe-level failures — `probeDomain()` already degrades
 * connection failures to `snapshot.unreachable = true` rather than
 * rejecting, and that unreachable state flows through diff/classification
 * like any other snapshot. This function DOES let unexpected errors from
 * the store layer (e.g. a permissions error creating `storeDir`) propagate,
 * since a cron entry point should fail loudly on infrastructure problems
 * rather than silently skip persistence.
 */
export async function runWatchTick(domain: string, options: RunWatchTickOptions = {}): Promise<RunWatchTickResult> {
  const dir = options.storeDir ?? watchDir();
  const persist = options.persist ?? true;

  const previous = loadLastSnapshot(domain, dir);
  const snapshot = await probeDomain(domain, options.probeOptions);

  let diff: AdapterFinding[] | undefined;
  let driftSeverity: DriftSeverityResult | undefined;
  if (previous) {
    diff = diffPostureSnapshots(domain, previous, snapshot);
    driftSeverity = classifyDriftSeverity(diff);
  }

  if (persist) {
    saveSnapshot(snapshot, dir);
  }

  return { snapshot, diff, driftSeverity };
}
