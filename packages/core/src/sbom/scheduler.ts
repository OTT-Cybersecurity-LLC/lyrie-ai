/**
 * sbom/scheduler.ts — a scheduler HOOK for living-SBOM revalidation
 * (Feature 5). This deliberately does NOT install a real cron/timer; it
 * exposes a single `runScheduledRevalidation()` that an external scheduler
 * (the daemon tick loop, a CI job, an operator CLI) calls on whatever
 * interval it chooses. Keeping the trigger out here means the SBOM code is
 * side-effect-free and unit-testable.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { ThreatIntelClient } from "../pentest/threat-intel/client";
import type { SbomStore } from "./generate";
import { revalidateSbom, reattest } from "./revalidate";
import type { Reattestation, RevalidationReport } from "./types";

export interface ScheduledRevalidationResult {
  serialNumber: string;
  report: RevalidationReport;
  reattestation: Reattestation;
}

/**
 * Revalidate every SBOM in the store against current intel, persist the new
 * snapshot as the baseline for next time (this is what makes the SBOM
 * "living"), and return a report + re-attestation per SBOM.
 *
 * @param store   SBOM store (holds artifacts + last snapshot per serial).
 * @param client  Threat-intel client (Lyrie feed + OSV).
 * @param now     Injectable clock for deterministic tests.
 */
export async function runScheduledRevalidation(
  store: SbomStore,
  client: ThreatIntelClient,
  now: () => number = Date.now,
): Promise<ScheduledRevalidationResult[]> {
  const out: ScheduledRevalidationResult[] = [];

  for (const artifact of store.list()) {
    const previous = store.getLastSnapshot(artifact.serialNumber);
    const report = await revalidateSbom(artifact, client, { previous, now });
    // Persist the fresh snapshot as the new baseline (the "living" step).
    store.setLastSnapshot(artifact.serialNumber, report.snapshot);
    const reattestation = reattest(report.snapshot, now);
    out.push({ serialNumber: artifact.serialNumber, report, reattestation });
  }

  return out;
}
