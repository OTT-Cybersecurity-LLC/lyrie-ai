/**
 * sbom/revalidate.ts — re-check each SBOM component's exploitability against
 * the CURRENT threat-intel/OSV picture, compute deltas vs the previous
 * snapshot, and emit a re-attestation (Feature 5).
 *
 * Exploitability re-check reuses the existing pentest pipeline pieces:
 *   - `ThreatIntelClient.matchDependencies()` (Lyrie feed + OSV) to find
 *     advisories affecting each component@version.
 *   - `calculateCompositeRiskScore()` / `calculateExploitMaturity()` for the
 *     0–100 urgency score + maturity label already used elsewhere.
 *
 * No new network client is introduced — this is a scheduler-friendly wrapper
 * around what the pipeline already knows how to do.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { ThreatIntelClient } from "../pentest/threat-intel/client";
import {
  calculateCompositeRiskScore,
  calculateExploitMaturity,
} from "../pentest/threat-intel/client";
import type { ThreatIntelMatch } from "../pentest/threat-intel/types";
import type { DependencyEntry } from "../pentest/attack-surface";
import { sha256 } from "./generate";
import type {
  ComponentExploitability,
  ExploitabilityDelta,
  Reattestation,
  RevalidationReport,
  SbomArtifact,
  SbomComponent,
  SbomExploitabilitySnapshot,
} from "./types";

const SEV_RANK: Record<ComponentExploitability["severity"], number> = {
  none: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

function componentToDep(c: SbomComponent): DependencyEntry {
  return {
    name: c.name,
    version: c.version,
    manifest: "sbom",
    ecosystem: c.ecosystem,
  };
}

/** Assess a single component's exploitability from its advisory matches. */
function assessComponent(
  c: SbomComponent,
  matches: ThreatIntelMatch[],
): ComponentExploitability {
  if (matches.length === 0) {
    return {
      bomRef: c.bomRef,
      name: c.name,
      version: c.version,
      exploitable: false,
      severity: "none",
      score: 0,
      cves: [],
      inKev: false,
    };
  }

  let severity: ComponentExploitability["severity"] = "none";
  let score = 0;
  let inKev = false;
  const cves: string[] = [];
  let worstMaturity = calculateExploitMaturity(matches[0].advisory);

  for (const m of matches) {
    const ad = m.advisory;
    if (SEV_RANK[ad.severity] > SEV_RANK[severity]) severity = ad.severity;
    const s = calculateCompositeRiskScore(ad);
    if (s > score) {
      score = s;
      worstMaturity = calculateExploitMaturity(ad);
    }
    if (ad.kev.inKev) inKev = true;
    if (!cves.includes(ad.cve)) cves.push(ad.cve);
  }

  return {
    bomRef: c.bomRef,
    name: c.name,
    version: c.version,
    exploitable: true,
    severity,
    score,
    exploitMaturity: worstMaturity,
    cves,
    inKev,
  };
}

/**
 * Re-validate a living SBOM against current intel. Produces a fresh
 * exploitability snapshot, deltas vs `previous`, and a summary. Pure with
 * respect to time apart from `now` (injectable).
 */
export async function revalidateSbom(
  artifact: SbomArtifact,
  client: ThreatIntelClient,
  opts: { previous?: SbomExploitabilitySnapshot; now?: () => number } = {},
): Promise<RevalidationReport> {
  const now = opts.now ?? Date.now;
  const assessedAt = new Date(now()).toISOString();

  // Match all components in one pass (client dedupes internally).
  const deps = artifact.components.map(componentToDep);
  const allMatches = await client.matchDependencies(deps);

  // Group matches back to their component by ecosystem:name.
  const byComponent = new Map<string, ThreatIntelMatch[]>();
  for (const c of artifact.components) {
    const key = `${c.ecosystem}:${c.name}`;
    byComponent.set(c.bomRef, allMatches.filter((m) => m.matchedOn === key));
  }

  const components = artifact.components.map((c) =>
    assessComponent(c, byComponent.get(c.bomRef) ?? []),
  );

  const snapshot: SbomExploitabilitySnapshot = {
    serialNumber: artifact.serialNumber,
    assessedAt,
    components,
  };

  const deltas = computeDeltas(opts.previous, snapshot);

  const exploitable = components.filter((c) => c.exploitable).length;
  const newlyExploitable = deltas.filter((d) => d.kind === "newly-exploitable").length;
  const highestSeverity = components.reduce<ComponentExploitability["severity"]>(
    (top, c) => (SEV_RANK[c.severity] > SEV_RANK[top] ? c.severity : top),
    "none",
  );

  return {
    serialNumber: artifact.serialNumber,
    assessedAt,
    snapshot,
    deltas,
    summary: { total: components.length, exploitable, newlyExploitable, highestSeverity },
  };
}

/** Delta detection: newly/no-longer exploitable, severity change, add/remove. */
export function computeDeltas(
  previous: SbomExploitabilitySnapshot | undefined,
  current: SbomExploitabilitySnapshot,
): ExploitabilityDelta[] {
  const deltas: ExploitabilityDelta[] = [];
  const prevByRef = new Map<string, ComponentExploitability>(
    (previous?.components ?? []).map((c) => [c.bomRef, c]),
  );
  const curByRef = new Map<string, ComponentExploitability>(
    current.components.map((c) => [c.bomRef, c]),
  );

  // First run (no previous): report currently-exploitable components as newly
  // exploitable so the initial attestation is honest about posture.
  if (!previous) {
    for (const c of current.components) {
      if (c.exploitable) {
        deltas.push({
          kind: "newly-exploitable",
          bomRef: c.bomRef,
          name: c.name,
          version: c.version,
          currentSeverity: c.severity,
          detail: `${c.name}${c.version ? `@${c.version}` : ""} is exploitable (${c.severity}, ${c.cves.join(", ") || "no CVE"})`,
        });
      }
    }
    return deltas;
  }

  for (const c of current.components) {
    const p = prevByRef.get(c.bomRef);
    if (!p) {
      deltas.push({
        kind: "component-added",
        bomRef: c.bomRef,
        name: c.name,
        version: c.version,
        currentSeverity: c.severity,
        detail: `component added: ${c.name}${c.version ? `@${c.version}` : ""}`,
      });
      if (c.exploitable) {
        deltas.push({
          kind: "newly-exploitable",
          bomRef: c.bomRef,
          name: c.name,
          version: c.version,
          currentSeverity: c.severity,
          detail: `${c.name} added and already exploitable (${c.severity})`,
        });
      }
      continue;
    }
    if (!p.exploitable && c.exploitable) {
      deltas.push({
        kind: "newly-exploitable",
        bomRef: c.bomRef,
        name: c.name,
        version: c.version,
        previousSeverity: p.severity,
        currentSeverity: c.severity,
        detail: `${c.name}${c.version ? `@${c.version}` : ""} became exploitable (${c.severity}, ${c.cves.join(", ") || "no CVE"})`,
      });
    } else if (p.exploitable && !c.exploitable) {
      deltas.push({
        kind: "no-longer-exploitable",
        bomRef: c.bomRef,
        name: c.name,
        version: c.version,
        previousSeverity: p.severity,
        currentSeverity: c.severity,
        detail: `${c.name} is no longer exploitable`,
      });
    } else if (SEV_RANK[c.severity] > SEV_RANK[p.severity]) {
      deltas.push({
        kind: "severity-increased",
        bomRef: c.bomRef,
        name: c.name,
        version: c.version,
        previousSeverity: p.severity,
        currentSeverity: c.severity,
        detail: `${c.name} severity increased ${p.severity} → ${c.severity}`,
      });
    } else if (SEV_RANK[c.severity] < SEV_RANK[p.severity]) {
      deltas.push({
        kind: "severity-decreased",
        bomRef: c.bomRef,
        name: c.name,
        version: c.version,
        previousSeverity: p.severity,
        currentSeverity: c.severity,
        detail: `${c.name} severity decreased ${p.severity} → ${c.severity}`,
      });
    }
  }

  // Removed components.
  for (const p of previous.components) {
    if (!curByRef.has(p.bomRef)) {
      deltas.push({
        kind: "component-removed",
        bomRef: p.bomRef,
        name: p.name,
        version: p.version,
        previousSeverity: p.severity,
        detail: `component removed: ${p.name}${p.version ? `@${p.version}` : ""}`,
      });
    }
  }

  return deltas;
}

// ─── Re-attestation ─────────────────────────────────────────────────────────

/**
 * Produce a hash-based re-attestation over a snapshot. This is an
 * integrity/provenance record (SHA-256 digest of the canonical snapshot),
 * NOT a cryptographic signature — kept honest by the field name and by not
 * claiming any key material was used.
 */
export function reattest(
  snapshot: SbomExploitabilitySnapshot,
  now: () => number = Date.now,
): Reattestation {
  const exploitable = snapshot.components.filter((c) => c.exploitable);
  const highestSeverity = snapshot.components.reduce<ComponentExploitability["severity"]>(
    (top, c) => (SEV_RANK[c.severity] > SEV_RANK[top] ? c.severity : top),
    "none",
  );
  const anyKevOrCritical = exploitable.some((c) => c.inKev || c.severity === "critical");
  const verdict: Reattestation["predicate"]["verdict"] =
    exploitable.length === 0 ? "clean" : anyKevOrCritical ? "action-required" : "action-recommended";

  return {
    serialNumber: snapshot.serialNumber,
    attestedAt: new Date(now()).toISOString(),
    digest: sha256(snapshot),
    predicate: {
      type: "https://lyrie.ai/attestations/exploitability/v1",
      exploitableComponents: exploitable.length,
      highestSeverity,
      verdict,
    },
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}
