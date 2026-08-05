/**
 * sbom/types.ts — Living SBOM exploitability-revalidation shapes (Feature 5).
 *
 * Lyrie's SBOM is "living": an artifact is generated once from a manifest,
 * then periodically RE-validated against the current threat-intel/OSV picture
 * so that a component which was clean at generation time but is now known-
 * exploitable is surfaced as a DELTA and re-attested. The artifact format is
 * a minimal CycloneDX-style JSON (enough to be recognizable/interoperable
 * without pulling in a CycloneDX dependency).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { ExploitMaturity } from "../pentest/threat-intel/types";

export type Ecosystem = "npm" | "cargo" | "pip" | "go" | "ruby" | "php" | "java" | "unknown";

/** A single SBOM component (subset of CycloneDX `component`). */
export interface SbomComponent {
  /** CycloneDX `bom-ref` — stable id within this SBOM. */
  bomRef: string;
  type: "library";
  name: string;
  version?: string;
  ecosystem: Ecosystem;
  /** Package URL (purl), e.g. "pkg:npm/lodash@4.17.20". */
  purl: string;
}

/** Minimal CycloneDX-style SBOM artifact. */
export interface SbomArtifact {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  /** Lyrie-assigned serial number for this SBOM. */
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tool: { vendor: string; name: string; version: string };
    /** Optional subject name (project/app). */
    component?: { type: "application"; name: string };
  };
  components: SbomComponent[];
}

/** Per-component exploitability verdict at a point in time. */
export interface ComponentExploitability {
  bomRef: string;
  name: string;
  version?: string;
  /** True if any advisory currently matches this component+version. */
  exploitable: boolean;
  /** Highest advisory severity found (or "none"). */
  severity: "critical" | "high" | "medium" | "low" | "info" | "none";
  /** Composite 0–100 exploitability/urgency score (max across matches). */
  score: number;
  /** Exploit maturity of the worst match. */
  exploitMaturity?: ExploitMaturity;
  /** CVE ids driving the verdict. */
  cves: string[];
  /** True when any driving CVE is in CISA KEV. */
  inKev: boolean;
}

/** A full exploitability assessment of an SBOM at one instant. */
export interface SbomExploitabilitySnapshot {
  serialNumber: string;
  /** ISO timestamp of the assessment. */
  assessedAt: string;
  components: ComponentExploitability[];
}

export type DeltaKind =
  | "newly-exploitable"
  | "no-longer-exploitable"
  | "severity-increased"
  | "severity-decreased"
  | "component-added"
  | "component-removed";

export interface ExploitabilityDelta {
  kind: DeltaKind;
  bomRef: string;
  name: string;
  version?: string;
  /** Human-readable one-liner. */
  detail: string;
  /** Previous & current severity where relevant. */
  previousSeverity?: ComponentExploitability["severity"];
  currentSeverity?: ComponentExploitability["severity"];
}

/** Result of re-validating a living SBOM against current intel. */
export interface RevalidationReport {
  serialNumber: string;
  assessedAt: string;
  /** The fresh snapshot produced by this run. */
  snapshot: SbomExploitabilitySnapshot;
  /** Deltas vs the previous snapshot (empty on first run). */
  deltas: ExploitabilityDelta[];
  /** Convenience roll-up. */
  summary: {
    total: number;
    exploitable: number;
    newlyExploitable: number;
    highestSeverity: ComponentExploitability["severity"];
  };
}

/** Signed-ish re-attestation output (hash-based, not a real cryptographic sig). */
export interface Reattestation {
  serialNumber: string;
  attestedAt: string;
  /** SHA-256 over the canonical snapshot JSON. */
  digest: string;
  /** Statement predicate summarizing the exploitability posture. */
  predicate: {
    type: "https://lyrie.ai/attestations/exploitability/v1";
    exploitableComponents: number;
    highestSeverity: ComponentExploitability["severity"];
    verdict: "clean" | "action-recommended" | "action-required";
  };
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
}
