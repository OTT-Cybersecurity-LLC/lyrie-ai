/**
 * Lyrie SARIF Viewer — Type definitions for SARIF 2.1.0
 *
 * Covers the subset of SARIF 2.1.0 that Lyrie uses.
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── SARIF 2.1.0 schema types ──────────────────────────────────────────────

export interface SarifPhysicalLocation {
  artifactLocation?: {
    uri?: string;
    uriBaseId?: string;
  };
  region?: {
    startLine?: number;
    startColumn?: number;
    endLine?: number;
    endColumn?: number;
  };
}

export interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  logicalLocations?: Array<{ name?: string; fullyQualifiedName?: string }>;
  message?: { text?: string };
}

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

export interface SarifResult {
  ruleId?: string;
  /** "error" | "warning" | "note" | "none" | "open" | "review" | "informational" */
  level?: string;
  message: { text?: string; markdown?: string };
  locations?: SarifLocation[];
  fingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

export interface SarifToolDriver {
  name: string;
  version?: string;
  informationUri?: string;
  rules?: SarifRule[];
}

export interface SarifRun {
  tool: {
    driver: SarifToolDriver;
  };
  results?: SarifResult[];
  automationDetails?: {
    id?: string;
    guid?: string;
  };
  invocations?: Array<{ executionSuccessful?: boolean; startTimeUtc?: string; endTimeUtc?: string }>;
}

export interface SarifDocument {
  $schema?: string;
  version?: string;
  runs: SarifRun[];
}

// ─── Enriched / parsed view types ──────────────────────────────────────────

export type SeverityLevel = "error" | "warning" | "note" | "none";

export interface ParsedFinding {
  ruleId: string;
  level: SeverityLevel;
  message: string;
  /** Display-friendly file path or URL */
  location?: string;
  /** Line number, if available */
  line?: number;
  /** Whether location is a full https:// URL (clickable) */
  locationIsUrl: boolean;
  /** Full rule metadata if available */
  rule?: SarifRule;
  /** Index in original results array (for stable keys) */
  index: number;
  toolName: string;
  runId?: string;
}

export interface ParsedSarif {
  findings: ParsedFinding[];
  toolNames: string[];
  runIds: string[];
  totalCount: number;
  bySeverity: Record<SeverityLevel, number>;
}
