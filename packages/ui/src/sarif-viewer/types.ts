/**
 * Minimal SARIF 2.1.0 types for the Lyrie SARIF viewer.
 * Full spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
 *
 * Two shapes coexist here:
 *   • The raw SARIF spec types (`SarifLog`, `SarifRun`, etc.).
 *   • A flattened view-model (`ParsedSarif`, `Finding`) optimised for UI
 *     rendering and produced by `parseSarif()` in `parse.ts`.
 *
 * `SarifDocument` is an alias for `SarifLog` with a relaxed `version` field
 * so callers can pass partial fixtures during tests.
 */

export type SarifLevel = "error" | "warning" | "note" | "none";

// ─── Raw SARIF spec ─────────────────────────────────────────────────────────

export interface SarifLog {
  version?: "2.1.0" | string;
  $schema?: string;
  runs: SarifRun[];
}

/**
 * Loose alias used by view-model tests that build minimal fixtures.
 * Most fields are optional so authors don't need a full SARIF blob.
 */
export type SarifDocument = SarifLog;

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules?: SarifRule[];
    };
  };
  automationDetails?: {
    id?: string;
    description?: { text?: string };
  };
  results?: SarifResult[];
}

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: {
    level?: SarifLevel;
  };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

export interface SarifResult {
  ruleId?: string;
  level?: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  fingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

export interface SarifLocation {
  physicalLocation?: {
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
  };
  logicalLocations?: Array<{
    name?: string;
    kind?: string;
  }>;
}

// ─── View-model ─────────────────────────────────────────────────────────────

/**
 * Flattened, UI-friendly representation of a SARIF result.
 *
 * `location` is a string (URI or file path) when present; `locationIsUrl`
 * is true when `location` parses as an http(s):// URL.
 */
export interface Finding {
  ruleId: string;
  level: SarifLevel;
  message: string;
  toolName: string;
  runId?: string;
  location?: string;
  locationIsUrl: boolean;
  line?: number;
  column?: number;
  rule?: {
    id: string;
    name?: string;
    description?: string;
    helpUri?: string;
  };
  raw: SarifResult;
}

export interface BySeverity {
  error: number;
  warning: number;
  note: number;
  none: number;
}

export interface ParsedSarif {
  findings: Finding[];
  totalCount: number;
  bySeverity: BySeverity;
  toolNames: string[];
  runIds: string[];
}

/**
 * Group of findings with the same `ruleId`. Produced by `groupByRule()`.
 *
 * Kept for backwards compatibility with the original `parse.ts` API.
 */
/** Alias kept for the SarifViewer.tsx component which uses the older name. */
export type ParsedFinding = Finding;

/** Alias kept for the SarifViewer.tsx component which uses the older name. */
export type SeverityLevel = SarifLevel;

export interface FindingGroup {
  ruleId: string;
  ruleName: string;
  ruleDescription: string;
  level: SarifLevel;
  helpUri?: string;
  results: SarifResult[];
}
