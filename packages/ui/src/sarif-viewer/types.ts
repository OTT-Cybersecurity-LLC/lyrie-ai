/**
 * Minimal SARIF 2.1.0 types for the Lyrie SARIF viewer.
 * Full spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
 */

export interface SarifLog {
  version: "2.1.0";
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules?: SarifRule[];
    };
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

export type SarifLevel = "error" | "warning" | "note" | "none";

export interface SarifResult {
  ruleId: string;
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

/** Derived view model used by the UI components */
export interface FindingGroup {
  ruleId: string;
  ruleName: string;
  ruleDescription: string;
  level: SarifLevel;
  helpUri?: string;
  results: SarifResult[];
}
