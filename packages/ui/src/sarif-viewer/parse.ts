/**
 * Lyrie SARIF Viewer — Parser
 *
 * Converts a SARIF 2.1.0 document into ParsedSarif (enriched flat view).
 * Handles missing/malformed fields gracefully — never throws.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  SarifDocument,
  SarifResult,
  SarifRule,
  ParsedFinding,
  ParsedSarif,
  SeverityLevel,
} from "./types";

const SEVERITY_ORDER: SeverityLevel[] = ["error", "warning", "note", "none"];

/** Normalise any level string to one of our four buckets. */
function normLevel(raw?: string): SeverityLevel {
  const s = (raw ?? "none").toLowerCase();
  if (s === "error") return "error";
  if (s === "warning") return "warning";
  if (s === "note" || s === "informational" || s === "open" || s === "review") return "note";
  return "none";
}

/** Extract a human-readable location string + line from a SARIF result. */
function extractLocation(result: SarifResult): {
  location?: string;
  line?: number;
  locationIsUrl: boolean;
} {
  const loc = result.locations?.[0];
  if (!loc) return { locationIsUrl: false };

  const phys = loc.physicalLocation;
  const uri = phys?.artifactLocation?.uri;
  const line = phys?.region?.startLine;

  if (!uri) return { locationIsUrl: false };

  const isUrl = uri.startsWith("https://") || uri.startsWith("http://");
  return { location: uri, line, locationIsUrl: isUrl };
}

/**
 * Parse a SarifDocument into a flat, enriched ParsedSarif.
 * Never throws — returns empty ParsedSarif on bad input.
 */
export function parseSarif(doc: SarifDocument): ParsedSarif {
  const findings: ParsedFinding[] = [];
  const toolNamesSet = new Set<string>();
  const runIdsSet = new Set<string>();

  const bySeverity: Record<SeverityLevel, number> = {
    error: 0,
    warning: 0,
    note: 0,
    none: 0,
  };

  if (!doc || !Array.isArray(doc.runs)) {
    return { findings, toolNames: [], runIds: [], totalCount: 0, bySeverity };
  }

  for (const run of doc.runs) {
    if (!run) continue;

    const toolName = run.tool?.driver?.name ?? "Unknown Tool";
    toolNamesSet.add(toolName);

    const runId = run.automationDetails?.id;
    if (runId) runIdsSet.add(runId);

    // Build rule map for quick lookup
    const ruleMap = new Map<string, SarifRule>();
    for (const rule of run.tool?.driver?.rules ?? []) {
      if (rule?.id) ruleMap.set(rule.id, rule);
    }

    for (let i = 0; i < (run.results?.length ?? 0); i++) {
      const result = run.results![i];
      if (!result) continue;

      const ruleId = result.ruleId ?? "unknown";
      const level = normLevel(result.level);
      const message =
        result.message?.text ?? result.message?.markdown ?? "(no message)";

      const { location, line, locationIsUrl } = extractLocation(result);

      bySeverity[level]++;

      findings.push({
        ruleId,
        level,
        message,
        location,
        line,
        locationIsUrl,
        rule: ruleMap.get(ruleId),
        index: i,
        toolName,
        runId,
      });
    }
  }

  // Sort: errors first, then warning, note, none — then alphabetical ruleId
  findings.sort((a, b) => {
    const orderA = SEVERITY_ORDER.indexOf(a.level);
    const orderB = SEVERITY_ORDER.indexOf(b.level);
    if (orderA !== orderB) return orderA - orderB;
    return a.ruleId.localeCompare(b.ruleId);
  });

  return {
    findings,
    toolNames: [...toolNamesSet],
    runIds: [...runIdsSet],
    totalCount: findings.length,
    bySeverity,
  };
}

/**
 * Parse a SARIF JSON string. Returns null on parse failure.
 */
export function parseSarifJson(json: string): ParsedSarif | null {
  try {
    const doc = JSON.parse(json) as SarifDocument;
    return parseSarif(doc);
  } catch {
    return null;
  }
}
