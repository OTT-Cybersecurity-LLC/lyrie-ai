import type { SarifLog, SarifRun, FindingGroup, SarifLevel } from "./types";

/**
 * Parse a raw SARIF JSON string or object into runs.
 */
export function parseSarif(input: string | object): SarifLog {
  const raw = typeof input === "string" ? JSON.parse(input) : input;
  if (!raw || raw.version !== "2.1.0") {
    throw new Error(`Unsupported SARIF version: ${raw?.version ?? "unknown"}`);
  }
  return raw as SarifLog;
}

/**
 * Group results by rule for display, sorted by severity (error → warning → note → none).
 */
export function groupByRule(run: SarifRun): FindingGroup[] {
  const ruleMap = new Map<string, FindingGroup>();

  const rulesById = new Map(
    (run.tool.driver.rules ?? []).map((r) => [r.id, r])
  );

  for (const result of run.results ?? []) {
    const rule = rulesById.get(result.ruleId);
    const level: SarifLevel =
      result.level ?? rule?.defaultConfiguration?.level ?? "warning";

    if (!ruleMap.has(result.ruleId)) {
      ruleMap.set(result.ruleId, {
        ruleId: result.ruleId,
        ruleName: rule?.name ?? result.ruleId,
        ruleDescription:
          rule?.shortDescription?.text ??
          rule?.fullDescription?.text ??
          "",
        level,
        helpUri: rule?.helpUri,
        results: [],
      });
    }
    ruleMap.get(result.ruleId)!.results.push(result);
  }

  const severityOrder: Record<SarifLevel, number> = {
    error: 0,
    warning: 1,
    note: 2,
    none: 3,
  };

  return [...ruleMap.values()].sort(
    (a, b) => severityOrder[a.level] - severityOrder[b.level]
  );
}
