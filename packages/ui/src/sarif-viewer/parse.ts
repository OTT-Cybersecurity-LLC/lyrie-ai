/**
 * SARIF 2.1.0 parser — Lyrie SARIF viewer.
 *
 * Two public entry points:
 *   • `parseSarif(input)`     → flattened `ParsedSarif` view-model for UI use.
 *   • `parseSarifRaw(input)`  → the raw `SarifLog` (preserves spec shape).
 *   • `parseSarifJson(json)`  → safe variant that returns `null` on bad input
 *                               instead of throwing. Always returns the
 *                               flattened view-model.
 *
 * `parseSarifRaw` is the legacy behavior kept for callers that want to walk
 * the spec tree directly; `parseSarif` returns the modern view-model that the
 * `<SarifViewer />` component renders against.
 */

import type {
  BySeverity,
  Finding,
  FindingGroup,
  ParsedSarif,
  SarifDocument,
  SarifLevel,
  SarifLog,
  SarifResult,
  SarifRun,
} from "./types";

const SEVERITY_ORDER: Record<SarifLevel, number> = {
  error: 0,
  warning: 1,
  note: 2,
  none: 3,
};

// ─── parseSarifRaw — strict spec parser ─────────────────────────────────────

/**
 * Parse a raw SARIF JSON string or object and return the spec `SarifLog` shape.
 *
 * Throws on:
 *   • invalid JSON
 *   • null / non-object input
 *   • missing or unsupported `version` field
 */
export function parseSarifRaw(input: string | object): SarifLog {
  const raw = typeof input === "string" ? JSON.parse(input) : input;
  if (raw === null || raw === undefined || typeof raw !== "object") {
    throw new Error(`Unsupported SARIF version: ${(raw as unknown) ?? "unknown"}`);
  }
  const r = raw as SarifLog & { version?: string };
  if (r.version !== "2.1.0") {
    throw new Error(`Unsupported SARIF version: ${r.version ?? "unknown"}`);
  }
  return r as SarifLog;
}

// ─── parseSarif — flattened view-model ──────────────────────────────────────

/**
 * Parse a SARIF document (string or object) into a flattened, UI-friendly
 * view-model. Unlike `parseSarifRaw`, this is permissive:
 *   • missing `runs` → empty findings
 *   • missing `version` → still parsed (used in fixtures)
 *   • unknown level → treated as `"none"`
 *
 * Throws only on JSON parse errors when `input` is a string.
 */
export function parseSarif(input: string | SarifDocument | object): ParsedSarif {
  const doc = (typeof input === "string" ? JSON.parse(input) : input) as
    | SarifDocument
    | null;

  if (!doc || typeof doc !== "object" || !Array.isArray((doc as SarifDocument).runs)) {
    return emptyParsed();
  }

  const findings: Finding[] = [];
  const toolNames = new Set<string>();
  const runIds = new Set<string>();

  for (const run of (doc as SarifDocument).runs) {
    const toolName = run.tool?.driver?.name ?? "unknown";
    toolNames.add(toolName);

    const runId = run.automationDetails?.id;
    if (runId) runIds.add(runId);

    const rulesById = new Map(
      (run.tool?.driver?.rules ?? []).map((r) => [r.id, r] as const),
    );

    for (const result of run.results ?? []) {
      const rule = result.ruleId ? rulesById.get(result.ruleId) : undefined;
      const level = normalizeLevel(
        result.level ?? rule?.defaultConfiguration?.level,
      );

      const phys = result.locations?.[0]?.physicalLocation;
      const uri = phys?.artifactLocation?.uri;
      const line = phys?.region?.startLine;
      const column = phys?.region?.startColumn;

      findings.push({
        ruleId: result.ruleId ?? "unknown",
        level,
        message: result.message?.text ?? "",
        toolName,
        runId,
        location: uri,
        locationIsUrl: typeof uri === "string" && /^https?:\/\//i.test(uri),
        line,
        column,
        rule: rule
          ? {
              id: rule.id,
              name: rule.name,
              description:
                rule.shortDescription?.text ?? rule.fullDescription?.text,
              helpUri: rule.helpUri,
            }
          : undefined,
        raw: result,
      });
    }
  }

  findings.sort(
    (a, b) => SEVERITY_ORDER[a.level] - SEVERITY_ORDER[b.level],
  );

  const bySeverity: BySeverity = { error: 0, warning: 0, note: 0, none: 0 };
  for (const f of findings) bySeverity[f.level]++;

  return {
    findings,
    totalCount: findings.length,
    bySeverity,
    toolNames: [...toolNames],
    runIds: [...runIds],
  };
}

/**
 * Safe variant of `parseSarif` for untrusted JSON strings.
 *
 * Returns `null` when the input cannot be JSON-parsed at all. Always returns
 * a `ParsedSarif` (possibly empty) when the input parses to an object — even
 * if it isn't strictly a SARIF document — so UIs can fail gracefully.
 */
export function parseSarifJson(json: string): ParsedSarif | null {
  if (typeof json !== "string" || json.trim() === "") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  return parseSarif(parsed as object);
}

// ─── groupByRule (raw API, kept for legacy callers) ────────────────────────

/**
 * Group raw SARIF results by rule, sorted by severity.
 *
 * Operates on the spec `SarifRun` shape (use `parseSarifRaw` first if you
 * have a JSON string).
 */
export function groupByRule(run: SarifRun): FindingGroup[] {
  const ruleMap = new Map<string, FindingGroup>();
  const rulesById = new Map(
    (run.tool?.driver?.rules ?? []).map((r) => [r.id, r] as const),
  );

  for (const result of run.results ?? []) {
    const ruleId = result.ruleId ?? "unknown";
    const rule = rulesById.get(ruleId);
    // Legacy `groupByRule` contract: missing level defaults to "warning".
    // (The newer `parseSarif` view-model defaults to "none".)
    const level: SarifLevel =
      (result.level as SarifLevel | undefined) ??
      (rule?.defaultConfiguration?.level as SarifLevel | undefined) ??
      "warning";

    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        ruleId,
        ruleName: rule?.name ?? ruleId,
        ruleDescription:
          rule?.shortDescription?.text ?? rule?.fullDescription?.text ?? "",
        level,
        helpUri: rule?.helpUri,
        results: [],
      });
    }
    ruleMap.get(ruleId)!.results.push(result satisfies SarifResult);
  }

  return [...ruleMap.values()].sort(
    (a, b) => SEVERITY_ORDER[a.level] - SEVERITY_ORDER[b.level],
  );
}

// ─── helpers ───────────────────────────────────────────────────────────────

function emptyParsed(): ParsedSarif {
  return {
    findings: [],
    totalCount: 0,
    bySeverity: { error: 0, warning: 0, note: 0, none: 0 },
    toolNames: [],
    runIds: [],
  };
}

function normalizeLevel(level: string | undefined): SarifLevel {
  switch (level) {
    case "error":
    case "warning":
    case "note":
      return level;
    default:
      return "none";
  }
}
