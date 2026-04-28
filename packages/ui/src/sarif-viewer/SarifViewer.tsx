"use client";
/**
 * Lyrie SARIF Viewer — React Component
 *
 * Props:
 *   sarifData  — already-parsed SarifDocument
 *   sarifJson  — raw JSON string (parsed on mount)
 *
 * Zero external deps beyond React + existing UI deps (lucide-react, clsx/tailwind-merge).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import React, { useState, useMemo, useCallback } from "react";
import { parseSarif, parseSarifJson } from "./parse";
import type { SarifDocument, ParsedFinding, SeverityLevel, ParsedSarif } from "./types";
import { cn } from "@/lib/utils";

// ─── Severity helpers ──────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  error: "bg-red-500/20 text-red-400 border border-red-500/40",
  warning: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
  note: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
  none: "bg-gray-500/20 text-gray-400 border border-gray-500/40",
};

const SEVERITY_DOT: Record<SeverityLevel, string> = {
  error: "bg-red-500",
  warning: "bg-yellow-500",
  note: "bg-blue-500",
  none: "bg-gray-500",
};

// ─── Sub-components ────────────────────────────────────────────────────────

function SeverityBadge({ level }: { level: SeverityLevel }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider",
        SEVERITY_COLORS[level]
      )}
    >
      <span className={cn("w-1.5 h-1.5 rounded-full", SEVERITY_DOT[level])} />
      {level}
    </span>
  );
}

function SummaryBar({ parsed }: { parsed: ParsedSarif }) {
  const items = [
    { label: "Total", value: parsed.totalCount, color: "text-white" },
    { label: "Errors", value: parsed.bySeverity.error, color: "text-red-400" },
    { label: "Warnings", value: parsed.bySeverity.warning, color: "text-yellow-400" },
    { label: "Notes", value: parsed.bySeverity.note, color: "text-blue-400" },
    { label: "None", value: parsed.bySeverity.none, color: "text-gray-400" },
  ];

  return (
    <div className="flex flex-wrap gap-4 p-4 rounded-xl border border-white/10 bg-white/5">
      {items.map(({ label, value, color }) => (
        <div key={label} className="flex flex-col items-center min-w-[56px]">
          <span className={cn("text-2xl font-bold tabular-nums", color)}>{value}</span>
          <span className="text-[11px] text-gray-400 mt-0.5">{label}</span>
        </div>
      ))}
      {parsed.toolNames.length > 0 && (
        <div className="flex flex-col justify-center ml-auto">
          <span className="text-[11px] text-gray-500">Tool{parsed.toolNames.length > 1 ? "s" : ""}</span>
          <span className="text-sm text-gray-200">{parsed.toolNames.join(", ")}</span>
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: ParsedFinding }) {
  const locationEl = finding.location ? (
    finding.locationIsUrl ? (
      <a
        href={finding.location}
        target="_blank"
        rel="noopener noreferrer"
        className="font-mono text-xs text-blue-400 hover:underline truncate max-w-xs"
        title={finding.location}
      >
        {finding.location}
      </a>
    ) : (
      <span className="font-mono text-xs text-gray-400 truncate max-w-xs" title={finding.location}>
        {finding.location}
        {finding.line ? <span className="text-gray-500">:{finding.line}</span> : null}
      </span>
    )
  ) : null;

  return (
    <div className="flex flex-col gap-1.5 py-3 px-4 border-b border-white/5 last:border-0 hover:bg-white/5 transition-colors">
      <div className="flex items-center gap-2 flex-wrap">
        <SeverityBadge level={finding.level} />
        <button
          onClick={() => navigator.clipboard?.writeText(finding.ruleId)}
          className="font-mono text-xs text-gray-300 bg-white/10 px-2 py-0.5 rounded hover:bg-white/20 transition-colors cursor-pointer"
          title="Click to copy rule ID"
        >
          {finding.ruleId}
        </button>
        {finding.rule?.name && (
          <span className="text-xs text-gray-400">{finding.rule.name}</span>
        )}
        {finding.rule?.helpUri && (
          <a
            href={finding.rule.helpUri}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-blue-400 hover:underline"
          >
            docs ↗
          </a>
        )}
      </div>
      <p className="text-sm text-gray-200 leading-snug">{finding.message}</p>
      {locationEl && <div className="flex items-center gap-1">{locationEl}</div>}
    </div>
  );
}

interface RuleGroupProps {
  ruleId: string;
  findings: ParsedFinding[];
  defaultOpen?: boolean;
}

function RuleGroup({ ruleId, findings, defaultOpen = false }: RuleGroupProps) {
  const [open, setOpen] = useState(defaultOpen);
  const level = findings[0]?.level ?? "none";
  const rule = findings[0]?.rule;

  return (
    <div className="border border-white/10 rounded-xl overflow-hidden mb-2">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 bg-white/5 hover:bg-white/10 transition-colors text-left"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className={cn("w-2 h-2 rounded-full flex-shrink-0", SEVERITY_DOT[level])} />
        <span className="font-mono text-sm text-gray-200 flex-1">{ruleId}</span>
        {rule?.name && <span className="text-xs text-gray-500 hidden sm:block">{rule.name}</span>}
        <span className="text-xs text-gray-400 bg-white/10 px-2 py-0.5 rounded-full flex-shrink-0">
          {findings.length} finding{findings.length !== 1 ? "s" : ""}
        </span>
        <span className="text-gray-500 text-xs ml-1">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="bg-black/20">
          {findings.map((f) => (
            <FindingRow key={`${f.ruleId}-${f.index}`} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Export helpers ────────────────────────────────────────────────────────

function exportJson(parsed: ParsedSarif) {
  const blob = new Blob([JSON.stringify(parsed.findings, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "lyrie-scan-results.json";
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Main component ────────────────────────────────────────────────────────

export interface SarifViewerProps {
  sarifData?: SarifDocument;
  sarifJson?: string;
}

export function SarifViewer({ sarifData, sarifJson }: SarifViewerProps) {
  const parsed = useMemo<ParsedSarif | null>(() => {
    if (sarifData) return parseSarif(sarifData);
    if (sarifJson) return parseSarifJson(sarifJson);
    return null;
  }, [sarifData, sarifJson]);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | "all">("all");

  const filteredFindings = useMemo(() => {
    if (!parsed) return [];
    return parsed.findings.filter((f) => {
      if (severityFilter !== "all" && f.level !== severityFilter) return false;
      if (search && !f.ruleId.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [parsed, search, severityFilter]);

  // Group by ruleId
  const groups = useMemo(() => {
    const map = new Map<string, ParsedFinding[]>();
    for (const f of filteredFindings) {
      const arr = map.get(f.ruleId) ?? [];
      arr.push(f);
      map.set(f.ruleId, arr);
    }
    return [...map.entries()];
  }, [filteredFindings]);

  const handleExport = useCallback(() => {
    if (parsed) exportJson(parsed);
  }, [parsed]);

  if (!parsed) {
    return (
      <div className="flex items-center justify-center py-20 text-gray-500 text-sm">
        No SARIF data provided.
      </div>
    );
  }

  if (parsed.totalCount === 0) {
    return (
      <div className="space-y-4">
        <SummaryBar parsed={parsed} />
        <div className="flex flex-col items-center justify-center py-20 text-gray-500 text-sm gap-2">
          <span className="text-2xl">✅</span>
          <span>No findings — clean scan!</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <SummaryBar parsed={parsed} />

      {/* Toolbar */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="search"
          placeholder="Filter by rule ID…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-[200px] bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <div className="flex gap-1.5">
          {(["all", "error", "warning", "note", "none"] as const).map((sv) => (
            <button
              key={sv}
              onClick={() => setSeverityFilter(sv)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-colors",
                severityFilter === sv
                  ? "bg-blue-600 text-white"
                  : "bg-white/5 text-gray-400 hover:bg-white/10"
              )}
            >
              {sv}
            </button>
          ))}
        </div>
        <button
          onClick={handleExport}
          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-white/10 text-gray-300 hover:bg-white/20 transition-colors"
        >
          Export JSON ↓
        </button>
      </div>

      {/* Results */}
      {filteredFindings.length === 0 ? (
        <div className="text-center py-10 text-gray-500 text-sm">No findings match filters.</div>
      ) : (
        <div>
          {groups.map(([ruleId, findings], idx) => (
            <RuleGroup
              key={ruleId}
              ruleId={ruleId}
              findings={findings}
              defaultOpen={idx === 0 && findings[0]?.level === "error"}
            />
          ))}
        </div>
      )}
    </div>
  );
}
