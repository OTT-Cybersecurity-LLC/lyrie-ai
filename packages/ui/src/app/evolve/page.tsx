// lyrie-shield: ignore-file (Evolve dashboard UI surfaces skill/domain names; this is product copy)
//
// ─────────────────────────────────────────────────────────────────────────
// DATA SOURCE NOTE (read before wiring a real API):
//
// This page currently renders MOCK data. The real backend exists and is
// fully wired in packages/core/src/evolve/:
//   - dream-cycle.ts    → runDreamCycle() returns a DreamReport (unprocessed
//                          outcomes, extracted skills, pruned candidates,
//                          total skills)
//   - scorer.ts         → Scorer reads/writes ~/.lyrie/evolve/outcomes.jsonl,
//                          one TaskOutcome per line (domain, score, signals)
//   - skill-extractor.ts→ SkillExtractor writes SKILL.md files with
//                          **Avg Score:** headers parsed by dream-cycle's
//                          findPruneCandidates()
//   - training-exporter.ts → TrainingExporter.status() returns
//                          TrainingStatus { totalOutcomes, readySamples,
//                          byDomain, lastExportTimestamp }
//
// There is no existing `packages/ui/src/app/api/*` route pattern in this
// repo (checked: shield/overview/agents/memory/settings pages all render
// static/mock data directly, no API routes exist yet). Rather than invent
// a new pattern unilaterally, this page follows the same convention:
// mock data is used until a decision is made on how the UI process reads
// ~/.lyrie/evolve/outcomes.jsonl (options: a small API route reading the
// file server-side, or a shared read-only IPC/socket to a running daemon).
// That's a real architectural decision, not a rendering detail, so it's
// deliberately left as a TODO rather than guessed at here.
// ─────────────────────────────────────────────────────────────────────────

import {
  Brain,
  TrendingUp,
  Scissors,
  Database,
  Sparkles,
  Clock,
} from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";

/* ---------- Mock data (see DATA SOURCE NOTE above) ---------- */

interface DomainStat {
  domain: string;
  outcomes: number;
  avgScore: number;
  skillsExtracted: number;
}

const MOCK_DOMAIN_STATS: DomainStat[] = [
  { domain: "cyber", outcomes: 214, avgScore: 0.78, skillsExtracted: 12 },
  { domain: "code", outcomes: 187, avgScore: 0.71, skillsExtracted: 9 },
  { domain: "seo", outcomes: 96, avgScore: 0.64, skillsExtracted: 5 },
  { domain: "trading", outcomes: 58, avgScore: 0.52, skillsExtracted: 2 },
  { domain: "general", outcomes: 341, avgScore: 0.69, skillsExtracted: 15 },
];

interface DreamCycleRun {
  date: string;
  unprocessed: number;
  extracted: number;
  pruned: number;
  totalSkills: number;
}

const MOCK_DREAM_CYCLES: DreamCycleRun[] = [
  { date: "07-25", unprocessed: 42, extracted: 3, pruned: 1, totalSkills: 43 },
  { date: "07-24", unprocessed: 38, extracted: 2, pruned: 0, totalSkills: 41 },
  { date: "07-23", unprocessed: 51, extracted: 4, pruned: 2, totalSkills: 39 },
  { date: "07-22", unprocessed: 29, extracted: 1, pruned: 0, totalSkills: 37 },
  { date: "07-21", unprocessed: 33, extracted: 2, pruned: 1, totalSkills: 36 },
];

interface TrainingExportRow {
  date: string;
  format: string;
  samples: number;
  sizeKb: number;
}

const MOCK_EXPORT_HISTORY: TrainingExportRow[] = [
  { date: "07-24", format: "atropos", samples: 512, sizeKb: 340 },
  { date: "07-17", format: "atropos", samples: 401, sizeKb: 267 },
  { date: "07-10", format: "openai-sft", samples: 350, sizeKb: 198 },
];

const domainColor: Record<string, string> = {
  cyber: "text-lyrie-red bg-lyrie-red/10",
  code: "text-lyrie-cyan bg-lyrie-cyan/10",
  seo: "text-lyrie-green bg-lyrie-green/10",
  trading: "text-lyrie-amber bg-lyrie-amber/10",
  general: "text-lyrie-accent-light bg-lyrie-accent/10",
};

/* ---------- Domain Breakdown ---------- */
function DomainBreakdown() {
  const totalOutcomes = MOCK_DOMAIN_STATS.reduce((s, d) => s + d.outcomes, 0);

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Brain className="w-4 h-4 text-lyrie-accent-light" />
        <h3 className="text-sm font-semibold text-white">Domain Breakdown</h3>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {MOCK_DOMAIN_STATS.map((d) => {
          const pct = totalOutcomes > 0 ? (d.outcomes / totalOutcomes) * 100 : 0;
          return (
            <div key={d.domain} className="px-5 py-3.5">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full",
                      domainColor[d.domain] ?? "text-lyrie-text-dim bg-lyrie-card",
                    )}
                  >
                    {d.domain}
                  </span>
                  <span className="text-xs text-lyrie-text-muted">
                    {d.outcomes} outcomes · {d.skillsExtracted} skills
                  </span>
                </div>
                <span className="text-xs font-mono text-lyrie-text-dim">
                  avg {d.avgScore.toFixed(2)}
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-lyrie-card overflow-hidden">
                <div
                  className="h-full rounded-full bg-lyrie-accent"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Dream Cycle History ---------- */
function DreamCycleHistory() {
  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-lyrie-cyan" />
          <h3 className="text-sm font-semibold text-white">Dream Cycle History</h3>
        </div>
        <span className="text-[10px] px-2 py-1 rounded-full bg-lyrie-green/10 text-lyrie-green font-semibold uppercase">
          Idle
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-lyrie-border text-lyrie-text-muted">
              <th className="px-5 py-2.5 text-left font-medium">Run</th>
              <th className="px-3 py-2.5 text-left font-medium">Unprocessed</th>
              <th className="px-3 py-2.5 text-left font-medium">Extracted</th>
              <th className="px-3 py-2.5 text-left font-medium">Pruned</th>
              <th className="px-5 py-2.5 text-right font-medium">Total Skills</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-lyrie-border/50">
            {MOCK_DREAM_CYCLES.map((r, i) => (
              <tr key={i} className="hover:bg-lyrie-card/30 transition-colors">
                <td className="px-5 py-2.5 text-lyrie-text font-mono">{r.date}</td>
                <td className="px-3 py-2.5 text-lyrie-text-dim">{r.unprocessed}</td>
                <td className="px-3 py-2.5 text-lyrie-green">{r.extracted}</td>
                <td className="px-3 py-2.5">
                  <span className={r.pruned > 0 ? "text-lyrie-amber" : "text-lyrie-text-dim"}>
                    {r.pruned}
                  </span>
                </td>
                <td className="px-5 py-2.5 text-right text-lyrie-text font-mono">
                  {r.totalSkills}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Training Export History ---------- */
function TrainingExportHistory() {
  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Database className="w-4 h-4 text-lyrie-green" />
        <h3 className="text-sm font-semibold text-white">Training Export History</h3>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {MOCK_EXPORT_HISTORY.map((e, i) => (
          <div key={i} className="px-5 py-3 flex items-center justify-between hover:bg-lyrie-card/30 transition-colors">
            <div className="flex items-center gap-3">
              <Clock className="w-3.5 h-3.5 text-lyrie-text-muted" />
              <div>
                <p className="text-sm text-lyrie-text">{e.samples.toLocaleString()} samples</p>
                <p className="text-[10px] text-lyrie-text-muted">{e.date} · {e.format}</p>
              </div>
            </div>
            <span className="text-xs font-mono text-lyrie-text-dim">{e.sizeKb} KB</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Page ---------- */
export default function EvolvePage() {
  const totalOutcomes = MOCK_DOMAIN_STATS.reduce((s, d) => s + d.outcomes, 0);
  const totalSkills = MOCK_DREAM_CYCLES[0]?.totalSkills ?? 0;
  const latestPruned = MOCK_DREAM_CYCLES[0]?.pruned ?? 0;
  const totalExported = MOCK_EXPORT_HISTORY.reduce((s, e) => s + e.samples, 0);

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Sparkles className="w-7 h-7 text-lyrie-cyan" />
          Evolve Dashboard
        </h2>
        <p className="text-sm text-lyrie-text-muted mt-1">
          Self-training loop: outcome scoring, skill extraction, and training export
          &nbsp;·&nbsp;
          <span className="text-lyrie-amber">mock data — see DATA SOURCE NOTE in page.tsx</span>
        </p>
      </div>

      {/* Stat Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Outcomes" value={totalOutcomes.toLocaleString()} subtitle="All domains" icon={TrendingUp} variant="accent" />
        <StatCard title="Active Skills" value={totalSkills} subtitle={`${latestPruned} pruned last cycle`} icon={Brain} variant="cyan" />
        <StatCard title="Pruned (last cycle)" value={latestPruned} subtitle="avgScore < 0.3, uses ≥ 5" icon={Scissors} variant="amber" />
        <StatCard title="Training Samples Exported" value={totalExported.toLocaleString()} subtitle="Across all exports" icon={Database} variant="green" />
      </div>

      {/* Two Column */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DomainBreakdown />
        <DreamCycleHistory />
      </div>

      <TrainingExportHistory />
    </div>
  );
}
