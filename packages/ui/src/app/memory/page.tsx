import {
  Brain,
  Search,
  Download,
  Upload,
  Clock,
  Database,
  Activity,
  Tag,
  FileText,
  Star,
  ChevronRight,
  Heart,
  Lightbulb,
  User,
} from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";

/* ---------- Memory Search ---------- */
function MemorySearch() {
  return (
    <div className="glass-card p-5">
      <div className="flex items-center gap-2 mb-4">
        <Search className="w-4 h-4 text-lyrie-accent-light" />
        <h3 className="text-sm font-semibold text-white">Semantic Search</h3>
      </div>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-lyrie-text-muted" />
        <input
          type="text"
          placeholder="Search memories by meaning, not just keywords..."
          className="w-full bg-lyrie-bg/50 border border-lyrie-border rounded-lg pl-10 pr-4 py-3 text-sm text-lyrie-text placeholder:text-lyrie-text-muted focus:outline-none focus:border-lyrie-accent/50 focus:shadow-glow transition-all"
        />
      </div>
      <div className="mt-3 flex items-center gap-2 flex-wrap">
        {["preferences", "decisions", "facts", "entities", "conversations"].map((tag) => (
          <button
            key={tag}
            className="text-[10px] px-2.5 py-1 rounded-full bg-lyrie-card border border-lyrie-border text-lyrie-text-muted hover:text-lyrie-accent-light hover:border-lyrie-accent/30 transition-colors capitalize"
          >
            {tag}
          </button>
        ))}
      </div>
    </div>
  );
}

/* ---------- Memory Timeline ---------- */
function MemoryTimeline() {
  const entries = [
    { time: "16:00", category: "decision", content: "Selected Claude Opus as primary strategy model", importance: 0.9, icon: Lightbulb },
    { time: "15:30", category: "fact", content: "Lyrie Agent project launched — open source autonomous agent", importance: 0.95, icon: Star },
    { time: "14:45", category: "preference", content: "Guy prefers sharp, direct communication — no fluff", importance: 0.85, icon: Heart },
    { time: "14:00", category: "entity", content: "OTT Cybersecurity LLC — parent company for Lyrie.ai", importance: 0.8, icon: User },
    { time: "13:20", category: "fact", content: "5 machines in fleet: Mac #1, #2, EPYC, Beast, H100-NL", importance: 0.75, icon: Database },
    { time: "12:00", category: "decision", content: "Auto model routing: Haiku for simple, Opus for complex", importance: 0.88, icon: Lightbulb },
    { time: "11:30", category: "fact", content: "Cost target: less than $50/day total agent spend", importance: 0.7, icon: FileText },
    { time: "10:15", category: "preference", content: "Execute first, don't ask unless destructive action", importance: 0.92, icon: Heart },
  ];

  const categoryColors: Record<string, string> = {
    decision: "text-lyrie-accent-glow bg-lyrie-accent/10 border-lyrie-accent/20",
    fact: "text-lyrie-cyan bg-lyrie-cyan/10 border-lyrie-cyan/20",
    preference: "text-lyrie-amber bg-lyrie-amber/10 border-lyrie-amber/20",
    entity: "text-lyrie-green bg-lyrie-green/10 border-lyrie-green/20",
  };

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Clock className="w-4 h-4 text-lyrie-accent-light" />
        <h3 className="text-sm font-semibold text-white">Memory Timeline</h3>
      </div>
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-8 top-0 bottom-0 w-px bg-lyrie-border" />

        <div className="divide-y divide-lyrie-border/30">
          {entries.map((entry, i) => {
            const Icon = entry.icon;
            return (
              <div key={i} className="px-5 py-3.5 flex items-start gap-4 hover:bg-lyrie-card/30 transition-colors relative">
                <span className="text-[10px] font-mono text-lyrie-text-muted w-10 mt-1 shrink-0 text-right">
                  {entry.time}
                </span>
                <div className="relative z-10 p-1 rounded-full bg-lyrie-surface border border-lyrie-border shrink-0">
                  <Icon className="w-3 h-3 text-lyrie-accent-light" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={cn("text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full border", categoryColors[entry.category])}>
                      {entry.category}
                    </span>
                    <div className="flex items-center gap-0.5 ml-auto">
                      {Array.from({ length: 5 }).map((_, j) => (
                        <div
                          key={j}
                          className={cn(
                            "w-1 h-3 rounded-full",
                            j < Math.round(entry.importance * 5)
                              ? "bg-lyrie-accent"
                              : "bg-lyrie-card"
                          )}
                        />
                      ))}
                    </div>
                  </div>
                  <p className="text-xs text-lyrie-text leading-relaxed">{entry.content}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ---------- Memory Health ---------- */
function MemoryHealth() {
  const metrics = [
    { label: "Total Entries", value: "14,247", trend: "+340 today" },
    { label: "Unique Entities", value: "892", trend: "+12 today" },
    { label: "Avg Importance", value: "0.73", trend: "Stable" },
    { label: "Duplicates Removed", value: "1,203", trend: "Last cleanup 2h ago" },
    { label: "Storage Used", value: "48 MB", trend: "of 1 GB limit" },
    { label: "Last Backup", value: "4:30 AM", trend: "Auto-daily" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Activity className="w-4 h-4 text-lyrie-green" />
        <h3 className="text-sm font-semibold text-white">Memory Health</h3>
      </div>
      <div className="p-4 grid grid-cols-2 gap-3">
        {metrics.map((m) => (
          <div key={m.label} className="p-3 rounded-lg bg-lyrie-card/30 border border-lyrie-border/30">
            <p className="text-[10px] uppercase tracking-wider text-lyrie-text-muted mb-1">{m.label}</p>
            <p className="text-lg font-bold text-white stat-value">{m.value}</p>
            <p className="text-[10px] text-lyrie-text-muted mt-0.5">{m.trend}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Import/Export ---------- */
function ImportExport() {
  return (
    <div className="glass-card p-5">
      <div className="flex items-center gap-2 mb-4">
        <Database className="w-4 h-4 text-lyrie-cyan" />
        <h3 className="text-sm font-semibold text-white">Import / Export</h3>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <button className="flex items-center justify-center gap-2 p-4 rounded-lg bg-lyrie-card/50 border border-lyrie-border hover:border-lyrie-accent/30 hover:bg-lyrie-card transition-all group">
          <Download className="w-5 h-5 text-lyrie-text-dim group-hover:text-lyrie-accent-light transition-colors" />
          <div className="text-left">
            <p className="text-sm font-medium text-lyrie-text group-hover:text-white transition-colors">Export</p>
            <p className="text-[10px] text-lyrie-text-muted">JSON / CSV</p>
          </div>
        </button>
        <button className="flex items-center justify-center gap-2 p-4 rounded-lg bg-lyrie-card/50 border border-lyrie-border hover:border-lyrie-accent/30 hover:bg-lyrie-card transition-all group">
          <Upload className="w-5 h-5 text-lyrie-text-dim group-hover:text-lyrie-accent-light transition-colors" />
          <div className="text-left">
            <p className="text-sm font-medium text-lyrie-text group-hover:text-white transition-colors">Import</p>
            <p className="text-[10px] text-lyrie-text-muted">JSON / CSV</p>
          </div>
        </button>
      </div>
    </div>
  );
}

/* ---------- Page ---------- */
export default function MemoryPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Brain className="w-7 h-7 text-lyrie-cyan" />
          Memory Explorer
        </h2>
        <p className="text-sm text-lyrie-text-muted mt-1">
          Explore, search, and manage the agent&apos;s long-term memory
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Memories" value="14.2K" subtitle="Across all categories" icon={Brain} variant="cyan" />
        <StatCard title="Health Score" value="98.7%" subtitle="Excellent" icon={Activity} variant="green" />
        <StatCard title="Categories" value={4} subtitle="decision, fact, pref, entity" icon={Tag} variant="accent" />
        <StatCard title="Storage" value="48 MB" subtitle="4.8% of limit" icon={Database} variant="amber" />
      </div>

      <MemorySearch />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <MemoryTimeline />
        </div>
        <div className="space-y-6">
          <MemoryHealth />
          <ImportExport />
        </div>
      </div>
    </div>
  );
}
