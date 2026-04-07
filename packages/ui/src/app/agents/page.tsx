import {
  Bot,
  Plus,
  Play,
  Pause,
  RotateCcw,
  Cpu,
  Clock,
  Zap,
  Brain,
  Search,
  Code,
  Palette,
  Eye,
  ChevronRight,
  Wrench,
} from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { cn } from "@/lib/utils";

/* ---------- Active Agents ---------- */
function ActiveAgents() {
  const agents = [
    {
      name: "Brain",
      model: "Claude Opus",
      status: "running",
      task: "Strategic planning for Q2 roadmap",
      uptime: "4h 23m",
      tokens: "124K",
      cost: "$1.86",
      icon: Brain,
      color: "text-lyrie-accent-glow",
    },
    {
      name: "Scout",
      model: "Claude Haiku",
      status: "running",
      task: "Monitoring 47 competitor feeds",
      uptime: "12h 05m",
      tokens: "892K",
      cost: "$0.22",
      icon: Search,
      color: "text-lyrie-cyan",
    },
    {
      name: "Coder",
      model: "GPT-5.4 Codex",
      status: "running",
      task: "Implementing shield module — PR #142",
      uptime: "2h 11m",
      tokens: "456K",
      cost: "$0.91",
      icon: Code,
      color: "text-lyrie-green",
    },
    {
      name: "Muscle",
      model: "MiniMax M2.5",
      status: "idle",
      task: "Waiting for batch job",
      uptime: "8h 44m",
      tokens: "2.1M",
      cost: "$0.17",
      icon: Zap,
      color: "text-lyrie-red",
    },
    {
      name: "Creative",
      model: "Gemini 3",
      status: "paused",
      task: "Social media content generation",
      uptime: "1h 30m",
      tokens: "67K",
      cost: "$0.08",
      icon: Palette,
      color: "text-lyrie-amber",
    },
  ];

  const statusStyles = {
    running: { dot: "bg-lyrie-green animate-pulse-slow", label: "Running", labelClass: "text-lyrie-green bg-lyrie-green/10" },
    idle: { dot: "bg-lyrie-amber", label: "Idle", labelClass: "text-lyrie-amber bg-lyrie-amber/10" },
    paused: { dot: "bg-lyrie-text-muted", label: "Paused", labelClass: "text-lyrie-text-muted bg-lyrie-card" },
  };

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-lyrie-accent-light" />
          <h3 className="text-sm font-semibold text-white">Active Agents</h3>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-lyrie-accent/15 text-lyrie-accent-light text-xs font-medium hover:bg-lyrie-accent/25 transition-colors border border-lyrie-accent/20">
          <Plus className="w-3 h-3" />
          Spawn Agent
        </button>
      </div>

      <div className="divide-y divide-lyrie-border/50">
        {agents.map((agent) => {
          const status = statusStyles[agent.status as keyof typeof statusStyles];
          const Icon = agent.icon;
          return (
            <div key={agent.name} className="px-5 py-4 hover:bg-lyrie-card/30 transition-colors">
              <div className="flex items-start gap-4">
                <div className={cn("p-2.5 rounded-xl bg-lyrie-card/80 border border-lyrie-border/50")}>
                  <Icon className={cn("w-5 h-5", agent.color)} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-semibold text-white">{agent.name}</span>
                    <span className={cn("text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full", status.labelClass)}>
                      {status.label}
                    </span>
                    <span className="text-[10px] text-lyrie-text-muted font-mono ml-auto">
                      {agent.model}
                    </span>
                  </div>
                  <p className="text-xs text-lyrie-text-dim truncate">{agent.task}</p>
                  <div className="flex items-center gap-4 mt-2">
                    <span className="text-[10px] text-lyrie-text-muted flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {agent.uptime}
                    </span>
                    <span className="text-[10px] text-lyrie-text-muted flex items-center gap-1">
                      <Cpu className="w-3 h-3" /> {agent.tokens} tokens
                    </span>
                    <span className="text-[10px] text-lyrie-text-muted flex items-center gap-1">
                      <Zap className="w-3 h-3" /> {agent.cost}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {agent.status === "running" ? (
                    <button className="p-1.5 rounded-lg hover:bg-lyrie-card transition-colors" title="Pause">
                      <Pause className="w-3.5 h-3.5 text-lyrie-text-dim" />
                    </button>
                  ) : (
                    <button className="p-1.5 rounded-lg hover:bg-lyrie-card transition-colors" title="Resume">
                      <Play className="w-3.5 h-3.5 text-lyrie-green" />
                    </button>
                  )}
                  <button className="p-1.5 rounded-lg hover:bg-lyrie-card transition-colors" title="Restart">
                    <RotateCcw className="w-3.5 h-3.5 text-lyrie-text-dim" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Agent History ---------- */
function AgentHistory() {
  const history = [
    { agent: "Coder", task: "Implemented memory dedup module", duration: "45m", status: "success", time: "2h ago" },
    { agent: "Scout", task: "Market analysis report generated", duration: "12m", status: "success", time: "3h ago" },
    { agent: "Brain", task: "Architecture review for shield module", duration: "1h 20m", status: "success", time: "4h ago" },
    { agent: "Muscle", task: "Batch processed 12K memory entries", duration: "8m", status: "success", time: "5h ago" },
    { agent: "Creative", task: "Generated landing page mockups", duration: "35m", status: "failed", time: "6h ago" },
    { agent: "Scout", task: "Vulnerability scan on public APIs", duration: "22m", status: "success", time: "7h ago" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Clock className="w-4 h-4 text-lyrie-text-dim" />
        <h3 className="text-sm font-semibold text-white">Agent History</h3>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {history.map((h, i) => (
          <div key={i} className="px-5 py-3 flex items-center gap-3 hover:bg-lyrie-card/30 transition-colors">
            <div className={cn(
              "w-2 h-2 rounded-full",
              h.status === "success" ? "bg-lyrie-green" : "bg-lyrie-red"
            )} />
            <span className="text-xs font-semibold text-lyrie-accent-light w-16">{h.agent}</span>
            <span className="text-xs text-lyrie-text flex-1 truncate">{h.task}</span>
            <span className="text-[10px] font-mono text-lyrie-text-muted">{h.duration}</span>
            <span className="text-[10px] text-lyrie-text-muted">{h.time}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Skills ---------- */
function SkillManagement() {
  const skills = [
    { name: "Web Search", category: "Research", agents: 2, status: "active" },
    { name: "Code Generation", category: "Development", agents: 1, status: "active" },
    { name: "Memory Management", category: "Core", agents: 3, status: "active" },
    { name: "Threat Detection", category: "Security", agents: 2, status: "active" },
    { name: "Content Creation", category: "Creative", agents: 1, status: "active" },
    { name: "Browser Automation", category: "Tools", agents: 1, status: "active" },
    { name: "File Operations", category: "Core", agents: 4, status: "active" },
    { name: "API Integration", category: "Tools", agents: 2, status: "active" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Wrench className="w-4 h-4 text-lyrie-amber" />
          <h3 className="text-sm font-semibold text-white">Skills</h3>
        </div>
        <span className="text-xs text-lyrie-text-muted font-mono">{skills.length} loaded</span>
      </div>
      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-2">
        {skills.map((s) => (
          <div key={s.name} className="flex items-center justify-between p-2.5 rounded-lg bg-lyrie-card/30 hover:bg-lyrie-card/60 transition-colors">
            <div className="flex items-center gap-2.5">
              <div className="w-1.5 h-1.5 rounded-full bg-lyrie-green" />
              <div>
                <p className="text-xs font-medium text-lyrie-text">{s.name}</p>
                <p className="text-[10px] text-lyrie-text-muted">{s.category} · {s.agents} agents</p>
              </div>
            </div>
            <ChevronRight className="w-3 h-3 text-lyrie-text-muted" />
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Page ---------- */
export default function AgentsPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Bot className="w-7 h-7 text-lyrie-accent-light" />
          Agent Management
        </h2>
        <p className="text-sm text-lyrie-text-muted mt-1">
          Deploy, monitor, and manage your autonomous agent fleet
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Agents" value={5} subtitle="2 autonomous" icon={Bot} variant="accent" />
        <StatCard title="Tasks Completed" value={147} subtitle="Today" icon={Zap} variant="green" trend={{ value: "23%", positive: true }} />
        <StatCard title="Total Tokens" value="4.5M" subtitle="Last 24h" icon={Cpu} variant="cyan" />
        <StatCard title="Total Cost" value="$3.24" subtitle="Today" icon={Eye} variant="amber" />
      </div>

      <ActiveAgents />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AgentHistory />
        <SkillManagement />
      </div>
    </div>
  );
}
