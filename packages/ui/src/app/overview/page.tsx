import {
  Shield,
  Bot,
  Brain,
  Cpu,
  MessageSquare,
  Wifi,
  Server,
  Eye,
  Radar,
  Lock,
} from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { ThreatFeed } from "@/components/threat-feed";
import { ActivityFeed } from "@/components/activity-feed";

/* ---------- Protection Score Ring ---------- */
function ProtectionScore() {
  const score = 94;
  const circumference = 2 * Math.PI * 58;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="glass-card p-6 flex flex-col items-center justify-center glow-border">
      <p className="text-xs font-medium uppercase tracking-wider text-lyrie-text-muted mb-4">
        Protection Score
      </p>
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
          {/* Track */}
          <circle
            cx="64"
            cy="64"
            r="58"
            fill="none"
            stroke="rgba(30,30,74,0.6)"
            strokeWidth="8"
          />
          {/* Score Arc */}
          <circle
            cx="64"
            cy="64"
            r="58"
            fill="none"
            stroke="url(#scoreGradient)"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
          <defs>
            <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#4f46e5" />
              <stop offset="50%" stopColor="#22c55e" />
              <stop offset="100%" stopColor="#06b6d4" />
            </linearGradient>
          </defs>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold text-white stat-value">{score}</span>
          <span className="text-[10px] uppercase tracking-widest text-lyrie-green font-semibold">
            Excellent
          </span>
        </div>
      </div>
      <div className="mt-4 flex items-center gap-2">
        <Lock className="w-3 h-3 text-lyrie-green" />
        <span className="text-xs text-lyrie-green font-medium">All defenses active</span>
      </div>
    </div>
  );
}

/* ---------- Channel Status ---------- */
function ChannelStatus() {
  const channels = [
    { name: "Telegram", status: "active", messages: 1247 },
    { name: "WhatsApp", status: "active", messages: 89 },
    { name: "Discord", status: "standby", messages: 0 },
    { name: "Slack", status: "active", messages: 312 },
    { name: "Web API", status: "active", messages: 4521 },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <MessageSquare className="w-4 h-4 text-lyrie-accent-light" />
        <h3 className="text-sm font-semibold text-white">Active Channels</h3>
      </div>
      <div className="p-4 space-y-2.5">
        {channels.map((ch) => (
          <div key={ch.name} className="flex items-center justify-between py-1.5">
            <div className="flex items-center gap-2.5">
              <div
                className={`w-2 h-2 rounded-full ${
                  ch.status === "active"
                    ? "bg-lyrie-green shadow-glow-green"
                    : "bg-lyrie-text-muted"
                }`}
              />
              <span className="text-sm text-lyrie-text">{ch.name}</span>
            </div>
            <span className="text-xs text-lyrie-text-muted font-mono">
              {ch.messages > 0 ? `${ch.messages.toLocaleString()} msgs` : "Idle"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Fleet Status ---------- */
function FleetStatus() {
  const machines = [
    { name: "Mac #1", role: "Primary", status: "online", cpu: 34 },
    { name: "Mac #2", role: "Desktop", status: "online", cpu: 12 },
    { name: "EPYC", role: "Compute", status: "online", cpu: 67 },
    { name: "Beast", role: "Gateway", status: "online", cpu: 28 },
    { name: "H100-NL", role: "GPU/Trading", status: "online", cpu: 89 },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Server className="w-4 h-4 text-lyrie-cyan" />
        <h3 className="text-sm font-semibold text-white">Fleet Status</h3>
      </div>
      <div className="p-4 space-y-3">
        {machines.map((m) => (
          <div key={m.name} className="space-y-1.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-lyrie-green" />
                <span className="text-xs font-medium text-lyrie-text">{m.name}</span>
                <span className="text-[10px] text-lyrie-text-muted">({m.role})</span>
              </div>
              <span className="text-xs font-mono text-lyrie-text-dim">{m.cpu}% CPU</span>
            </div>
            <div className="w-full h-1.5 rounded-full bg-lyrie-card overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  m.cpu > 80
                    ? "bg-lyrie-red"
                    : m.cpu > 50
                    ? "bg-lyrie-amber"
                    : "bg-lyrie-green"
                }`}
                style={{ width: `${m.cpu}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Model Routing ---------- */
function ModelRouting() {
  const models = [
    { name: "Claude Opus", task: "Strategy", active: true },
    { name: "Claude Haiku", task: "Research", active: true },
    { name: "GPT-5.4 Codex", task: "Code", active: true },
    { name: "MiniMax M2.5", task: "Bulk", active: true },
    { name: "Gemini 3", task: "Creative", active: false },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Cpu className="w-4 h-4 text-lyrie-amber" />
        <h3 className="text-sm font-semibold text-white">Model Routing</h3>
      </div>
      <div className="p-4 space-y-2.5">
        {models.map((m) => (
          <div key={m.name} className="flex items-center justify-between py-1">
            <div className="flex items-center gap-2.5">
              <div
                className={`w-2 h-2 rounded-full ${
                  m.active ? "bg-lyrie-green" : "bg-lyrie-text-muted"
                }`}
              />
              <span className="text-sm text-lyrie-text">{m.name}</span>
            </div>
            <span className="text-[10px] font-medium uppercase tracking-wider text-lyrie-text-muted px-2 py-0.5 rounded bg-lyrie-card">
              {m.task}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Page ---------- */
export default function OverviewPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      {/* Page Title */}
      <div>
        <h2 className="text-2xl font-bold text-white">Command Center</h2>
        <p className="text-sm text-lyrie-text-muted mt-1">
          Real-time overview of your autonomous agent fleet and cyber defenses
        </p>
      </div>

      {/* Stat Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Threats Blocked"
          value="2,847"
          subtitle="Last 24 hours"
          icon={Shield}
          trend={{ value: "12%", positive: true }}
          variant="red"
        />
        <StatCard
          title="Active Agents"
          value={5}
          subtitle="3 autonomous, 2 supervised"
          icon={Bot}
          variant="accent"
        />
        <StatCard
          title="Memory Entries"
          value="14.2K"
          subtitle="98.7% health score"
          icon={Brain}
          trend={{ value: "340", positive: true }}
          variant="cyan"
        />
        <StatCard
          title="Scans Completed"
          value={127}
          subtitle="0 critical findings"
          icon={Radar}
          variant="green"
        />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-6">
          <ThreatFeed limit={5} />
          <ActivityFeed limit={5} />
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          <ProtectionScore />
          <ChannelStatus />
          <ModelRouting />
          <FleetStatus />
        </div>
      </div>
    </div>
  );
}
