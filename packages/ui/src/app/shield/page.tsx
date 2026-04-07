import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Eye,
  Radar,
  Server,
  Smartphone,
  Laptop,
  Globe,
  Brain,
  Clock,
} from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { ThreatFeed } from "@/components/threat-feed";
import { cn } from "@/lib/utils";

/* ---------- WAF Status ---------- */
function WAFStatus() {
  const rules = [
    { name: "SQL Injection", blocked: 847, status: "active" },
    { name: "XSS Prevention", blocked: 312, status: "active" },
    { name: "DDoS Mitigation", blocked: 1204, status: "active" },
    { name: "Bot Detection", blocked: 2156, status: "active" },
    { name: "Rate Limiting", blocked: 89, status: "active" },
    { name: "Geo-blocking", blocked: 43, status: "active" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-lyrie-accent-light" />
          <h3 className="text-sm font-semibold text-white">WAF Rules</h3>
        </div>
        <span className="text-[10px] px-2 py-1 rounded-full bg-lyrie-green/10 text-lyrie-green font-semibold uppercase">
          All Active
        </span>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {rules.map((rule) => (
          <div key={rule.name} className="px-5 py-3 flex items-center justify-between hover:bg-lyrie-card/30 transition-colors">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-3.5 h-3.5 text-lyrie-green" />
              <span className="text-sm text-lyrie-text">{rule.name}</span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-lyrie-red">{rule.blocked.toLocaleString()} blocked</span>
              <div className="w-2 h-2 rounded-full bg-lyrie-green animate-pulse-slow" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Device Protection ---------- */
function DeviceProtection() {
  const devices = [
    { name: "Mac #1 — Primary", type: "laptop", status: "protected", lastScan: "5 min ago" },
    { name: "Mac #2 — Desktop", type: "laptop", status: "protected", lastScan: "12 min ago" },
    { name: "EPYC — Compute", type: "server", status: "protected", lastScan: "3 min ago" },
    { name: "Beast — Gateway", type: "server", status: "warning", lastScan: "2 hr ago" },
    { name: "H100-NL — GPU", type: "server", status: "protected", lastScan: "8 min ago" },
    { name: "iPhone 16 Pro", type: "phone", status: "protected", lastScan: "1 hr ago" },
  ];

  const typeIcon = { laptop: Laptop, server: Server, phone: Smartphone };

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Shield className="w-4 h-4 text-lyrie-green" />
        <h3 className="text-sm font-semibold text-white">Device Protection</h3>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {devices.map((d) => {
          const Icon = typeIcon[d.type as keyof typeof typeIcon] || Server;
          return (
            <div key={d.name} className="px-5 py-3.5 flex items-center justify-between hover:bg-lyrie-card/30 transition-colors">
              <div className="flex items-center gap-3">
                <Icon className="w-4 h-4 text-lyrie-text-dim" />
                <div>
                  <p className="text-sm text-lyrie-text">{d.name}</p>
                  <p className="text-[10px] text-lyrie-text-muted">Last scan: {d.lastScan}</p>
                </div>
              </div>
              <span
                className={cn(
                  "text-[10px] font-semibold uppercase px-2 py-1 rounded-full",
                  d.status === "protected"
                    ? "bg-lyrie-green/10 text-lyrie-green"
                    : "bg-lyrie-amber/10 text-lyrie-amber"
                )}
              >
                {d.status}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Rogue AI Detection ---------- */
function RogueAILog() {
  const logs = [
    { time: "16:02", event: "Prompt injection scan completed", result: "clean", model: "Claude Opus" },
    { time: "15:47", event: "Suspicious token pattern detected in input", result: "blocked", model: "GPT-5.4" },
    { time: "15:31", event: "Agent output validation passed", result: "clean", model: "Haiku" },
    { time: "15:12", event: "Jailbreak attempt intercepted", result: "blocked", model: "External API" },
    { time: "14:55", event: "Model alignment check passed", result: "clean", model: "MiniMax" },
    { time: "14:30", event: "Data exfiltration pattern detected", result: "blocked", model: "Unknown" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-lyrie-red" />
          <h3 className="text-sm font-semibold text-white">Rogue AI Detection</h3>
        </div>
        <div className="flex items-center gap-1.5">
          <Eye className="w-3 h-3 text-lyrie-amber" />
          <span className="text-[10px] uppercase tracking-wider text-lyrie-amber font-medium">Watching</span>
        </div>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {logs.map((log, i) => (
          <div key={i} className="px-5 py-3 flex items-center gap-3 hover:bg-lyrie-card/30 transition-colors">
            <span className="text-[10px] font-mono text-lyrie-text-muted w-10">{log.time}</span>
            <div
              className={cn(
                "p-1 rounded",
                log.result === "blocked" ? "bg-lyrie-red/10" : "bg-lyrie-green/10"
              )}
            >
              {log.result === "blocked" ? (
                <XCircle className="w-3 h-3 text-lyrie-red" />
              ) : (
                <CheckCircle className="w-3 h-3 text-lyrie-green" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-lyrie-text truncate">{log.event}</p>
            </div>
            <span className="text-[10px] font-mono text-lyrie-text-muted px-1.5 py-0.5 bg-lyrie-card rounded">
              {log.model}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Scan History ---------- */
function ScanHistory() {
  const scans = [
    { type: "Full System", started: "15:30", duration: "4m 12s", findings: 0, status: "passed" },
    { type: "Network Audit", started: "14:00", duration: "2m 45s", findings: 1, status: "warning" },
    { type: "Agent Integrity", started: "12:00", duration: "1m 30s", findings: 0, status: "passed" },
    { type: "Memory Audit", started: "10:00", duration: "3m 22s", findings: 0, status: "passed" },
    { type: "Port Scan", started: "08:00", duration: "5m 10s", findings: 2, status: "warning" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Clock className="w-4 h-4 text-lyrie-cyan" />
        <h3 className="text-sm font-semibold text-white">Scan History</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-lyrie-border text-lyrie-text-muted">
              <th className="px-5 py-2.5 text-left font-medium">Type</th>
              <th className="px-3 py-2.5 text-left font-medium">Started</th>
              <th className="px-3 py-2.5 text-left font-medium">Duration</th>
              <th className="px-3 py-2.5 text-left font-medium">Findings</th>
              <th className="px-5 py-2.5 text-right font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-lyrie-border/50">
            {scans.map((s, i) => (
              <tr key={i} className="hover:bg-lyrie-card/30 transition-colors">
                <td className="px-5 py-2.5 text-lyrie-text font-medium">{s.type}</td>
                <td className="px-3 py-2.5 text-lyrie-text-dim font-mono">{s.started}</td>
                <td className="px-3 py-2.5 text-lyrie-text-dim font-mono">{s.duration}</td>
                <td className="px-3 py-2.5">
                  <span className={s.findings > 0 ? "text-lyrie-amber" : "text-lyrie-green"}>
                    {s.findings}
                  </span>
                </td>
                <td className="px-5 py-2.5 text-right">
                  <span
                    className={cn(
                      "text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full",
                      s.status === "passed"
                        ? "bg-lyrie-green/10 text-lyrie-green"
                        : "bg-lyrie-amber/10 text-lyrie-amber"
                    )}
                  >
                    {s.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Page ---------- */
export default function ShieldPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Shield className="w-7 h-7 text-lyrie-red" />
          Shield Dashboard
        </h2>
        <p className="text-sm text-lyrie-text-muted mt-1">
          Real-time cyber defense monitoring and threat intelligence
        </p>
      </div>

      {/* Stat Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Threats Blocked" value="4,651" subtitle="All time" icon={XCircle} variant="red" trend={{ value: "18%", positive: true }} />
        <StatCard title="WAF Rules Active" value={6} subtitle="0 disabled" icon={Globe} variant="green" />
        <StatCard title="Rogue AI Detections" value={3} subtitle="Last 24h" icon={Brain} variant="amber" />
        <StatCard title="Uptime" value="99.97%" subtitle="Last 30 days" icon={Radar} variant="cyan" />
      </div>

      {/* Two Column */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatFeed limit={6} />
        <RogueAILog />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <WAFStatus />
        <DeviceProtection />
      </div>

      <ScanHistory />
    </div>
  );
}
