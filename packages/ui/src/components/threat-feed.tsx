import { Shield, AlertTriangle, XCircle, CheckCircle, Clock } from "lucide-react";
import { cn } from "@/lib/utils";

interface ThreatEntry {
  id: string;
  type: "blocked" | "detected" | "resolved" | "scanning";
  source: string;
  description: string;
  time: string;
  severity: "critical" | "high" | "medium" | "low";
}

const sampleThreats: ThreatEntry[] = [
  {
    id: "t1",
    type: "blocked",
    source: "WAF",
    description: "SQL injection attempt from 45.227.xx.xx blocked",
    time: "2 min ago",
    severity: "critical",
  },
  {
    id: "t2",
    type: "detected",
    source: "Rogue AI Scanner",
    description: "Suspicious prompt injection pattern in agent-7 input",
    time: "8 min ago",
    severity: "high",
  },
  {
    id: "t3",
    type: "resolved",
    source: "Shield",
    description: "DDoS mitigation completed — 12K requests blocked",
    time: "15 min ago",
    severity: "medium",
  },
  {
    id: "t4",
    type: "scanning",
    source: "Device Monitor",
    description: "Scheduled deep scan on fleet node Mac-2",
    time: "22 min ago",
    severity: "low",
  },
  {
    id: "t5",
    type: "blocked",
    source: "WAF",
    description: "XSS attempt on /api/agents endpoint neutralized",
    time: "31 min ago",
    severity: "high",
  },
  {
    id: "t6",
    type: "detected",
    source: "Anomaly Engine",
    description: "Unusual outbound traffic spike from EPYC node",
    time: "45 min ago",
    severity: "medium",
  },
];

const typeConfig = {
  blocked: { icon: XCircle, color: "text-lyrie-red", bg: "bg-lyrie-red/10" },
  detected: { icon: AlertTriangle, color: "text-lyrie-amber", bg: "bg-lyrie-amber/10" },
  resolved: { icon: CheckCircle, color: "text-lyrie-green", bg: "bg-lyrie-green/10" },
  scanning: { icon: Clock, color: "text-lyrie-cyan", bg: "bg-lyrie-cyan/10" },
};

const severityColor = {
  critical: "bg-lyrie-red text-white",
  high: "bg-lyrie-amber/20 text-lyrie-amber",
  medium: "bg-lyrie-accent/20 text-lyrie-accent-light",
  low: "bg-lyrie-card text-lyrie-text-muted",
};

export function ThreatFeed({ limit = 6 }: { limit?: number }) {
  const threats = sampleThreats.slice(0, limit);

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-lyrie-red" />
          <h3 className="text-sm font-semibold text-white">Threat Feed</h3>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-lyrie-red animate-pulse" />
          <span className="text-[10px] uppercase tracking-wider text-lyrie-text-muted font-medium">Live</span>
        </div>
      </div>

      <div className="divide-y divide-lyrie-border/50">
        {threats.map((threat) => {
          const cfg = typeConfig[threat.type];
          const Icon = cfg.icon;
          return (
            <div
              key={threat.id}
              className="px-5 py-3.5 hover:bg-lyrie-card/30 transition-colors flex items-start gap-3"
            >
              <div className={cn("p-1.5 rounded-md mt-0.5", cfg.bg)}>
                <Icon className={cn("w-3.5 h-3.5", cfg.color)} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-lyrie-text-muted">
                    {threat.source}
                  </span>
                  <span className={cn("text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-full", severityColor[threat.severity])}>
                    {threat.severity}
                  </span>
                </div>
                <p className="text-xs text-lyrie-text leading-relaxed truncate">
                  {threat.description}
                </p>
              </div>
              <span className="text-[10px] text-lyrie-text-muted whitespace-nowrap mt-1">
                {threat.time}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
