import { Bot, Zap, Brain, MessageSquare, GitBranch, Search } from "lucide-react";
import { cn } from "@/lib/utils";

interface ActivityEntry {
  id: string;
  agent: string;
  action: string;
  detail: string;
  time: string;
  icon: "bot" | "zap" | "brain" | "message" | "git" | "search";
}

const activities: ActivityEntry[] = [
  {
    id: "a1",
    agent: "Scout",
    action: "Research completed",
    detail: "Scanned 47 sources for competitive intel on Lyrie.ai",
    time: "1 min ago",
    icon: "search",
  },
  {
    id: "a2",
    agent: "Coder",
    action: "PR opened",
    detail: "feat: add rogue AI detection module — #142",
    time: "4 min ago",
    icon: "git",
  },
  {
    id: "a3",
    agent: "Brain",
    action: "Strategy update",
    detail: "Model routing optimized — 23% cost reduction",
    time: "12 min ago",
    icon: "brain",
  },
  {
    id: "a4",
    agent: "Creative",
    action: "Content generated",
    detail: "Generated 3 social media assets for launch",
    time: "18 min ago",
    icon: "zap",
  },
  {
    id: "a5",
    agent: "Muscle",
    action: "Batch complete",
    detail: "Processed 1,247 memory entries for dedup",
    time: "25 min ago",
    icon: "bot",
  },
  {
    id: "a6",
    agent: "Scout",
    action: "Alert",
    detail: "New competitor detected: CyberPilot v2 launch",
    time: "33 min ago",
    icon: "message",
  },
];

const iconMap = {
  bot: Bot,
  zap: Zap,
  brain: Brain,
  message: MessageSquare,
  git: GitBranch,
  search: Search,
};

const agentColors: Record<string, string> = {
  Scout: "text-lyrie-cyan",
  Coder: "text-lyrie-green",
  Brain: "text-lyrie-accent-glow",
  Creative: "text-lyrie-amber",
  Muscle: "text-lyrie-red",
};

export function ActivityFeed({ limit = 6 }: { limit?: number }) {
  const items = activities.slice(0, limit);

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-lyrie-accent-light" />
          <h3 className="text-sm font-semibold text-white">Agent Activity</h3>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-lyrie-text-muted font-medium">
          Last 1 hour
        </span>
      </div>

      <div className="divide-y divide-lyrie-border/50">
        {items.map((item) => {
          const Icon = iconMap[item.icon];
          return (
            <div
              key={item.id}
              className="px-5 py-3.5 hover:bg-lyrie-card/30 transition-colors flex items-start gap-3"
            >
              <div className="p-1.5 rounded-md bg-lyrie-card/50 mt-0.5">
                <Icon className="w-3.5 h-3.5 text-lyrie-text-dim" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className={cn("text-xs font-semibold", agentColors[item.agent] || "text-lyrie-text")}>
                    {item.agent}
                  </span>
                  <span className="text-[10px] text-lyrie-text-muted">•</span>
                  <span className="text-[10px] text-lyrie-text-muted font-medium">
                    {item.action}
                  </span>
                </div>
                <p className="text-xs text-lyrie-text-dim leading-relaxed truncate">
                  {item.detail}
                </p>
              </div>
              <span className="text-[10px] text-lyrie-text-muted whitespace-nowrap mt-1">
                {item.time}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
