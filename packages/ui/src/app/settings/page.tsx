// lyrie-shield: ignore-file (security-feature UI describes attack types by name; this is product copy, not an injection vector)
import {
  Settings,
  Key,
  MessageSquare,
  Cpu,
  Shield,
  Eye,
  EyeOff,
  Save,
  RefreshCw,
  Check,
  AlertTriangle,
  Plug,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* ---------- API Keys ---------- */
function APIKeyConfig() {
  const keys = [
    { name: "Anthropic", env: "ANTHROPIC_API_KEY", configured: true },
    { name: "OpenAI", env: "OPENAI_API_KEY", configured: true },
    { name: "Google AI", env: "GOOGLE_AI_API_KEY", configured: true },
    { name: "Bybit", env: "BYBIT_API_KEY", configured: true },
    { name: "Cloudflare", env: "CLOUDFLARE_API_TOKEN", configured: true },
    { name: "Brave Search", env: "BRAVE_API_KEY", configured: false },
    { name: "Perplexity", env: "PERPLEXITY_API_KEY", configured: false },
    { name: "Tavily", env: "TAVILY_API_KEY", configured: false },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Key className="w-4 h-4 text-lyrie-amber" />
          <h3 className="text-sm font-semibold text-white">API Keys</h3>
        </div>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-lyrie-accent/15 text-lyrie-accent-light text-xs font-medium hover:bg-lyrie-accent/25 transition-colors border border-lyrie-accent/20">
          <Save className="w-3 h-3" />
          Save All
        </button>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {keys.map((k) => (
          <div key={k.name} className="px-5 py-3.5 flex items-center gap-4 hover:bg-lyrie-card/30 transition-colors">
            <div className={cn("p-1.5 rounded-md", k.configured ? "bg-lyrie-green/10" : "bg-lyrie-card")}>
              {k.configured ? (
                <Check className="w-3.5 h-3.5 text-lyrie-green" />
              ) : (
                <AlertTriangle className="w-3.5 h-3.5 text-lyrie-text-muted" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-lyrie-text font-medium">{k.name}</p>
              <p className="text-[10px] font-mono text-lyrie-text-muted">{k.env}</p>
            </div>
            <div className="flex items-center gap-2">
              {k.configured ? (
                <span className="text-xs font-mono text-lyrie-text-muted">••••••••••••</span>
              ) : (
                <input
                  type="password"
                  placeholder="Enter key..."
                  className="bg-lyrie-bg/50 border border-lyrie-border rounded px-2 py-1 text-xs text-lyrie-text w-40 focus:outline-none focus:border-lyrie-accent/50"
                />
              )}
              <button className="p-1 rounded hover:bg-lyrie-card transition-colors">
                <EyeOff className="w-3 h-3 text-lyrie-text-muted" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Channel Setup ---------- */
function ChannelSetup() {
  const channels = [
    { name: "Telegram", status: "connected", id: "@Lyrie_ai_bot" },
    { name: "WhatsApp", status: "connected", id: "+1-XXX-XXX-XXXX" },
    { name: "Discord", status: "disconnected", id: "—" },
    { name: "Slack", status: "connected", id: "#lyrie-agent" },
    { name: "Web API", status: "connected", id: "api.lyrie.ai" },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <MessageSquare className="w-4 h-4 text-lyrie-accent-light" />
        <h3 className="text-sm font-semibold text-white">Channel Setup</h3>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {channels.map((ch) => (
          <div key={ch.name} className="px-5 py-3.5 flex items-center justify-between hover:bg-lyrie-card/30 transition-colors">
            <div className="flex items-center gap-3">
              <Plug className={cn("w-4 h-4", ch.status === "connected" ? "text-lyrie-green" : "text-lyrie-text-muted")} />
              <div>
                <p className="text-sm text-lyrie-text font-medium">{ch.name}</p>
                <p className="text-[10px] font-mono text-lyrie-text-muted">{ch.id}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "text-[10px] font-semibold uppercase px-2 py-1 rounded-full",
                  ch.status === "connected"
                    ? "bg-lyrie-green/10 text-lyrie-green"
                    : "bg-lyrie-red/10 text-lyrie-red"
                )}
              >
                {ch.status}
              </span>
              <button className="p-1.5 rounded-lg hover:bg-lyrie-card transition-colors">
                <RefreshCw className="w-3 h-3 text-lyrie-text-muted" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Model Preferences ---------- */
function ModelPreferences() {
  const models = [
    { task: "Strategy", model: "Claude Opus", cost: "$15/MTok", priority: 1 },
    { task: "Research", model: "Claude Haiku", cost: "$0.25/MTok", priority: 1 },
    { task: "Code", model: "GPT-5.4 Codex", cost: "$2/MTok", priority: 1 },
    { task: "Bulk/Fast", model: "MiniMax M2.5-HS", cost: "$0.08/MTok", priority: 1 },
    { task: "Creative", model: "Gemini 3", cost: "$1/MTok", priority: 2 },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Cpu className="w-4 h-4 text-lyrie-cyan" />
        <h3 className="text-sm font-semibold text-white">Model Preferences</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-lyrie-border text-lyrie-text-muted">
              <th className="px-5 py-2.5 text-left font-medium">Task</th>
              <th className="px-3 py-2.5 text-left font-medium">Model</th>
              <th className="px-3 py-2.5 text-left font-medium">Cost</th>
              <th className="px-5 py-2.5 text-right font-medium">Priority</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-lyrie-border/50">
            {models.map((m) => (
              <tr key={m.task} className="hover:bg-lyrie-card/30 transition-colors">
                <td className="px-5 py-2.5 text-lyrie-text font-medium">{m.task}</td>
                <td className="px-3 py-2.5 text-lyrie-accent-light font-mono">{m.model}</td>
                <td className="px-3 py-2.5 text-lyrie-text-dim font-mono">{m.cost}</td>
                <td className="px-5 py-2.5 text-right">
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-lyrie-accent/10 text-lyrie-accent-light">
                    P{m.priority}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-5 py-3 border-t border-lyrie-border">
        <p className="text-[10px] text-lyrie-text-muted">
          Daily budget target: <span className="text-lyrie-amber font-semibold">$50.00</span> · Current spend: <span className="text-lyrie-green font-semibold">$3.24</span>
        </p>
      </div>
    </div>
  );
}

/* ---------- Shield Config ---------- */
function ShieldConfig() {
  const settings = [
    { name: "WAF Protection", description: "Web Application Firewall rules", enabled: true },
    { name: "Rogue AI Detection", description: "Monitor for prompt injection & jailbreak", enabled: true },
    { name: "DDoS Mitigation", description: "Automatic traffic flood protection", enabled: true },
    { name: "Agent Sandboxing", description: "Isolate agent execution environments", enabled: true },
    { name: "Output Validation", description: "Verify agent outputs before delivery", enabled: true },
    { name: "Data Exfiltration Guard", description: "Block unauthorized data transfers", enabled: true },
    { name: "Auto-Quarantine", description: "Auto-isolate compromised agents", enabled: false },
  ];

  return (
    <div className="glass-card overflow-hidden">
      <div className="px-5 py-4 border-b border-lyrie-border flex items-center gap-2">
        <Shield className="w-4 h-4 text-lyrie-red" />
        <h3 className="text-sm font-semibold text-white">Shield Configuration</h3>
      </div>
      <div className="divide-y divide-lyrie-border/50">
        {settings.map((s) => (
          <div key={s.name} className="px-5 py-3.5 flex items-center justify-between hover:bg-lyrie-card/30 transition-colors">
            <div>
              <p className="text-sm text-lyrie-text font-medium">{s.name}</p>
              <p className="text-[10px] text-lyrie-text-muted">{s.description}</p>
            </div>
            {/* Toggle */}
            <div className={cn(
              "w-10 h-5 rounded-full flex items-center px-0.5 cursor-pointer transition-colors",
              s.enabled ? "bg-lyrie-green" : "bg-lyrie-card border border-lyrie-border"
            )}>
              <div className={cn(
                "w-4 h-4 rounded-full bg-white shadow-sm transition-transform",
                s.enabled ? "translate-x-5" : "translate-x-0"
              )} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- Page ---------- */
export default function SettingsPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-3">
          <Settings className="w-7 h-7 text-lyrie-text-dim" />
          Settings
        </h2>
        <p className="text-sm text-lyrie-text-muted mt-1">
          Configure API keys, channels, models, and security settings
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <APIKeyConfig />
        <ChannelSetup />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ModelPreferences />
        <ShieldConfig />
      </div>
    </div>
  );
}
