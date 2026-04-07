"use client";

import { Shield, Bell, Search, User, ChevronDown } from "lucide-react";

export function Header() {
  return (
    <header className="h-16 border-b border-lyrie-border bg-lyrie-surface/80 backdrop-blur-md flex items-center justify-between px-6 shrink-0">
      {/* Search */}
      <div className="flex items-center gap-3 flex-1 max-w-md">
        <div className="relative w-full">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-lyrie-text-muted" />
          <input
            type="text"
            placeholder="Search agents, memory, threats..."
            className="w-full bg-lyrie-card/50 border border-lyrie-border rounded-lg pl-10 pr-4 py-2 text-sm text-lyrie-text placeholder:text-lyrie-text-muted focus:outline-none focus:border-lyrie-accent/50 focus:shadow-glow transition-all"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-lyrie-text-muted bg-lyrie-bg px-1.5 py-0.5 rounded border border-lyrie-border font-mono">
            ⌘K
          </kbd>
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* Shield Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-lyrie-green/10 border border-lyrie-green/20">
          <Shield className="w-4 h-4 text-lyrie-green" />
          <span className="text-xs font-semibold text-lyrie-green">PROTECTED</span>
          <div className="w-1.5 h-1.5 rounded-full bg-lyrie-green animate-pulse-slow" />
        </div>

        {/* Notifications */}
        <button className="relative p-2 rounded-lg hover:bg-lyrie-card/50 transition-colors">
          <Bell className="w-5 h-5 text-lyrie-text-dim" />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-lyrie-red" />
        </button>

        {/* Profile */}
        <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-lyrie-card/50 transition-colors">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-lyrie-accent to-lyrie-cyan flex items-center justify-center">
            <User className="w-3.5 h-3.5 text-white" />
          </div>
          <span className="text-sm font-medium text-lyrie-text-dim">Admin</span>
          <ChevronDown className="w-3 h-3 text-lyrie-text-muted" />
        </button>
      </div>
    </header>
  );
}
