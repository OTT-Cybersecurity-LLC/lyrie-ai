"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Shield,
  LayoutDashboard,
  Bot,
  Brain,
  Settings,
  Zap,
  Activity,
} from "lucide-react";

const navItems = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/shield", label: "Shield", icon: Shield },
  { href: "/agents", label: "Agents", icon: Bot },
  { href: "/memory", label: "Memory", icon: Brain },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-lyrie-surface border-r border-lyrie-border flex flex-col shrink-0">
      {/* Logo */}
      <div className="p-6 border-b border-lyrie-border">
        <div className="flex items-center gap-3">
          <div className="relative w-10 h-10 rounded-xl bg-gradient-to-br from-lyrie-accent to-lyrie-cyan flex items-center justify-center shadow-glow">
            <Shield className="w-5 h-5 text-white" />
            <div className="absolute -top-0.5 -right-0.5 w-3 h-3 bg-lyrie-green rounded-full border-2 border-lyrie-surface" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">
              Lyrie<span className="text-lyrie-accent">.ai</span>
            </h1>
            <p className="text-[10px] uppercase tracking-[0.2em] text-lyrie-text-muted font-medium">
              Agent Platform
            </p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
                active
                  ? "bg-lyrie-accent/15 text-lyrie-accent-glow border border-lyrie-accent/20 shadow-glow"
                  : "text-lyrie-text-dim hover:text-lyrie-text hover:bg-lyrie-card/50"
              )}
            >
              <Icon className={cn("w-4 h-4", active && "text-lyrie-accent-light")} />
              {label}
              {active && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-lyrie-accent animate-pulse-slow" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* System Status */}
      <div className="p-4 border-t border-lyrie-border">
        <div className="glass-card p-3 space-y-2">
          <div className="flex items-center gap-2 text-xs font-medium text-lyrie-text-dim">
            <Activity className="w-3 h-3 text-lyrie-green" />
            System Status
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-lyrie-green shadow-glow-green animate-pulse-slow" />
            <span className="text-xs text-lyrie-green font-medium">All Systems Operational</span>
          </div>
          <div className="flex items-center gap-2">
            <Zap className="w-3 h-3 text-lyrie-amber" />
            <span className="text-xs text-lyrie-text-muted">5 agents active</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
