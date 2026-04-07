import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: { value: string; positive: boolean };
  variant?: "default" | "accent" | "green" | "red" | "amber" | "cyan";
  className?: string;
}

const variantStyles = {
  default: {
    icon: "text-lyrie-text-dim bg-lyrie-card",
    value: "text-white",
  },
  accent: {
    icon: "text-lyrie-accent-light bg-lyrie-accent/10",
    value: "text-lyrie-accent-glow",
  },
  green: {
    icon: "text-lyrie-green bg-lyrie-green/10",
    value: "text-lyrie-green",
  },
  red: {
    icon: "text-lyrie-red bg-lyrie-red/10",
    value: "text-lyrie-red",
  },
  amber: {
    icon: "text-lyrie-amber bg-lyrie-amber/10",
    value: "text-lyrie-amber",
  },
  cyan: {
    icon: "text-lyrie-cyan bg-lyrie-cyan/10",
    value: "text-lyrie-cyan",
  },
};

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = "default",
  className,
}: StatCardProps) {
  const styles = variantStyles[variant];
  return (
    <div className={cn("glass-card p-5 hover:glow-border transition-all duration-300 group", className)}>
      <div className="flex items-start justify-between">
        <div className="space-y-3">
          <p className="text-xs font-medium uppercase tracking-wider text-lyrie-text-muted">
            {title}
          </p>
          <div className="flex items-baseline gap-2">
            <span className={cn("text-3xl font-bold stat-value", styles.value)}>
              {value}
            </span>
            {trend && (
              <span
                className={cn(
                  "text-xs font-semibold px-1.5 py-0.5 rounded",
                  trend.positive
                    ? "text-lyrie-green bg-lyrie-green/10"
                    : "text-lyrie-red bg-lyrie-red/10"
                )}
              >
                {trend.positive ? "↑" : "↓"} {trend.value}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="text-xs text-lyrie-text-muted">{subtitle}</p>
          )}
        </div>
        <div className={cn("p-2.5 rounded-lg", styles.icon)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}
