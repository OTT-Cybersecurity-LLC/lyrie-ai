#!/usr/bin/env bun
/**
 * lyrie daemon — Continuous operation mode (proactive / heartbeat).
 *
 * Usage:
 *   lyrie daemon [options]
 *
 * Options:
 *   --interval <duration>   Tick interval. Accepts ms numbers or human strings:
 *                           "5m", "30s", "1h". Default: 5m.
 *   --channel <id>          Channel to send alerts to (repeatable). Default: telegram.
 *   --threat-watch          Enable CVE / threat-intel feed monitoring.
 *   --self-heal             Auto-spawn `lyrie hack` on critical findings.
 *   --provider <id>         LLM provider for tick analysis. Default: hermes.
 *   --max-ticks <n>         Stop after N ticks (for bounded / test runs).
 *   --help, -h              Show this help message.
 *
 * Examples:
 *   bun run scripts/daemon.ts --interval 5m --channel telegram --threat-watch
 *   bun run scripts/daemon.ts --threat-watch --self-heal --provider hermes
 *   bun run scripts/daemon.ts --max-ticks 3   # bounded run (CI / smoke test)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { DaemonEngine, type DaemonEngineConfig, type DaemonTickResult } from "../packages/core/src/engine/daemon";

// ─── Arg parsing ─────────────────────────────────────────────────────────────

function parseArgs(argv: string[]): {
  intervalMs: number;
  channels: string[];
  threatWatch: boolean;
  selfHeal: boolean;
  provider: string;
  maxTicks: number;
  help: boolean;
} {
  const args = argv.slice(2); // strip "bun" + script path
  const result = {
    intervalMs: parseDuration("5m"),
    channels: [] as string[],
    threatWatch: false,
    selfHeal: false,
    provider: "hermes",
    maxTicks: 0,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--interval":
        result.intervalMs = parseDuration(args[++i] ?? "5m");
        break;
      case "--channel":
        result.channels.push(args[++i] ?? "telegram");
        break;
      case "--threat-watch":
        result.threatWatch = true;
        break;
      case "--self-heal":
        result.selfHeal = true;
        break;
      case "--provider":
        result.provider = args[++i] ?? "hermes";
        break;
      case "--max-ticks":
        result.maxTicks = parseInt(args[++i] ?? "0", 10);
        break;
      case "--help":
      case "-h":
        result.help = true;
        break;
    }
  }

  // Default channel
  if (result.channels.length === 0) result.channels = ["telegram"];

  return result;
}

/**
 * Parse a human-readable duration string into milliseconds.
 * Accepts: "5m", "30s", "1h", "2h30m", or raw ms as a number string.
 */
function parseDuration(input: string): number {
  if (!input) return 5 * 60_000;

  // Pure number → treat as ms
  if (/^\d+$/.test(input)) return parseInt(input, 10);

  let totalMs = 0;
  const re = /(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(input)) !== null) {
    const val = parseFloat(match[1]);
    const unit = match[2].toLowerCase();
    switch (unit) {
      case "ms": totalMs += val; break;
      case "s":  totalMs += val * 1_000; break;
      case "m":  totalMs += val * 60_000; break;
      case "h":  totalMs += val * 3_600_000; break;
      case "d":  totalMs += val * 86_400_000; break;
    }
  }

  return totalMs > 0 ? totalMs : 5 * 60_000; // fallback to 5m
}

function printHelp(): void {
  console.log(`
lyrie daemon — Continuous proactive operation mode

USAGE
  lyrie daemon [options]

OPTIONS
  --interval <dur>     Tick interval (e.g. 5m, 30s, 1h). Default: 5m
  --channel <id>       Alert channel id (repeatable). Default: telegram
  --threat-watch       Enable CVE / threat-intel feed monitoring
  --self-heal          Auto-spawn \`lyrie hack\` on critical findings
  --provider <id>      LLM provider for tick analysis. Default: hermes
  --max-ticks <n>      Stop after N ticks (0 = unlimited). Default: 0
  --help, -h           Show this help

EXAMPLES
  lyrie daemon --interval 5m --channel telegram --threat-watch
  lyrie daemon --threat-watch --self-heal --provider hermes
  lyrie daemon --max-ticks 3   # bounded smoke-test run
`.trim());
}

// ─── Alert formatting ─────────────────────────────────────────────────────────

function formatTickResult(result: DaemonTickResult, tickNum: number): string {
  const ts = new Date().toLocaleString("en-US", { timeZone: "Asia/Dubai" });
  const icon = result.status === "alert" ? "🚨" : result.status === "action" ? "⚡" : "✅";
  let out = `[${ts}] Tick #${tickNum} ${icon} ${result.status.toUpperCase()}`;
  if (result.message) out += ` — ${result.message}`;
  if (result.findings?.length) {
    out += `\n  Findings (${result.findings.length}):`;
    for (const f of result.findings) {
      out += `\n    [${f.severity.toUpperCase()}] ${f.title} (${f.source})`;
    }
  }
  if (result.actionsTriggered?.length) {
    out += `\n  Actions triggered:`;
    for (const a of result.actionsTriggered) {
      out += `\n    → ${a}`;
    }
  }
  return out;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const opts = parseArgs(process.argv);

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  const config: DaemonEngineConfig = {
    intervalMs: opts.intervalMs,
    threatWatch: opts.threatWatch,
    selfHeal: opts.selfHeal,
    provider: opts.provider,
    channels: opts.channels,
    maxTicksBeforeRest: opts.maxTicks > 0 ? opts.maxTicks : undefined,
  };

  console.log(`
╔══════════════════════════════════════╗
║  🛡  Lyrie Daemon — Proactive Mode  ║
╚══════════════════════════════════════╝
  Interval:     ${formatMs(config.intervalMs)}
  Provider:     ${config.provider}
  Channels:     ${config.channels.join(", ")}
  Threat-watch: ${config.threatWatch ? "✅" : "❌"}
  Self-heal:    ${config.selfHeal ? "✅" : "❌"}
  Max ticks:    ${config.maxTicksBeforeRest ?? "∞"}
  
  Press Ctrl+C to stop.
`);

  const engine = new DaemonEngine();

  engine.on("idle", (r) => {
    console.log(formatTickResult(r, engine.ticksFired()));
  });

  engine.on("alert", (r) => {
    console.error(formatTickResult(r, engine.ticksFired()));
    // In production: send to configured channels via channel adapters.
    // For now: log prominently to stderr so monitoring picks it up.
  });

  engine.on("action", (r) => {
    console.log(formatTickResult(r, engine.ticksFired()));
  });

  // Graceful shutdown on SIGINT / SIGTERM
  const shutdown = async () => {
    console.log("\n⏹  Stopping daemon...");
    await engine.stop();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  try {
    await engine.start(config);
    console.log(`\n✅ Daemon stopped cleanly after ${engine.ticksFired()} tick(s).`);
  } catch (err) {
    console.error("💥 Daemon crashed:", err);
    process.exit(1);
  }
}

function formatMs(ms: number): string {
  if (ms >= 3_600_000) return `${(ms / 3_600_000).toFixed(1)}h`;
  if (ms >= 60_000)    return `${(ms / 60_000).toFixed(1)}m`;
  if (ms >= 1_000)     return `${(ms / 1_000).toFixed(1)}s`;
  return `${ms}ms`;
}

main();
