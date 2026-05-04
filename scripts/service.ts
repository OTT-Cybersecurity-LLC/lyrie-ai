#!/usr/bin/env bun
/**
 * lyrie service — install/manage Lyrie as a persistent background daemon
 *
 * Usage:
 *   lyrie service install    # install as background service
 *   lyrie service uninstall  # remove the service
 *   lyrie service start      # start (if stopped)
 *   lyrie service stop       # stop (if running)
 *   lyrie service restart    # restart
 *   lyrie service status     # is it running? PID? uptime?
 *   lyrie service logs       # tail the service logs
 *   lyrie service logs -n 100
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { join } from "path";
import { getServiceManager } from "../packages/core/src/service/index";
import type { ServiceConfig } from "../packages/core/src/service/types";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function usage(): void {
  console.log(`
  lyrie service <command> [options]

  Commands:
    install      Install Lyrie as a background daemon (launchd on macOS, systemd on Linux)
    uninstall    Remove the installed daemon
    start        Start the daemon (if stopped)
    stop         Stop the running daemon
    restart      Restart the daemon
    status       Show daemon status (running, PID, uptime)
    logs         Tail daemon logs (-n <lines>, default 50)

  Options for install:
    --label <label>        Service label (default: ai.lyrie.daemon)
    --channel <id>         Channel to pass to daemon (default: telegram)
    --interval <duration>  Daemon tick interval (default: 5m)
    --no-keep-alive        Don't restart on exit
    --no-run-at-load       Don't start automatically on login/boot

  Examples:
    lyrie service install
    lyrie service install --channel telegram --interval 5m
    lyrie service status
    lyrie service logs -n 100
`);
}

function parseInstallArgs(argv: string[]): {
  label: string;
  channel: string;
  interval: string;
  keepAlive: boolean;
  runAtLoad: boolean;
} {
  const result = {
    label: "ai.lyrie.daemon",
    channel: "telegram",
    interval: "5m",
    keepAlive: true,
    runAtLoad: true,
  };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--label":
        result.label = argv[++i] ?? result.label;
        break;
      case "--channel":
        result.channel = argv[++i] ?? result.channel;
        break;
      case "--interval":
        result.interval = argv[++i] ?? result.interval;
        break;
      case "--no-keep-alive":
        result.keepAlive = false;
        break;
      case "--no-run-at-load":
        result.runAtLoad = false;
        break;
    }
  }
  return result;
}

/** Find the bun binary (or node as fallback). */
function findBun(): string {
  // On macOS with bun installed, Bun.which is the most reliable
  if (typeof (globalThis as any).Bun !== "undefined") {
    const found = (globalThis as any).Bun.which("bun");
    if (found) return found;
  }
  // Fallback: use the path that launched this process
  return process.execPath;
}

/** Absolute path of this repo. */
function repoRoot(): string {
  // __dirname is scripts/, so parent is repo root
  return join(import.meta.dir, "..");
}

// ─── Main ────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const command = args[0];
const rest = args.slice(1);

if (!command || command === "--help" || command === "-h") {
  usage();
  process.exit(0);
}

const manager = getServiceManager();

switch (command) {
  case "install": {
    const opts = parseInstallArgs(rest);
    const bunBin = findBun();
    const daemonScript = join(repoRoot(), "scripts", "daemon.ts");

    const config: ServiceConfig = {
      label: opts.label,
      program: bunBin,
      args: ["run", daemonScript, "--channel", opts.channel, "--interval", opts.interval],
      logPath: join(process.env.HOME ?? "~", ".lyrie", "logs", "daemon.log"),
      runAtLoad: opts.runAtLoad,
      keepAlive: opts.keepAlive,
    };

    await manager.install(config);
    break;
  }

  case "uninstall":
    await manager.uninstall();
    break;

  case "start":
    await manager.start();
    break;

  case "stop":
    await manager.stop();
    break;

  case "restart":
    await manager.restart();
    break;

  case "status": {
    const s = await manager.status();
    if (!s.installed) {
      console.log(`⚠️  Lyrie daemon is not installed.`);
      console.log(`   Run: lyrie service install`);
    } else if (s.running) {
      console.log(`✅ Lyrie daemon is running.`);
      if (s.pid) console.log(`   PID: ${s.pid}`);
    } else {
      console.log(`⏹  Lyrie daemon is installed but not running.`);
      console.log(`   Run: lyrie service start`);
    }
    break;
  }

  case "logs": {
    const nFlag = rest.findIndex((a) => a === "-n" || a === "--lines");
    const lines = nFlag >= 0 ? parseInt(rest[nFlag + 1] ?? "50", 10) : 50;
    const output = await manager.logs(lines);
    console.log(output);
    break;
  }

  default:
    console.error(`❌ Unknown command: ${command}`);
    usage();
    process.exit(1);
}
