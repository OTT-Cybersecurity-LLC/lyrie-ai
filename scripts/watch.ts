#!/usr/bin/env bun
/**
 * `lyrie watch <domain>` — continuous exposure monitoring (design stub).
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * STATUS: the TS engine (packages/core/src/watch/*) + tests are the actual
 * deliverable for this feature and are fully wired and tested. THIS SCRIPT
 * is a CLI-level design stub only — it drives `WatchEngine` directly so you
 * can run it locally, but it is NOT yet wired into the Python `omega`
 * command-dispatch layer the way `lyrie scan`/`lyrie hack` are (see
 * scripts/scan.ts, scripts/hack.ts for that wiring's shape). Doing that
 * wiring is explicitly out of scope for this build (prompt contract, item 5).
 *
 * Usage:
 *   bun run scripts/watch.ts <domain> [domain2 ...]
 *   bun run scripts/watch.ts example.com --interval 300000 --once
 *
 *   domain             one or more domains to monitor
 *   --interval <ms>    tick interval in milliseconds (default: 15 minutes)
 *   --once              run exactly one tick and exit (useful for cron)
 *   --json              emit each tick's findings as JSON lines to stdout
 */

import { WatchEngine } from "../packages/core/src/watch";
import type { DaemonTickResult } from "../packages/core/src/engine/daemon";

interface Args {
  domains: string[];
  intervalMs: number;
  once: boolean;
  json: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { domains: [], intervalMs: 15 * 60_000, once: false, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-h":
      case "--help":
        out.help = true;
        break;
      case "--interval":
        out.intervalMs = Number(argv[++i] ?? String(out.intervalMs));
        break;
      case "--once":
        out.once = true;
        break;
      case "--json":
        out.json = true;
        break;
      default:
        if (!a.startsWith("--")) out.domains.push(a);
        break;
    }
  }
  return out;
}

function printHelp(): void {
  console.log(`lyrie watch <domain> [domain2 ...] [options]

  Continuous exposure monitoring — diffs security posture between scheduled
  probes and only reports what changed. Design-stub CLI over WatchEngine
  (packages/core/src/watch/engine.ts); not yet wired into the omega dispatch
  layer (see this file's header comment).

  --interval <ms>   tick interval in milliseconds (default: 900000 = 15 min)
  --once            run exactly one tick and exit (good for cron)
  --json            emit each tick's findings as JSON lines to stdout

  Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
`);
}

function printResult(result: DaemonTickResult, json: boolean): void {
  if (json) {
    process.stdout.write(JSON.stringify(result) + "\n");
    return;
  }
  if (result.status === "idle") {
    console.log(`[watch] idle — no posture changes detected`);
    return;
  }
  console.log(`[watch] ${result.status.toUpperCase()} — ${result.message ?? ""}`);
  for (const f of result.findings ?? []) {
    console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.title}`);
    console.log(`              ${f.description}`);
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args.domains.length === 0) {
    printHelp();
    process.exit(args.help ? 0 : 2);
  }

  const engine = new WatchEngine();
  engine.on("alert", (r) => printResult(r, args.json));
  engine.on("action", (r) => printResult(r, args.json));
  engine.on("idle", (r) => printResult(r, args.json));

  await engine.start({
    domains: args.domains,
    intervalMs: args.intervalMs,
    threatWatch: true,
    selfHeal: false,
    provider: "lyrie-watch-cli",
    channels: [],
    maxTicksBeforeRest: args.once ? 1 : undefined,
  });
}

main();
