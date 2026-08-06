#!/usr/bin/env bun
/**
 * `lyrie watch-once <domain>` — single-tick, cron/CI-friendly posture check.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Unlike `scripts/watch.ts` (a long-running design-stub CLI that drives
 * `WatchEngine`'s continuous tick loop directly — see that file's header),
 * this script runs exactly ONE probe→diff→classify tick via
 * `runWatchTick()` (packages/core/src/watch/run-once.ts) and exits. That
 * makes it the right shape for `cron`, a CI step, or any scheduler that
 * expects "run once, report, exit non-zero on trouble" rather than a
 * long-lived process.
 *
 * Exit codes:
 *   0   ok — no drift, or drift severity is info/low/medium
 *   1   drift severity is high or critical (or an unexpected error occurred)
 *   2   usage error (no domain given)
 *
 * Usage:
 *   bun run scripts/watch-once.ts <domain>
 *   bun run scripts/watch-once.ts example.com --json
 *   bun run scripts/watch-once.ts example.com --store-dir /tmp/lyrie-watch
 */

import { runWatchTick } from "../packages/core/src/watch/run-once";

interface Args {
  domain: string | undefined;
  json: boolean;
  help: boolean;
  storeDir: string | undefined;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { domain: undefined, json: false, help: false, storeDir: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-h":
      case "--help":
        out.help = true;
        break;
      case "--json":
        out.json = true;
        break;
      case "--store-dir":
        out.storeDir = argv[++i];
        break;
      default:
        if (!a.startsWith("--") && !out.domain) out.domain = a;
        break;
    }
  }
  return out;
}

function printHelp(): void {
  console.log(`lyrie watch-once <domain> [options]

  Run a single posture-watch tick (probe → diff → drift-severity classify)
  and exit. Cron/CI-friendly counterpart to scripts/watch.ts's continuous
  loop — see packages/core/src/watch/run-once.ts for the underlying logic.

  --json             emit the full tick result as JSON to stdout
  --store-dir <path>  override snapshot storage directory (default: ~/.lyrie/watch)

  Exit codes: 0 = ok, 1 = high/critical drift (or error), 2 = usage error

  Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.domain) {
    printHelp();
    process.exit(args.help ? 0 : 2);
  }

  const domain = args.domain;

  try {
    const result = await runWatchTick(domain, { storeDir: args.storeDir });

    if (args.json) {
      process.stdout.write(JSON.stringify(result) + "\n");
    } else if (!result.driftSeverity) {
      console.log(`[watch-once] ${domain}: baseline established (first run, nothing to diff against yet)`);
    } else if (result.driftSeverity.severity === "info" && result.driftSeverity.reasons.length === 0) {
      console.log(`[watch-once] ${domain}: idle — no posture changes detected`);
    } else {
      console.log(`[watch-once] ${domain}: drift severity = ${result.driftSeverity.severity.toUpperCase()}`);
      for (const reason of result.driftSeverity.reasons) {
        console.log(`  - ${reason}`);
      }
    }

    const severity = result.driftSeverity?.severity;
    process.exit(severity === "high" || severity === "critical" ? 1 : 0);
  } catch (err) {
    if (args.json) {
      process.stdout.write(JSON.stringify({ error: String(err) }) + "\n");
    } else {
      console.error(`[watch-once] error: ${String(err)}`);
    }
    process.exit(1);
  }
}

main();
