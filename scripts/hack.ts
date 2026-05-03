#!/usr/bin/env bun
/**
 * `lyrie hack <target>` — the headline autonomous-pentest command.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run scripts/hack.ts <target> [options]
 *
 *   target                URL, repo path, or IP:port to attack
 *   --mode <mode>         quick|standard|deep|paranoid (default: standard)
 *   --output <fmt>        markdown|sarif|json|all (default: all)
 *   --out <dir>           output directory (default: ./lyrie-reports/<timestamp>/)
 *   --aav                 also run LyrieAAV against the deployed instance
 *   --agt                 generate AGT policy template after scanning
 *   --no-self-scan        skip final self-integrity check
 *   --concurrency <n>     parallel scanner threads (default: 3)
 *   --fail-on <sev>       exit 1 on findings >= severity (critical|high|medium|low)
 *   --dry-run             plan only, no HTTP requests or file writes
 *   --json                emit final summary as JSON
 *   --quiet               suppress progress output
 */

import { HackOrchestrator } from "../packages/core/src/hack";
import type {
  FindingEvent,
  HackEvent,
  HackMode,
  HackReport,
  OutputFormat,
  PhaseEvent,
  Severity,
} from "../packages/core/src/hack";

const COLORS = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  magenta: "\x1b[35m",
  bold: "\x1b[1m",
};

function colorize(s: string, color: keyof typeof COLORS, useColor = true): string {
  if (!useColor) return s;
  return COLORS[color] + s + COLORS.reset;
}

function severityColor(sev: Severity): keyof typeof COLORS {
  switch (sev) {
    case "critical":
      return "red";
    case "high":
      return "magenta";
    case "medium":
      return "yellow";
    case "low":
      return "blue";
    default:
      return "dim";
  }
}

interface Args {
  target?: string;
  mode: HackMode;
  output: OutputFormat;
  out?: string;
  aav: boolean;
  agt: boolean;
  noSelfScan: boolean;
  concurrency: number;
  failOn?: Severity;
  dryRun: boolean;
  json: boolean;
  quiet: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const out: Args = {
    mode: "standard",
    output: "all",
    aav: false,
    agt: false,
    noSelfScan: false,
    concurrency: 3,
    dryRun: false,
    json: false,
    quiet: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-h":
      case "--help":
        out.help = true;
        break;
      case "--mode":
        out.mode = (argv[++i] ?? "standard") as HackMode;
        break;
      case "--output":
        out.output = (argv[++i] ?? "all") as OutputFormat;
        break;
      case "--out":
        out.out = argv[++i];
        break;
      case "--aav":
        out.aav = true;
        break;
      case "--agt":
        out.agt = true;
        break;
      case "--no-self-scan":
        out.noSelfScan = true;
        break;
      case "--concurrency":
        out.concurrency = Number(argv[++i] ?? "3");
        break;
      case "--fail-on":
        out.failOn = argv[++i] as Severity;
        break;
      case "--dry-run":
        out.dryRun = true;
        break;
      case "--json":
        out.json = true;
        break;
      case "-q":
      case "--quiet":
        out.quiet = true;
        break;
      default:
        if (!a.startsWith("--") && !out.target) out.target = a;
        break;
    }
  }
  return out;
}

function printHelp(): void {
  console.log(`lyrie hack <target> [options]

  target                URL, repo path, or IP:port to attack
  --mode <mode>         quick|standard|deep|paranoid (default: standard)
  --output <fmt>        markdown|sarif|json|all (default: all)
  --out <dir>           output directory (default: ./lyrie-reports/<timestamp>/)
  --aav                 also run LyrieAAV against the deployed instance
  --agt                 generate AGT policy template after scanning
  --no-self-scan        skip final self-integrity check of the run
  --concurrency <n>     parallel scanner threads (default: 3)
  --fail-on <sev>       exit 1 on findings >= severity (critical|high|medium|low)
  --dry-run             plan only, no HTTP requests or file writes
  --json                emit final summary as JSON to stdout
  --quiet               suppress progress output

  Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
`);
}

function severityRank(s: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[s];
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.target) {
    printHelp();
    process.exit(args.help ? 0 : 2);
  }

  const useColor = !args.quiet && !args.json && process.stdout.isTTY === true;

  if (!args.quiet && !args.json) {
    console.log("");
    console.log(
      colorize("🛡️  Lyrie Hack", "cyan", useColor) +
        colorize("  ·  ", "dim", useColor) +
        colorize("Lyrie.ai by OTT Cybersecurity LLC", "dim", useColor),
    );
    console.log(
      colorize("─────────────────────────────────────────────────────────────────", "dim", useColor),
    );
    console.log(`  target: ${colorize(args.target!, "bold", useColor)}`);
    console.log(`  mode:   ${args.mode}`);
    console.log(`  output: ${args.output}${args.out ? ` → ${args.out}` : ""}`);
    if (args.aav) console.log("  aav:    enabled");
    if (args.agt) console.log("  agt:    enabled");
    if (args.dryRun) console.log("  dry-run: enabled (no writes)");
    console.log("");
  }

  const orch = new HackOrchestrator();
  if (!args.quiet && !args.json) {
    orch.on((e: HackEvent) => onEvent(e, useColor));
  }

  let report: HackReport;
  try {
    report = await orch.run(args.target!, {
      mode: args.mode,
      output: args.output,
      outDir: args.out,
      aav: args.aav,
      agt: args.agt,
      noSelfScan: args.noSelfScan,
      concurrency: args.concurrency,
      failOn: args.failOn,
      dryRun: args.dryRun,
    });
  } catch (err: any) {
    console.error(colorize(`✗ Hack failed: ${err?.message ?? err}`, "red", useColor));
    process.exit(1);
  }

  // Final summary.
  if (args.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else if (!args.quiet) {
    printSummary(report, useColor);
  }

  // Exit code: --fail-on
  if (args.failOn) {
    const threshold = severityRank(args.failOn);
    let worst = -1;
    for (const v of report.validatedFindings) {
      if (!v.confirmed) continue;
      worst = Math.max(worst, severityRank(v.finding.severity));
    }
    for (const s of report.secretFindings) {
      worst = Math.max(worst, severityRank(s.severity));
    }
    if (worst >= threshold) {
      if (!args.quiet && !args.json) {
        console.error(
          colorize(
            `\nfail-on: at least one finding ≥ ${args.failOn} → exit 1`,
            "red",
            useColor,
          ),
        );
      }
      process.exit(1);
    }
  }
}

function onEvent(e: HackEvent, useColor: boolean): void {
  if ((e as any).phase) {
    const p = e as PhaseEvent;
    if (p.type === "start") {
      process.stdout.write(
        colorize(`▸ ${p.phase.padEnd(10)}`, "cyan", useColor) +
          colorize(" starting…", "dim", useColor) +
          "\n",
      );
    } else if (p.type === "complete") {
      const t = p.durationMs !== undefined ? `${(p.durationMs / 1000).toFixed(2)}s` : "";
      process.stdout.write(
        colorize(`✓ ${p.phase.padEnd(10)}`, "green", useColor) +
          ` ${t.padStart(7)}` +
          (p.detail ? colorize(`  ${p.detail}`, "dim", useColor) : "") +
          "\n",
      );
    } else if (p.type === "skipped") {
      process.stdout.write(
        colorize(`· ${p.phase.padEnd(10)}`, "dim", useColor) +
          colorize(" skipped", "dim", useColor) +
          "\n",
      );
    }
  } else {
    const f = e as FindingEvent;
    if (severityRank(f.severity) < 2) return;
    const tag = f.severity.toUpperCase().padEnd(8);
    process.stdout.write(
      "  " +
        colorize(`[${tag}]`, severityColor(f.severity), useColor) +
        ` ${f.title}` +
        (f.file ? colorize(`  ${f.file}${f.line ? `:${f.line}` : ""}`, "dim", useColor) : "") +
        "\n",
    );
  }
}

function printSummary(report: HackReport, useColor: boolean): void {
  console.log("");
  console.log(colorize("📊 Summary", "bold", useColor));
  console.log(
    colorize("─────────────────────────────────────────────────────────────────", "dim", useColor),
  );
  console.log(`  run id:       ${report.runId}`);
  console.log(`  duration:     ${(report.durationMs / 1000).toFixed(2)}s`);
  console.log(`  findings:     ${report.totalFindings}`);
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    if (report.counts[sev] === 0) continue;
    console.log(
      `    ${colorize(sev.padEnd(8), severityColor(sev), useColor)} ${report.counts[sev]}`,
    );
  }
  if (report.threatMatches.length > 0) {
    console.log(`  threats:      ${report.threatMatches.length} matches`);
  }
  if (report.aavRan) console.log(`  aav:          ✓`);
  if (report.selfScanRan) {
    const v = report.selfScanVerdict ?? "unknown";
    const c: keyof typeof COLORS =
      v === "clean" ? "green" : v === "suspicious" ? "yellow" : "red";
    console.log(`  self-scan:    ${colorize(v, c, useColor)}`);
  }
  console.log("");
  console.log(`  ${colorize("signature:", "dim", useColor)} Lyrie.ai by OTT Cybersecurity LLC`);
  console.log("");
}

main();
