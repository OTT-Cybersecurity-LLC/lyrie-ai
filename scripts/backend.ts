#!/usr/bin/env bun
/**
 * `lyrie backend` — operator CLI for the Lyrie execution backends.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run backend status                                # show what's configured
 *   bun run backend list                                  # supported backends
 *   bun run backend show <kind>                           # show config + envs
 *   bun run backend preflight [<kind>]                    # cheap auth/connectivity check
 *   bun run backend run --kind=<k> --target=<dir> [--mode=quick|full|...] [--scope=full|diff]
 */

import {
  describeBackend,
  getBackend,
  readDaytonaConfigFromEnv,
  readLocalConfigFromEnv,
  readModalConfigFromEnv,
  resolveBackendKind,
  SUPPORTED_BACKENDS,
  type BackendKind,
  type BackendRunRequest,
} from "../packages/core/src/backends";

const cmd = process.argv[2];
const rest = process.argv.slice(3);

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const a of argv) {
    const m = a.match(/^--([^=]+)=(.*)$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

function header(title: string): void {
  console.log("");
  console.log(`🛡️  ${title}  ·  Lyrie.ai by OTT Cybersecurity LLC`);
  console.log("─".repeat(65));
}

const env = process.env as Record<string, string | undefined>;

switch (cmd) {
  case "list": {
    header("Lyrie Execution Backends");
    for (const k of SUPPORTED_BACKENDS) {
      const b = getBackend(k, undefined, { env });
      console.log(`  ${describeBackend(b)}`);
    }
    console.log("");
    break;
  }

  case "status": {
    header("Lyrie Backend Status");
    const resolved = resolveBackendKind(undefined, env);
    console.log(`  resolved (LYRIE_BACKEND):  ${resolved}`);
    for (const k of SUPPORTED_BACKENDS) {
      const b = getBackend(k, undefined, { env });
      const mark = b.isConfigured() ? "✅" : "❌";
      console.log(`  ${mark} ${k.padEnd(8)}  ${b.displayName}`);
    }
    console.log("");
    break;
  }

  case "show": {
    const kind = (rest[0] ?? "local") as BackendKind;
    if (!SUPPORTED_BACKENDS.includes(kind)) {
      console.error(`unknown backend: ${kind}`);
      process.exit(2);
    }
    header(`Lyrie Backend · ${kind}`);
    const b = getBackend(kind, undefined, { env });
    console.log(`  display:    ${b.displayName}`);
    console.log(`  configured: ${b.isConfigured() ? "yes" : "no"}`);
    if (kind === "daytona") {
      const c = readDaytonaConfigFromEnv(env);
      console.log(`  apiUrl:     ${c.apiUrl ?? "(default https://app.daytona.io/api)"}`);
      console.log(`  apiKey:     ${c.apiKey ? "•••set" : "(unset)"}`);
      console.log(`  image:      ${c.image ?? "(default ghcr.io/overthetopseo/lyrie-agent:latest)"}`);
      console.log(`  region:     ${c.region ?? "(default)"}`);
      console.log(`  ttlSeconds: ${c.ttlSeconds ?? "1800"}`);
    } else if (kind === "modal") {
      const c = readModalConfigFromEnv(env);
      console.log(`  app:        ${c.app ?? "(default lyrie-agent)"}`);
      console.log(`  function:   ${c.functionName ?? "(default lyrie_scan)"}`);
      console.log(`  tokenId:    ${c.tokenId ? "•••set" : "(unset)"}`);
      console.log(`  tokenSecret:${c.tokenSecret ? "•••set" : "(unset)"}`);
      console.log(`  region:     ${c.region ?? "(default)"}`);
      console.log(`  gpu:        ${c.gpu ?? "(none)"}`);
    } else {
      const c = readLocalConfigFromEnv(env);
      console.log(`  dryRun:     ${c.dryRun ? "yes" : "no"}`);
      console.log(`  cwd:        ${c.cwd ?? "(process cwd)"}`);
    }
    console.log("");
    break;
  }

  case "preflight": {
    const kind = ((rest[0] ?? resolveBackendKind(undefined, env)) as BackendKind);
    if (!SUPPORTED_BACKENDS.includes(kind)) {
      console.error(`unknown backend: ${kind}`);
      process.exit(2);
    }
    header(`Lyrie Backend Preflight · ${kind}`);
    const b = getBackend(kind, undefined, { env });
    const r = await b.preflight();
    console.log(`  ${r.ok ? "✅ ok" : "❌ failed"}${r.reason ? `  · ${r.reason}` : ""}`);
    console.log("");
    process.exit(r.ok ? 0 : 1);
  }

  case "run": {
    const args = parseArgs(rest);
    const kind = ((args["kind"] ?? resolveBackendKind(undefined, env)) as BackendKind);
    if (!SUPPORTED_BACKENDS.includes(kind)) {
      console.error(`unknown backend: ${kind}`);
      process.exit(2);
    }
    const request: BackendRunRequest = {
      target: args["target"] ?? process.cwd(),
      scanMode: ((args["mode"] ?? "quick") as BackendRunRequest["scanMode"]),
      scope: ((args["scope"] ?? "diff") as BackendRunRequest["scope"]),
      diffBase: args["diffBase"],
      failOn: ((args["failOn"] ?? "high") as BackendRunRequest["failOn"]),
      intelOffline: args["intelOffline"] === "1" || args["intelOffline"] === "true",
    };
    header(`Lyrie Backend Run · ${kind}`);
    const b = getBackend(kind, undefined, { env });
    if (!b.isConfigured()) {
      console.error(`  ❌ backend ${kind} not configured.  Run \`lyrie backend show ${kind}\``);
      process.exit(1);
    }
    const result = await b.run(request);
    console.log(`  status:        ${result.status}`);
    console.log(`  findings:      ${result.findingCount}  (highest=${result.highestSeverity})`);
    console.log(`  durationMs:    ${result.durationMs}`);
    if (result.runId) console.log(`  runId:         ${result.runId}`);
    if (result.costUsd !== undefined) console.log(`  costUsd:       $${result.costUsd}`);
    if (result.error) console.log(`  error:         ${result.error}`);
    console.log("");
    process.exit(result.status === "error" ? 1 : 0);
  }

  default:
    console.error("Usage:");
    console.error("  lyrie backend list");
    console.error("  lyrie backend status");
    console.error("  lyrie backend show <local|daytona|modal>");
    console.error("  lyrie backend preflight [<kind>]");
    console.error("  lyrie backend run --kind=<k> --target=<dir> [--mode=quick|full|...] [--scope=full|diff]");
    process.exit(2);
}
