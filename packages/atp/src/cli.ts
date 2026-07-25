#!/usr/bin/env node
/**
 * lyrie-atp — standalone CLI for @lyrie/atp.
 *
 * Verifies ATP artifacts (AIC / Action Receipt / Scope Declaration /
 * Trust Chain / Breach Attestation) fully offline, no server/hosting
 * required — reads a JSON file, sniffs the artifact kind with
 * `detectArtifactKind()`, and reports pass/fail with a machine-readable
 * reason code via `verifyArtifact()`.
 *
 * Usage:
 *   lyrie-atp verify <file.json> [--json]
 *   lyrie-atp status <file.json> [--json]
 *
 * `verify` exits 0 on a valid artifact, 1 otherwise (script-friendly).
 * `status` never fails on an invalid-but-parseable artifact; it always
 * exits 0 and prints the verdict (useful for dashboards/CI status checks
 * that want output without a non-zero-triggered pipeline abort). Both
 * exit 2 on usage errors (missing file, unparseable JSON, unknown kind).
 *
 * Input file shapes:
 *   - AIC / Scope / Trust Chain: the bare artifact JSON (self-contained,
 *     no companion material needed to verify).
 *   - Action Receipt / Breach Attestation: these primitives are only
 *     verifiable against the Agent Identity Certificate that issued them
 *     (receipt/attestation signatures are checked against the cert's
 *     public key — see `VerifyReceiptOptions`/`VerifyAttestationOptions`).
 *     Supply a wrapper object: `{ "artifact": <receipt-or-attestation>,
 *     "cert": <AgentIdentityCertificate> }`. A bare receipt/attestation
 *     with no wrapper will fail with ATP_MALFORMED and a clear message
 *     telling the caller to wrap it — this is not a crash, it's an
 *     expected, documented usage error.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { readFileSync } from "node:fs";
import { detectArtifactKind, verifyArtifact, type AtpArtifact, type AtpVerifyContext } from "./verify";
import type { AgentIdentityCertificate, VerificationResult } from "./types";

interface ParsedInput {
  artifact: AtpArtifact;
  context?: AtpVerifyContext;
}

/** Reads and JSON-parses a file, throwing a clear CliError on failure. */
function readJsonFile(path: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err: any) {
    throw new CliError(`cannot read file: ${path} (${err?.message ?? err})`);
  }
  try {
    return JSON.parse(raw);
  } catch (err: any) {
    throw new CliError(`file is not valid JSON: ${path} (${err?.message ?? err})`);
  }
}

class CliError extends Error {
  /** Preserve the sniffed kind even when the error prevents full parsing (e.g. missing cert). */
  readonly kind: AtpArtifact["kind"] | null;

  constructor(message: string, kind: AtpArtifact["kind"] | null = null) {
    super(message);
    this.kind = kind;
  }
}

/**
 * A "wrapper" input is `{ artifact: {...}, cert: {...} }` — used for
 * receipt/attestation verification, which requires the issuing cert.
 * A bare artifact is anything else; we sniff it directly.
 */
function parseInput(value: unknown): ParsedInput {
  if (value && typeof value === "object" && "artifact" in (value as Record<string, unknown>)) {
    const wrapper = value as { artifact: unknown; cert?: AgentIdentityCertificate };
    const kind = detectArtifactKind(wrapper.artifact);
    if (!kind) {
      throw new CliError("cannot detect artifact kind inside wrapper's \"artifact\" field");
    }
    return buildParsedInput(kind, wrapper.artifact, wrapper.cert);
  }

  const kind = detectArtifactKind(value);
  if (!kind) {
    throw new CliError(
      'cannot detect artifact kind — expected one of aic/receipt/scope/trust-chain/attestation. ' +
        'If verifying a receipt or attestation, wrap it as { "artifact": <receipt-or-attestation>, "cert": <AIC> }.',
    );
  }
  return buildParsedInput(kind, value, undefined);
}

function buildParsedInput(
  kind: AtpArtifact["kind"],
  value: unknown,
  cert: AgentIdentityCertificate | undefined,
): ParsedInput {
  switch (kind) {
    case "aic":
      return { artifact: { kind: "aic", cert: value as AgentIdentityCertificate } };
    case "scope":
      return { artifact: { kind: "scope", scope: value as any } };
    case "trust-chain":
      return { artifact: { kind: "trust-chain", chain: value as any } };
    case "receipt": {
      if (!cert) {
        throw new CliError(
          'receipt artifacts require a companion cert — supply { "artifact": <receipt>, "cert": <AIC> }',
          "receipt",
        );
      }
      return {
        artifact: { kind: "receipt", receipt: value as any },
        context: { kind: "receipt", opts: { cert } },
      };
    }
    case "attestation": {
      if (!cert) {
        throw new CliError(
          'attestation artifacts require a companion cert — supply { "artifact": <attestation>, "cert": <AIC> }',
          "attestation",
        );
      }
      return {
        artifact: { kind: "attestation", attestation: value as any },
        context: { kind: "attestation", opts: { cert } },
      };
    }
  }
}

interface CliResult {
  kind: AtpArtifact["kind"] | null;
  result: VerificationResult;
}

/** Pure function — verifies a raw parsed JSON value. Exported for tests. */
export function verifyFile(raw: unknown): CliResult {
  let parsed: ParsedInput;
  try {
    parsed = parseInput(raw);
  } catch (err) {
    if (err instanceof CliError) {
      return { kind: err.kind, result: { valid: false, code: "ATP_MALFORMED", reason: err.message } };
    }
    throw err;
  }
  return { kind: parsed.artifact.kind, result: verifyArtifact(parsed.artifact, parsed.context) };
}

function printHuman(cmd: "verify" | "status", path: string, r: CliResult): void {
  console.log();
  console.log(`🛡️  lyrie-atp ${cmd}  ·  Lyrie.ai by OTT Cybersecurity LLC`);
  console.log("─".repeat(65));
  console.log(`  file: ${path}`);
  console.log(`  kind: ${r.kind ?? "(unknown)"}`);
  if (r.result.valid) {
    console.log(`  ✅ VALID`);
  } else {
    console.log(`  ❌ INVALID`);
    console.log(`  code:   ${r.result.code ?? "(none)"}`);
    console.log(`  reason: ${r.result.reason ?? "(none)"}`);
    if (r.result.details?.length) {
      console.log(`  details:`);
      for (const d of r.result.details) {
        console.log(`    - [${d.code}]${d.index !== undefined ? ` #${d.index}` : ""} ${d.reason}`);
      }
    }
  }
  console.log();
}

function printJson(r: CliResult): void {
  console.log(JSON.stringify({ kind: r.kind, ...r.result }, null, 2));
}

function printHelp(): void {
  console.log(`lyrie-atp — Agent Trust Protocol CLI (offline, no server required)

Usage:
  lyrie-atp verify <file.json> [--json]
  lyrie-atp status <file.json> [--json]

  verify   exits 0 if the artifact is valid, 1 otherwise
  status   always exits 0 (informational; check output for verdict)
  --json   machine-readable JSON output instead of human-readable text

Input file shapes:
  - aic / scope / trust-chain: bare artifact JSON
  - receipt / attestation: { "artifact": <receipt-or-attestation>, "cert": <AIC> }

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
`);
}

export async function main(argv: string[]): Promise<number> {
  const [cmd, file, ...rest] = argv;
  const jsonMode = rest.includes("--json") || argv.includes("--json");

  if (!cmd || cmd === "-h" || cmd === "--help") {
    printHelp();
    return cmd ? 0 : 2;
  }
  if (cmd !== "verify" && cmd !== "status") {
    console.error(`unknown command: ${cmd}`);
    printHelp();
    return 2;
  }
  if (!file) {
    console.error(`usage: lyrie-atp ${cmd} <file.json> [--json]`);
    return 2;
  }

  let raw: unknown;
  try {
    raw = readJsonFile(file);
  } catch (err) {
    if (err instanceof CliError) {
      if (jsonMode) {
        console.log(JSON.stringify({ kind: null, valid: false, code: "ATP_MALFORMED", reason: err.message }, null, 2));
      } else {
        console.error(`✗ ${err.message}`);
      }
      return 2;
    }
    throw err;
  }

  const result = verifyFile(raw);

  if (jsonMode) {
    printJson(result);
  } else {
    printHuman(cmd, file, result);
  }

  if (cmd === "status") return 0;
  return result.result.valid ? 0 : 1;
}

const isDirectRun =
  typeof Bun !== "undefined"
    ? Bun.main === import.meta.path
    : process.argv[1]?.endsWith("cli.ts") || process.argv[1]?.endsWith("cli.js");

if (isDirectRun) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
