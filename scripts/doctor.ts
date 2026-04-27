#!/usr/bin/env bun
/**
 * Lyrie Doctor — self-diagnostic for environment, dependencies, channels,
 * security posture, and update status.
 *
 * Usage:
 *   bun run scripts/doctor.ts
 *   bun run scripts/doctor.ts --json
 *   bun run scripts/doctor.ts --repair          (planned — non-destructive only)
 *
 * Phase 0 ships a read-only diagnostic. --repair is a placeholder.
 */

import { existsSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

type Status = "ok" | "warn" | "error" | "info";

interface Check {
  id: string;
  label: string;
  status: Status;
  detail?: string;
  fix?: string;
}

const args = new Set(process.argv.slice(2));
const asJson = args.has("--json");
const verbose = args.has("--verbose") || args.has("-v");

const ROOT = process.cwd();
const checks: Check[] = [];

const ICON: Record<Status, string> = {
  ok: "✅",
  warn: "⚠️ ",
  error: "❌",
  info: "ℹ️ ",
};

function add(c: Check) {
  checks.push(c);
  if (!asJson) {
    const line = `${ICON[c.status]} ${c.label}${c.detail ? `  — ${c.detail}` : ""}`;
    console.log(line);
    if (c.fix && c.status !== "ok") console.log(`     fix: ${c.fix}`);
  }
}

function tryExec(cmd: string): string | null {
  try {
    return execSync(cmd, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return null;
  }
}

function semverGte(a: string, b: string): boolean {
  const norm = (v: string) => v.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const [a1, a2, a3] = norm(a);
  const [b1, b2, b3] = norm(b);
  if (a1 !== b1) return a1 > b1;
  if (a2 !== b2) return a2 > b2;
  return a3 >= b3;
}

// 1) Runtime versions
{
  const node = process.versions.node;
  const minNode = "20.0.0";
  add({
    id: "runtime.node",
    label: `Node.js ${node}`,
    status: semverGte(node, minNode) ? "ok" : "warn",
    detail: semverGte(node, minNode) ? undefined : `recommend Node ${minNode}+`,
    fix: "use nvm/fnm/asdf to install a newer Node, or `brew install node`",
  });

  const bun = tryExec("bun --version");
  add({
    id: "runtime.bun",
    label: bun ? `Bun ${bun}` : "Bun not found",
    status: bun ? "ok" : "warn",
    detail: bun ? undefined : "Lyrie's preferred runtime is Bun (fast install + bundling)",
    fix: bun ? undefined : "curl -fsSL https://bun.sh/install | bash",
  });

  const git = tryExec("git --version");
  add({
    id: "runtime.git",
    label: git ?? "git not found",
    status: git ? "ok" : "error",
    fix: git ? undefined : "install git from https://git-scm.com or your package manager",
  });

  const cargo = tryExec("cargo --version");
  add({
    id: "runtime.cargo",
    label: cargo ?? "Rust toolchain (cargo) not found",
    status: cargo ? "ok" : "warn",
    detail: cargo ? undefined : "needed to build packages/shield (Rust)",
    fix: cargo ? undefined : "https://rustup.rs",
  });
}

// 2) Repo layout
{
  const expected = ["package.json", "packages/core", "packages/gateway", "packages/shield", "skills"];
  for (const p of expected) {
    add({
      id: `repo.${p}`,
      label: `repo: ${p}`,
      status: existsSync(join(ROOT, p)) ? "ok" : "warn",
      detail: existsSync(join(ROOT, p)) ? undefined : "missing — running outside the repo?",
    });
  }
}

// 3) Package + version
{
  try {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    add({
      id: "pkg.identity",
      label: `package: ${pkg.name}@${pkg.version}`,
      status: "ok",
      detail: pkg.repository?.url ?? undefined,
    });
  } catch {
    add({
      id: "pkg.identity",
      label: "package.json not readable",
      status: "warn",
      fix: "run `lyrie doctor` from the repo root",
    });
  }
}

// 4) Lockfile
{
  add({
    id: "deps.lockfile",
    label: "lockfile present (bun.lock)",
    status: existsSync(join(ROOT, "bun.lock")) ? "ok" : "warn",
    fix: existsSync(join(ROOT, "bun.lock")) ? undefined : "run `bun install` to generate",
  });
}

// 5) Env
{
  const envPath = join(ROOT, ".env");
  const examplePath = join(ROOT, ".env.example");
  if (existsSync(examplePath) && !existsSync(envPath)) {
    add({
      id: "env.missing",
      label: ".env not configured",
      status: "warn",
      detail: ".env.example exists; copy and fill",
      fix: "cp .env.example .env && edit",
    });
  } else if (existsSync(envPath)) {
    const env = readFileSync(envPath, "utf8");
    const placeholders = (env.match(/=\s*(your_|YOUR_|REPLACE|<.*>)/g) || []).length;
    add({
      id: "env.placeholders",
      label: ".env present",
      status: placeholders === 0 ? "ok" : "warn",
      detail: placeholders ? `${placeholders} placeholder(s) still unset` : "no placeholders detected",
    });
  } else {
    add({
      id: "env.example",
      label: "no .env / .env.example found",
      status: "info",
    });
  }
}

// 6) Channel keys (heuristic — does .env reference common channels?)
{
  const envPath = join(ROOT, ".env");
  if (existsSync(envPath)) {
    const env = readFileSync(envPath, "utf8");
    const channels: Record<string, RegExp> = {
      telegram: /TELEGRAM[_A-Z]*TOKEN\s*=\s*\S+/,
      discord: /DISCORD[_A-Z]*TOKEN\s*=\s*\S+/,
      slack: /SLACK[_A-Z]*TOKEN\s*=\s*\S+/,
      whatsapp: /WHATSAPP[_A-Z]*=\s*\S+/,
      anthropic: /ANTHROPIC[_A-Z]*KEY\s*=\s*\S+/,
      openai: /OPENAI[_A-Z]*KEY\s*=\s*\S+/,
    };
    for (const [name, re] of Object.entries(channels)) {
      const present = re.test(env);
      add({
        id: `channel.${name}`,
        label: `channel: ${name}`,
        status: present ? "ok" : "info",
        detail: present ? "credential present" : "not configured",
      });
    }
  }
}

// 7) Security: SECURITY.md + LICENSE
{
  add({
    id: "security.SECURITY",
    label: "SECURITY.md present",
    status: existsSync(join(ROOT, "SECURITY.md")) ? "ok" : "warn",
  });
  add({
    id: "security.LICENSE",
    label: "LICENSE present",
    status: existsSync(join(ROOT, "LICENSE")) ? "ok" : "error",
  });
  add({
    id: "security.CODE_OF_CONDUCT",
    label: "CODE_OF_CONDUCT.md present",
    status: existsSync(join(ROOT, "CODE_OF_CONDUCT.md")) ? "ok" : "warn",
  });
}

// 8) DM pairing reminder (additive — this is informational until policy ships)
{
  add({
    id: "policy.dmPairing",
    label: "DM pairing policy (recommended for production)",
    status: "info",
    detail: "set channels.<channel>.dmPolicy = \"pairing\" in your config",
  });
}

// 9) Updates — github releases ping (best-effort, offline-tolerant)
{
  const remote = tryExec("git config --get remote.origin.url");
  add({
    id: "git.remote",
    label: "git remote",
    status: remote ? "ok" : "warn",
    detail: remote ?? "no origin configured",
  });
}

// 10) Summary
const errors = checks.filter((c) => c.status === "error").length;
const warns = checks.filter((c) => c.status === "warn").length;
const oks = checks.filter((c) => c.status === "ok").length;

if (asJson) {
  process.stdout.write(JSON.stringify({ checks, summary: { ok: oks, warn: warns, error: errors } }, null, 2) + "\n");
} else {
  console.log("");
  console.log(`Doctor summary: ${oks} ok, ${warns} warn, ${errors} error`);
  if (verbose) {
    console.log("");
    console.log("docs: https://docs.lyrie.ai/doctor");
  }
}

process.exit(errors > 0 ? 1 : 0);
