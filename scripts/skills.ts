#!/usr/bin/env bun
/**
 * lyrie skills — SKILL.md runtime CLI
 *
 * Usage:
 *   bun run scripts/skills.ts list
 *   bun run scripts/skills.ts search <query>
 *   bun run scripts/skills.ts info <name>
 *   bun run scripts/skills.ts run <name> [--message <msg>]
 *   bun run scripts/skills.ts install <path>
 *   bun run scripts/skills.ts import --from openclaw
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, mkdirSync, readdirSync, copyFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, basename, dirname } from "node:path";

import { SkillLoader } from "../packages/core/src/skills/skill-loader";
import { SkillRegistry } from "../packages/core/src/skills/skill-registry";
import { SkillRunner } from "../packages/core/src/skills/skill-runner";

// ─── ANSI ─────────────────────────────────────────────────────────────────────
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  magenta: "\x1b[35m",
  blue: "\x1b[34m",
};
function c(str: string, ...codes: string[]): string {
  return codes.join("") + str + C.reset;
}

// ─── Banner ───────────────────────────────────────────────────────────────────
function printBanner(): void {
  console.log(`
${c("  ╔══════════════════════════════════════════════╗", C.cyan, C.bold)}
${c("  ║      🧠  LYRIE AGENT — SKILLS MANAGER         ║", C.cyan, C.bold)}
${c("  ║   OpenClaw-format SKILL.md runtime             ║", C.cyan)}
${c("  ╚══════════════════════════════════════════════╝", C.cyan, C.bold)}
${c("  © OTT Cybersecurity LLC / Lyrie.ai", C.dim)}
`);
}

// ─── Help ─────────────────────────────────────────────────────────────────────
function printHelp(): void {
  console.log(`
${c("USAGE", C.bold)}
  lyrie skills <command> [options]

${c("COMMANDS", C.bold)}
  ${c("list", C.cyan)}                    List all installed skills
  ${c("search", C.cyan)} <query>          Find skills by name or description
  ${c("info", C.cyan)} <name>             Show full SKILL.md for a skill
  ${c("run", C.cyan)} <name>              Activate skill + print system prompt injection
  ${c("install", C.cyan)} <path>          Install a skill from a directory or SKILL.md path
  ${c("import", C.cyan)} --from openclaw  Import all skills from ~/.openclaw/workspace/skills/

${c("OPTIONS", C.bold)}
  --message <text>        Message to pass as context when running a skill
  --paths <p1,p2,...>     Override default skill search paths
  --json                  Output as JSON (for list/search/info)
  --help                  Show this help

${c("EXAMPLES", C.bold)}
  lyrie skills list
  lyrie skills search "google analytics"
  lyrie skills info ga4-analytics
  lyrie skills run ga4-analytics --message "show me traffic for last 7 days"
  lyrie skills install ~/my-custom-skill/
  lyrie skills import --from openclaw
`);
}

// ─── Args ─────────────────────────────────────────────────────────────────────
interface CliArgs {
  command: string | null;
  target: string | null;
  message: string | null;
  from: string | null;
  paths: string[] | null;
  json: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2);
  const result: CliArgs = {
    command: null,
    target: null,
    message: null,
    from: null,
    paths: null,
    json: false,
    help: false,
  };

  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a === "--help" || a === "-h") {
      result.help = true;
    } else if (a === "--json") {
      result.json = true;
    } else if (a === "--message" && args[i + 1]) {
      result.message = args[++i];
    } else if (a === "--from" && args[i + 1]) {
      result.from = args[++i];
    } else if (a === "--paths" && args[i + 1]) {
      result.paths = args[++i].split(",").map((p) => p.trim());
    } else if (!result.command) {
      result.command = a;
    } else if (!result.target) {
      result.target = a;
    }
    i++;
  }

  return result;
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function lyrieDirs() {
  const home = homedir();
  return {
    lyrieSkills: join(home, ".lyrie", "skills"),
    openclawSkills: join(home, ".openclaw", "workspace", "skills"),
  };
}

async function loadRegistry(paths?: string[]): Promise<SkillRegistry> {
  const reg = SkillRegistry.getInstance();
  if (!reg.loaded) {
    await reg.loadAll(paths ?? undefined);
  }
  return reg;
}

// ─── Commands ────────────────────────────────────────────────────────────────

async function cmdList(args: CliArgs): Promise<void> {
  const reg = await loadRegistry(args.paths ?? undefined);
  const skills = reg.list();

  if (skills.length === 0) {
    console.log(c("  No skills found.", C.yellow));
    console.log(c(`  Run: lyrie skills import --from openclaw`, C.dim));
    return;
  }

  if (args.json) {
    console.log(JSON.stringify(skills.map((m) => ({
      name: m.name,
      description: m.description,
      version: m.version,
      author: m.author,
      location: m.location,
    })), null, 2));
    return;
  }

  console.log(c(`\n  ${skills.length} skill${skills.length !== 1 ? "s" : ""} installed\n`, C.bold));
  for (const m of skills) {
    const desc = m.description ? c(`  ${m.description.slice(0, 80)}`, C.dim) : "";
    console.log(`  ${c(m.name, C.cyan, C.bold)}${m.version ? c(` v${m.version}`, C.dim) : ""}`);
    if (desc) console.log(desc);
  }
  console.log();
}

async function cmdSearch(args: CliArgs): Promise<void> {
  if (!args.target) {
    console.error(c("  Error: search requires a query string", C.red));
    process.exit(1);
  }

  const reg = await loadRegistry(args.paths ?? undefined);
  const results = reg.search(args.target, 20);

  if (results.length === 0) {
    console.log(c(`  No skills matching "${args.target}"`, C.yellow));
    return;
  }

  if (args.json) {
    console.log(JSON.stringify(results.map((m) => ({ name: m.name, description: m.description })), null, 2));
    return;
  }

  console.log(c(`\n  Found ${results.length} skill${results.length !== 1 ? "s" : ""} matching "${args.target}"\n`, C.bold));
  for (const m of results) {
    console.log(`  ${c(m.name, C.cyan, C.bold)}`);
    if (m.description) console.log(c(`  ${m.description.slice(0, 100)}`, C.dim));
  }
  console.log();
}

async function cmdInfo(args: CliArgs): Promise<void> {
  if (!args.target) {
    console.error(c("  Error: info requires a skill name", C.red));
    process.exit(1);
  }

  const reg = await loadRegistry(args.paths ?? undefined);
  const m = reg.get(args.target);

  if (!m) {
    console.error(c(`  Skill "${args.target}" not found.`, C.red));
    console.log(c(`  Tip: run \`lyrie skills search ${args.target}\` to find similar skills.`, C.dim));
    process.exit(1);
  }

  if (args.json) {
    console.log(JSON.stringify(m, null, 2));
    return;
  }

  console.log(c(`\n  ╔══ ${m.name} ══╗\n`, C.cyan, C.bold));
  if (m.description) console.log(`  ${c("Description:", C.bold)} ${m.description}`);
  if (m.version) console.log(`  ${c("Version:", C.bold)} ${m.version}`);
  if (m.author) console.log(`  ${c("Author:", C.bold)} ${m.author}`);
  if (m.tools?.length) console.log(`  ${c("Tools:", C.bold)} ${m.tools.join(", ")}`);
  if (m.channels?.length) console.log(`  ${c("Channels:", C.bold)} ${m.channels.join(", ")}`);
  if (m.triggers?.length) console.log(`  ${c("Triggers:", C.bold)} ${m.triggers.join(", ")}`);
  console.log(`  ${c("Location:", C.bold)} ${m.location}\n`);
  console.log(c("  ─── SKILL.md Content ───────────────────────────────", C.dim));
  console.log(m.content);
  console.log();
}

async function cmdRun(args: CliArgs): Promise<void> {
  if (!args.target) {
    console.error(c("  Error: run requires a skill name", C.red));
    process.exit(1);
  }

  const reg = await loadRegistry(args.paths ?? undefined);
  const runner = new SkillRunner(reg);

  let activated;
  try {
    activated = await runner.activate(args.target, {
      message: args.message ?? undefined,
      channel: "cli",
    });
  } catch (err: any) {
    console.error(c(`  Error: ${err.message}`, C.red));
    process.exit(1);
  }

  if (args.json) {
    console.log(JSON.stringify({
      skill: activated.manifest.name,
      activatedAt: activated.activatedAt,
      systemPromptInjection: activated.systemPromptInjection,
    }, null, 2));
    return;
  }

  console.log(c(`\n  ✅ Skill activated: ${activated.manifest.name}`, C.green, C.bold));
  console.log(c(`  Activated at: ${activated.activatedAt}\n`, C.dim));
  console.log(c("  ─── System Prompt Injection ────────────────────────", C.dim));
  console.log(activated.systemPromptInjection);
  console.log(c("\n  This would be prepended to the agent's system prompt for the next turn.", C.dim));
  console.log();
}

async function cmdInstall(args: CliArgs): Promise<void> {
  if (!args.target) {
    console.error(c("  Error: install requires a path to a skill directory", C.red));
    process.exit(1);
  }

  const src = args.target;
  let skillMdPath: string;

  if (basename(src) === "SKILL.md") {
    skillMdPath = src;
  } else {
    skillMdPath = join(src, "SKILL.md");
  }

  if (!existsSync(skillMdPath)) {
    console.error(c(`  Error: no SKILL.md found at ${skillMdPath}`, C.red));
    process.exit(1);
  }

  // Load the manifest to get the skill name
  const loader = new SkillLoader();
  const manifest = await loader.load(skillMdPath);

  const { lyrieSkills } = lyrieDirs();
  mkdirSync(lyrieSkills, { recursive: true });

  const destDir = join(lyrieSkills, manifest.name);
  mkdirSync(destDir, { recursive: true });

  // Copy SKILL.md
  const destPath = join(destDir, "SKILL.md");
  copyFileSync(skillMdPath, destPath);

  console.log(c(`\n  ✅ Installed: ${manifest.name}`, C.green, C.bold));
  console.log(c(`  Location: ${destPath}`, C.dim));
  console.log();
}

async function cmdImport(args: CliArgs): Promise<void> {
  if (args.from?.toLowerCase() !== "openclaw") {
    console.error(c(`  Error: --from only supports "openclaw" currently`, C.red));
    process.exit(1);
  }

  const { openclawSkills, lyrieSkills } = lyrieDirs();

  if (!existsSync(openclawSkills)) {
    console.error(c(`  Error: ~/.openclaw/workspace/skills/ not found`, C.red));
    console.log(c("  Is OpenClaw installed?", C.dim));
    process.exit(1);
  }

  mkdirSync(lyrieSkills, { recursive: true });

  // Walk openclaw skills and discover all SKILL.md files
  const loader = new SkillLoader();
  const manifests = await loader.discover(openclawSkills);

  if (manifests.length === 0) {
    console.log(c("  No SKILL.md files found in OpenClaw skills directory.", C.yellow));
    return;
  }

  console.log(c(`\n  Importing ${manifests.length} skills from OpenClaw...\n`, C.bold));

  let imported = 0;
  let skipped = 0;

  for (const m of manifests) {
    const destDir = join(lyrieSkills, m.name);
    const destPath = join(destDir, "SKILL.md");

    if (existsSync(destPath)) {
      console.log(c(`  ↷ Skip (exists): ${m.name}`, C.dim));
      skipped++;
      continue;
    }

    mkdirSync(destDir, { recursive: true });
    copyFileSync(m.location, destPath);
    console.log(`  ${c("✓", C.green)} ${c(m.name, C.cyan)}`);
    imported++;
  }

  console.log(c(`\n  Done. Imported: ${imported}, Skipped: ${skipped}\n`, C.bold));
  console.log(c(`  Run \`lyrie skills list\` to verify.\n`, C.dim));
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help || !args.command) {
    printBanner();
    printHelp();
    return;
  }

  switch (args.command) {
    case "list":
      await cmdList(args);
      break;
    case "search":
      await cmdSearch(args);
      break;
    case "info":
      await cmdInfo(args);
      break;
    case "run":
      await cmdRun(args);
      break;
    case "install":
      await cmdInstall(args);
      break;
    case "import":
      await cmdImport(args);
      break;
    default:
      console.error(c(`  Unknown command: ${args.command}`, C.red));
      printHelp();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(c(`\n  Fatal: ${err.message}`, C.red, C.bold));
  process.exit(1);
});
