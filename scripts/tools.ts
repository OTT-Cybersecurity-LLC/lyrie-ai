#!/usr/bin/env bun
/**
 * `lyrie tools` — operator CLI for the Lyrie Tools Catalog.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run tools list                   # all tools, grouped by category
 *   bun run tools categories             # show all 19 categories
 *   bun run tools search <query>         # free-text search
 *   bun run tools tags                   # list tags
 *   bun run tools tag <tag>              # tools matching a tag
 *   bun run tools recommend "<intent>"   # natural-language recommend
 *   bun run tools status                 # installed / missing summary
 *   bun run tools show <id>              # full tool detail
 *
 * In-memory only; nothing persisted to disk.
 */

import {
  CATEGORIES,
  CATEGORY_BY_ID,
  ToolsCatalog,
  type ToolDefinition,
} from "../packages/core/src/tools-catalog";

const cmd = process.argv[2];
const args = process.argv.slice(3);

function header(title: string): void {
  console.log("");
  console.log(`🛡️  ${title}  ·  Lyrie.ai by OTT Cybersecurity LLC`);
  console.log("─".repeat(65));
}

function fmtTool(tool: ToolDefinition, status?: string): string {
  const cat = CATEGORY_BY_ID.get(tool.category);
  const badge = cat ? `${cat.emoji} ${cat.title}` : tool.category;
  const tags = tool.tags.length > 0 ? ` [${tool.tags.join(",")}]` : "";
  const stat = status ? `  ${status}` : "";
  return `  ${tool.id.padEnd(18)} ${tool.name.padEnd(28)} ${badge}${tags}${stat}`;
}

const cat = new ToolsCatalog();

switch (cmd) {
  case "list": {
    header("Lyrie Tools Catalog");
    for (const c of CATEGORIES) {
      const tools = cat.byCategoryList(c.id);
      if (tools.length === 0) continue;
      console.log("");
      console.log(`${c.emoji}  ${c.title}  (${tools.length})`);
      for (const t of tools) {
        console.log(`    ${t.id.padEnd(18)} ${t.name}`);
        console.log(`    ${"".padEnd(18)}   ${t.description}`);
      }
    }
    console.log("");
    const stats = cat.stats();
    console.log(`  total: ${stats.total}  installed: ${stats.installed}  missing: ${stats.missing}`);
    console.log(`  signature: ${cat.signature}`);
    console.log("");
    break;
  }

  case "categories": {
    header("Lyrie Tools Categories");
    for (const c of CATEGORIES) {
      const count = cat.byCategoryList(c.id).length;
      console.log(`  ${c.emoji}  ${c.title.padEnd(28)} ${count.toString().padStart(3)} tools`);
      console.log(`    ${"".padEnd(28)} ${c.description}`);
    }
    console.log("");
    break;
  }

  case "search": {
    const q = args.join(" ");
    if (!q) {
      console.error("Usage: lyrie tools search <query>");
      process.exit(2);
    }
    header(`Lyrie Tools Search: "${q}"`);
    const results = cat.search(q);
    if (results.length === 0) {
      console.log("  (no matches)");
    } else {
      for (const t of results) console.log(fmtTool(t));
    }
    console.log("");
    break;
  }

  case "tags": {
    header("Lyrie Tools Tags");
    const tagCounts = new Map<string, number>();
    for (const tool of cat.list()) {
      for (const tag of tool.tags) {
        tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
      }
    }
    const sorted = [...tagCounts.entries()].sort((a, b) => b[1] - a[1]);
    for (const [tag, count] of sorted) {
      console.log(`  ${tag.padEnd(14)} ${count} tools`);
    }
    console.log("");
    break;
  }

  case "tag": {
    const tag = args[0];
    if (!tag) {
      console.error("Usage: lyrie tools tag <tag>");
      process.exit(2);
    }
    header(`Lyrie Tools — tag "${tag}"`);
    const list = cat.byTagList(tag as any);
    if (list.length === 0) console.log("  (no tools with this tag)");
    else for (const t of list) console.log(fmtTool(t));
    console.log("");
    break;
  }

  case "recommend": {
    const intent = args.join(" ");
    if (!intent) {
      console.error('Usage: lyrie tools recommend "I want to <action>"');
      process.exit(2);
    }
    header(`Lyrie Tools Recommend: "${intent}"`);
    const results = cat.recommend(intent);
    if (results.length === 0) {
      console.log("  (no matches — try Lyrie's agent for richer routing)");
    } else {
      for (const t of results) console.log(fmtTool(t));
    }
    console.log("");
    break;
  }

  case "status": {
    header("Lyrie Tools Status");
    const stats = cat.stats();
    console.log(`  total:     ${stats.total}`);
    console.log(`  installed: ${stats.installed}`);
    console.log(`  missing:   ${stats.missing}`);
    console.log("");
    for (const tool of cat.list()) {
      const installed = cat.isInstalled(tool);
      const mark = installed.installed ? "✅" : "❌";
      const ver = installed.version ? ` (${installed.version})` : "";
      console.log(`  ${mark} ${tool.id.padEnd(18)} ${tool.name}${ver}`);
    }
    console.log("");
    break;
  }

  case "show": {
    const id = args[0];
    if (!id) {
      console.error("Usage: lyrie tools show <id>");
      process.exit(2);
    }
    const tool = cat.get(id);
    if (!tool) {
      console.error(`Tool not found: ${id}`);
      process.exit(1);
    }
    const c = CATEGORY_BY_ID.get(tool.category);
    const installed = cat.isInstalled(tool);
    header(`Lyrie Tool: ${tool.name}`);
    console.log(`  id:           ${tool.id}`);
    console.log(`  category:     ${c?.emoji ?? ""} ${c?.title ?? tool.category}`);
    console.log(`  tags:         ${tool.tags.join(", ")}`);
    console.log(`  license:      ${tool.license}`);
    console.log(`  os:           ${tool.supportedOS.join(", ")}`);
    console.log(`  homepage:     ${tool.homepage}`);
    console.log(`  description:  ${tool.description}`);
    console.log(`  install:      ${tool.install.command}`);
    console.log(`  detect:       ${tool.install.detect}${tool.install.versionFlag ? `  (version: ${tool.install.detect} ${tool.install.versionFlag})` : ""}`);
    console.log(`  installed:    ${installed.installed ? `✅ ${installed.detectedPath ?? ""}${installed.version ? `\n                ${installed.version}` : ""}` : "❌"}`);
    console.log(`  intents:`);
    for (const i of tool.intents) console.log(`    - ${i}`);
    console.log("");
    break;
  }

  default:
    console.error("Usage:");
    console.error("  lyrie tools list");
    console.error("  lyrie tools categories");
    console.error("  lyrie tools search <query>");
    console.error("  lyrie tools tags");
    console.error("  lyrie tools tag <tag>");
    console.error('  lyrie tools recommend "<intent>"');
    console.error("  lyrie tools status");
    console.error("  lyrie tools show <id>");
    process.exit(2);
}
