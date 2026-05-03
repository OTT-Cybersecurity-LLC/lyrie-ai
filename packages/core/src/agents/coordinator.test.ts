/**
 * LyrieCoordinator mode tests.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { LyrieCoordinator, COORDINATOR_ALLOWED_TOOLS } from "./coordinator";
import type { Tool } from "../tools/tool-executor";

const t = (name: string): Tool => ({
  name,
  description: name,
  parameters: {},
  risk: "safe",
  async execute() {
    return { success: true, output: "" };
  },
});

describe("LyrieCoordinator", () => {
  test("filterTools strips disallowed tools (exec, read_file, write_file)", () => {
    const c = new LyrieCoordinator();
    const all = [t("exec"), t("read_file"), t("write_file"), t("agent_spawn"), t("tool_search")];
    const filtered = c.filterTools(all);
    const names = filtered.map((x) => x.name).sort();
    expect(names).toContain("agent_spawn");
    expect(names).toContain("tool_search");
    expect(names).not.toContain("exec");
    expect(names).not.toContain("read_file");
    expect(names).not.toContain("write_file");
  });

  test("isAllowed mirrors the allowlist", () => {
    const c = new LyrieCoordinator();
    expect(c.isAllowed("agent_spawn")).toBe(true);
    expect(c.isAllowed("exec")).toBe(false);
  });

  test("getSystemPromptAddendum names the spawn-only constraint", () => {
    const c = new LyrieCoordinator();
    const p = c.getSystemPromptAddendum();
    expect(p).toContain("COORDINATOR mode");
    expect(p).toContain("agent_spawn");
    expect(p).toContain("NOT call exec");
  });

  test("appendRules option extends the prompt", () => {
    const c = new LyrieCoordinator({ appendRules: "Extra rule X." });
    const p = c.getSystemPromptAddendum();
    expect(p).toContain("Extra rule X.");
  });

  test("custom allowlist overrides defaults", () => {
    const c = new LyrieCoordinator({ allowedTools: new Set(["only_this"]) });
    expect(c.isAllowed("agent_spawn")).toBe(false);
    expect(c.isAllowed("only_this")).toBe(true);
  });

  test("default allowlist contains the orchestration core", () => {
    expect(COORDINATOR_ALLOWED_TOOLS.has("agent_spawn")).toBe(true);
    expect(COORDINATOR_ALLOWED_TOOLS.has("agent_status")).toBe(true);
    expect(COORDINATOR_ALLOWED_TOOLS.has("report")).toBe(true);
  });
});
