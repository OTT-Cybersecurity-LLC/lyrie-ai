/**
 * @lyrie/agt-bridge — PolicyGenerator tests
 * © OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { PolicyGenerator } from "../src/policy";
import type { ScopeDeclaration } from "../src/types";

const gen = new PolicyGenerator();

describe("PolicyGenerator.generate()", () => {
  it("produces a v1.0 policy", () => {
    const policy = gen.generate({ agentId: "test-agent" });
    expect(policy.version).toBe("1.0");
  });

  it("sets the correct agentId", () => {
    const policy = gen.generate({ agentId: "lyrie-core" });
    expect(policy.agent.id).toBe("lyrie-core");
  });

  it("enables all 10 OWASP ASI controls by default", () => {
    const policy = gen.generate({ agentId: "test-agent" });
    const controls = policy.controls;
    expect(controls.asi01_prompt_injection).toBe(true);
    expect(controls.asi02_resource_overuse).toBe(true);
    expect(controls.asi03_tool_misuse).toBe(true);
    expect(controls.asi04_excessive_agency).toBe(true);
    expect(controls.asi05_sensitive_data_exposure).toBe(true);
    expect(controls.asi06_memory_poisoning).toBe(true);
    expect(controls.asi07_uncontrolled_subagents).toBe(true);
    expect(controls.asi08_trust_boundary_violation).toBe(true);
    expect(controls.asi09_unverified_outputs).toBe(true);
    expect(controls.asi10_audit_evasion).toBe(true);
  });

  it("respects control overrides while keeping others at default", () => {
    const policy = gen.generate({
      agentId: "test-agent",
      controls: { asi09_unverified_outputs: false },
    });
    expect(policy.controls.asi09_unverified_outputs).toBe(false);
    // All others stay on
    expect(policy.controls.asi01_prompt_injection).toBe(true);
    expect(policy.controls.asi10_audit_evasion).toBe(true);
  });

  it("defaults to maxCallsPerTurn = 25", () => {
    const policy = gen.generate({ agentId: "test-agent" });
    expect(policy.agent.maxCallsPerTurn).toBe(25);
  });

  it("respects custom maxCallsPerTurn", () => {
    const policy = gen.generate({ agentId: "test-agent", maxCallsPerTurn: 10 });
    expect(policy.agent.maxCallsPerTurn).toBe(10);
  });

  it("includes default dangerous denied tools", () => {
    const policy = gen.generate({ agentId: "test-agent" });
    expect(policy.agent.deniedTools).toContain("sudo");
    expect(policy.agent.deniedTools).toContain("su");
    expect(policy.agent.deniedTools).toContain("load_kernel_module");
  });

  it("merges operator denied tools with defaults", () => {
    const policy = gen.generate({
      agentId: "test-agent",
      deniedTools: ["custom_dangerous_tool"],
    });
    expect(policy.agent.deniedTools).toContain("sudo");
    expect(policy.agent.deniedTools).toContain("custom_dangerous_tool");
  });

  it("does not double-deny tools listed in both defaults and operator list", () => {
    const policy = gen.generate({
      agentId: "test-agent",
      deniedTools: ["sudo"],
    });
    const sudoCount = policy.agent.deniedTools.filter((t) => t === "sudo").length;
    expect(sudoCount).toBe(1);
  });

  it("puts high-risk tools in requireHumanApproval when allowed (wildcard case)", () => {
    const policy = gen.generate({ agentId: "test-agent", allowedTools: [] });
    expect(policy.agent.requireHumanApproval).toContain("exec");
    expect(policy.agent.requireHumanApproval).toContain("web_fetch");
  });

  it("puts specifically allowed high-risk tools in requireHumanApproval", () => {
    const policy = gen.generate({
      agentId: "test-agent",
      allowedTools: ["read", "exec"],
    });
    expect(policy.agent.requireHumanApproval).toContain("exec");
    expect(policy.agent.requireHumanApproval).not.toContain("read");
  });

  it("throws if agentId is empty", () => {
    expect(() => gen.generate({ agentId: "" })).toThrow();
  });

  it("throws if agentId is blank whitespace", () => {
    expect(() => gen.generate({ agentId: "   " })).toThrow();
  });

  it("throws if maxCallsPerTurn is 0", () => {
    expect(() =>
      gen.generate({ agentId: "test-agent", maxCallsPerTurn: 0 })
    ).toThrow();
  });

  it("throws if maxCallsPerTurn is negative", () => {
    expect(() =>
      gen.generate({ agentId: "test-agent", maxCallsPerTurn: -5 })
    ).toThrow();
  });

  it("serializes to valid JSON", () => {
    const policy = gen.generate({ agentId: "test-agent" });
    const json = gen.serialize(policy);
    const parsed = JSON.parse(json);
    expect(parsed.version).toBe("1.0");
  });
});
