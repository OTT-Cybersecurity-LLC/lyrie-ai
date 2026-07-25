/**
 * trust.ts tests — ATP trust gate for MCP server connections.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { issueAic, makeScope, sha256Hex, RevocationRegistry } from "@lyrie/atp";
import type { AgentIdentityCertificate } from "@lyrie/atp";

import { evaluateMcpTrust } from "./trust";

const issueCert = (overrides: Partial<Parameters<typeof issueAic>[0]> = {}) =>
  issueAic({
    modelId: "anthropic/claude-sonnet-4-6",
    systemPromptHash: sha256Hex("system prompt"),
    scope: makeScope({ allowedTools: ["search", "fetch"], maxSubAgentDepth: 0 }),
    operatorId: "guy@lyrie.ai",
    ...overrides,
  });

describe("evaluateMcpTrust — no AIC present", () => {
  test("open policy: connects", () => {
    const d = evaluateMcpTrust("srv", {}, { policy: "open" });
    expect(d.outcome).toBe("connect");
  });

  test("warn-untrusted policy: connects (with a console warning)", () => {
    const d = evaluateMcpTrust("srv", {}, { policy: "warn-untrusted" });
    expect(d.outcome).toBe("connect");
  });

  test("require-atp policy: refuses", () => {
    const d = evaluateMcpTrust("srv", {}, { policy: "require-atp" });
    expect(d.outcome).toBe("refuse");
    if (d.outcome === "refuse") {
      expect(d.reason).toMatch(/no Agent Identity Certificate/);
    }
  });
});

describe("evaluateMcpTrust — valid, unexpired AIC", () => {
  test("connects under all three policies", () => {
    const { cert } = issueCert();
    for (const policy of ["open", "warn-untrusted", "require-atp"] as const) {
      const d = evaluateMcpTrust("srv", { aic: cert }, { policy, declaredTools: ["search", "fetch"] });
      expect(d.outcome).toBe("connect");
    }
  });
});

describe("evaluateMcpTrust — expired AIC", () => {
  test("refused under require-atp regardless of policy leniency", () => {
    const { cert } = issueCert({ issuedAt: Date.now() - 1000, ttlMs: 500 });
    const d = evaluateMcpTrust("srv", { aic: cert }, { policy: "require-atp", now: Date.now() });
    expect(d.outcome).toBe("refuse");
    if (d.outcome === "refuse") {
      expect(d.reason).toMatch(/ATP_CERT_EXPIRED/);
    }
  });

  test("also refused under open policy — a broken cert is worse than none", () => {
    const { cert } = issueCert({ issuedAt: Date.now() - 1000, ttlMs: 500 });
    const d = evaluateMcpTrust("srv", { aic: cert }, { policy: "open", now: Date.now() });
    expect(d.outcome).toBe("refuse");
  });
});

describe("evaluateMcpTrust — revoked AIC", () => {
  test("refused once revoked", () => {
    const { cert, certId } = issueCert();
    const registry = new RevocationRegistry();
    registry.revoke(certId);

    const d = evaluateMcpTrust(
      "srv",
      { aic: cert },
      { policy: "require-atp", isRevoked: registry.isRevoked, declaredTools: ["search"] },
    );
    expect(d.outcome).toBe("refuse");
    if (d.outcome === "refuse") {
      expect(d.reason).toMatch(/ATP_CERT_REVOKED/);
    }
  });

  test("connects before revocation, refused after", () => {
    const { cert, certId } = issueCert();
    const registry = new RevocationRegistry();

    const before = evaluateMcpTrust("srv", { aic: cert }, { policy: "require-atp", isRevoked: registry.isRevoked });
    expect(before.outcome).toBe("connect");

    registry.revoke(certId);
    const after = evaluateMcpTrust("srv", { aic: cert }, { policy: "require-atp", isRevoked: registry.isRevoked });
    expect(after.outcome).toBe("refuse");
  });
});

describe("evaluateMcpTrust — scope mismatch (downgrade, not refuse)", () => {
  test("server declares tools outside cert scope: connects with tool list downgraded", () => {
    const { cert } = issueCert(); // scope covers ["search", "fetch"]
    const d = evaluateMcpTrust(
      "srv",
      { aic: cert },
      { policy: "require-atp", declaredTools: ["search", "fetch", "delete_everything"] },
    );
    expect(d.outcome).toBe("connect");
    if (d.outcome === "connect") {
      expect(d.allowedTools).toEqual(["search", "fetch"]);
      expect(d.reason).toMatch(/does not cover tool/);
    }
  });

  test("full coverage: no downgrade reason emitted", () => {
    const { cert } = issueCert();
    const d = evaluateMcpTrust("srv", { aic: cert }, { policy: "open", declaredTools: ["search", "fetch"] });
    expect(d.outcome).toBe("connect");
    if (d.outcome === "connect") {
      expect(d.allowedTools).toEqual(["search", "fetch"]);
      expect(d.reason).toBeUndefined();
    }
  });

  test("wildcard scope covers everything declared, minus deniedTools", () => {
    const { cert } = issueCert({
      scope: makeScope({ allowedTools: ["*"], deniedTools: ["shell_exec"], maxSubAgentDepth: 0 }),
    });
    const d = evaluateMcpTrust(
      "srv",
      { aic: cert },
      { policy: "open", declaredTools: ["search", "fetch", "shell_exec"] },
    );
    expect(d.outcome).toBe("connect");
    if (d.outcome === "connect") {
      expect(d.allowedTools).toEqual(["search", "fetch"]);
    }
  });
});

describe("evaluateMcpTrust — malformed AIC", () => {
  test("tampered signature is refused", () => {
    const { cert } = issueCert();
    const tampered: AgentIdentityCertificate = { ...cert, operatorId: "attacker@evil.example" };
    const d = evaluateMcpTrust("srv", { aic: tampered }, { policy: "open" });
    expect(d.outcome).toBe("refuse");
    if (d.outcome === "refuse") {
      expect(d.reason).toMatch(/ATP_SIGNATURE_INVALID/);
    }
  });
});
