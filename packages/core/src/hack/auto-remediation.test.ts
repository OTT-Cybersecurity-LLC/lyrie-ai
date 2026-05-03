/**
 * Lyrie Hack — Auto-Remediation tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, expect, it } from "bun:test";

import {
  AUTO_REMEDIATION_VERSION,
  suggestRemediation,
  suggestSecretRemediation,
} from "./auto-remediation";
import type { ValidatedFinding, RawFinding } from "../pentest/stages-validator";
import type { SecretFinding } from "./secret-detector";

function vf(over: Partial<RawFinding>): ValidatedFinding {
  const finding: RawFinding = {
    id: over.id ?? "test-1",
    title: over.title ?? "Test finding",
    severity: over.severity ?? "high",
    description: over.description ?? "demo",
    category: over.category,
    cwe: over.cwe,
    file: over.file,
    line: over.line,
    evidence: over.evidence,
    flow: over.flow,
  };
  return {
    finding,
    confirmed: true,
    stages: [],
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

function secret(over: Partial<SecretFinding>): SecretFinding {
  return {
    id: "lyrie-secret-test",
    type: over.type ?? "aws-access-key-id",
    severity: over.severity ?? "high",
    file: over.file ?? "x.js",
    line: over.line ?? 1,
    redactedSample: over.redactedSample ?? "AKIA***XX",
    length: over.length ?? 20,
    confidence: 0.99,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
}

describe("suggestRemediation", () => {
  it("emits a version tag", () => {
    expect(AUTO_REMEDIATION_VERSION).toMatch(/^lyrie-/);
  });

  it("suggests parameterized queries for SQLi (Python evidence)", () => {
    const r = suggestRemediation(vf({
      category: "sql-injection",
      evidence: `cursor.execute(f"SELECT * FROM x WHERE id = {id}")`,
    }))!;
    expect(r).toBeDefined();
    expect(r.diffHint?.after.toLowerCase()).toContain("%s");
    expect(r.referenceCwe).toBe("CWE-89");
  });

  it("suggests parameterized queries for SQLi (JS evidence)", () => {
    const r = suggestRemediation(vf({
      category: "sql-injection",
      evidence: "db.query(`SELECT * FROM x WHERE id = ${id}`)",
    }))!;
    expect(r.diffHint?.after).toContain("?");
  });

  it("suggests output encoding for XSS", () => {
    const r = suggestRemediation(vf({ category: "xss" }))!;
    expect(r.diffHint?.after.toLowerCase()).toMatch(/textcontent|dompurify/);
    expect(r.referenceCwe).toBe("CWE-79");
  });

  it("suggests SSRF allowlists with private-IP rejection", () => {
    const r = suggestRemediation(vf({ category: "ssrf" }))!;
    expect(r.description.toLowerCase()).toContain("allowlist");
    expect(r.referenceCwe).toBe("CWE-918");
  });

  it("suggests argv-array exec for shell injection", () => {
    const r = suggestRemediation(vf({
      category: "shell-injection",
      evidence: "exec(`convert ${filename} out.png`)",
      file: "server.ts",
    }))!;
    expect(r.diffHint?.after).toMatch(/execFile|argv/);
    expect(r.referenceCwe).toBe("CWE-78");
  });

  it("suggests argv-array exec for shell injection (Python)", () => {
    const r = suggestRemediation(vf({
      category: "shell-injection",
      evidence: `subprocess.call(f"convert {filename}", shell=True)`,
    }))!;
    expect(r.diffHint?.after).toMatch(/shell=False|subprocess\.run\(/);
  });

  it("suggests realpath checks for path traversal", () => {
    const r = suggestRemediation(vf({ category: "path-traversal" }))!;
    expect(r.diffHint?.after).toContain("startsWith(root");
    expect(r.referenceCwe).toBe("CWE-22");
  });

  it("suggests safe deserializers (yaml.safe_load) for YAML evidence", () => {
    const r = suggestRemediation(vf({
      category: "deserialization",
      evidence: "yaml.load(payload)",
    }))!;
    expect(r.diffHint?.after).toContain("safe_load");
  });

  it("suggests JSON over pickle for pickle evidence", () => {
    const r = suggestRemediation(vf({
      category: "deserialization",
      evidence: "pickle.loads(request.body)",
    }))!;
    expect(r.diffHint?.after.toLowerCase()).toContain("json");
  });

  it("suggests env-var redirection for secret exposure", () => {
    const r = suggestRemediation(vf({ category: "secret-exposure" }))!;
    expect(r.diffHint?.after).toContain("process.env");
    expect(r.referenceCwe).toBe("CWE-798");
  });

  it("suggests open-redirect allowlists", () => {
    const r = suggestRemediation(vf({ category: "open-redirect" }))!;
    expect(r.diffHint?.after).toContain("ALLOWED");
    expect(r.referenceCwe).toBe("CWE-601");
  });

  it("suggests ShieldGuard wrapping for prompt injection", () => {
    const r = suggestRemediation(vf({ category: "prompt-injection" }))!;
    expect(r.diffHint?.after).toContain("ShieldGuard");
  });

  it("returns null for uncovered categories", () => {
    const r = suggestRemediation(vf({ category: "race-condition" }));
    expect(r).toBeNull();
  });

  it("emits the Lyrie signature on every suggestion", () => {
    const r = suggestRemediation(vf({ category: "xss" }))!;
    expect(r.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });

  it("attaches a CWE reference URL", () => {
    const r = suggestRemediation(vf({ category: "ssrf" }))!;
    expect(r.referenceUrl).toMatch(/^https?:\/\//);
  });
});

describe("suggestSecretRemediation", () => {
  it("maps an AWS access key to the AWS_ACCESS_KEY_ID env var", () => {
    const r = suggestSecretRemediation(secret({ type: "aws-access-key-id" }));
    expect(r.diffHint?.after).toContain("AWS_ACCESS_KEY_ID");
  });

  it("maps an OpenAI key to OPENAI_API_KEY", () => {
    const r = suggestSecretRemediation(secret({ type: "openai-key" }));
    expect(r.diffHint?.after).toContain("OPENAI_API_KEY");
  });

  it("maps an Anthropic key to ANTHROPIC_API_KEY", () => {
    const r = suggestSecretRemediation(secret({ type: "anthropic-key" }));
    expect(r.diffHint?.after).toContain("ANTHROPIC_API_KEY");
  });

  it("emits the Lyrie signature", () => {
    const r = suggestSecretRemediation(secret({}));
    expect(r.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });
});
