/**
 * Lyrie Scanner Adapters — Test Suite
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * All tests use injected mock executors (no real binaries required).
 * Tests cover:
 *   1. isAvailable() → false when binary not on PATH
 *   2. JSON output parsing → correct AdapterFinding conversion
 *   3. Trivy binary verification: mismatch → binaryVerified=false + warning
 *   4. Trivy binary verification: known hash → binaryVerified=true
 *   5. TruffleHog placeholder detection (Lyrie AI judgment layer)
 *   6. Orchestrator Phase 2 adapter dispatch
 *   7. Graceful error handling (missing tools, bad JSON)
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

import { describe, it, expect } from "bun:test";

import type { ShellExecutor } from "./nuclei";
import {
  NucleiAdapter,
  parseNucleiOutput,
} from "./nuclei";
import {
  TrivyAdapter,
  parseTrivyOutput,
  verifyBinaryHash,
  TRIVY_KNOWN_HASHES,
  type BinaryHasher,
} from "./trivy";
import { SemgrepAdapter, parseSemgrepOutput } from "./semgrep";
import { TruffleHogAdapter, parseTruffleHogOutput, detectPlaceholderHint } from "./trufflehog";
import {
  runAdapterPhase,
  adapterFindingToRaw,
} from "../hack/orchestrator";
import type { AdapterResult } from "./adapter-types";

// ─── Test helpers ─────────────────────────────────────────────────────────────

function makeExecutor(stdout: string, rejects = false): ShellExecutor {
  return async () => {
    if (rejects) throw new Error("command not found");
    return { stdout, stderr: "" };
  };
}

function makeFailingExecutor(stderr: string): ShellExecutor {
  return async () => ({ stdout: "", stderr });
}

// ─── Nuclei Adapter ───────────────────────────────────────────────────────────

describe("NucleiAdapter — isAvailable", () => {
  it("returns false when nuclei is not installed", async () => {
    const adapter = new NucleiAdapter(makeExecutor("", true));
    expect(await adapter.isAvailable()).toBe(false);
  });

  it("returns true when nuclei responds", async () => {
    const adapter = new NucleiAdapter(makeExecutor("nuclei version 3.0.0"));
    expect(await adapter.isAvailable()).toBe(true);
  });
});

describe("NucleiAdapter — scan", () => {
  it("returns empty findings when output is empty", async () => {
    const adapter = new NucleiAdapter(makeExecutor(""));
    const result = await adapter.scan("https://example.com");
    expect(result.findings).toHaveLength(0);
    expect(result.scannerName).toBe("nuclei");
  });

  it("returns findings from JSON-lines output", async () => {
    const line = JSON.stringify({
      "template-id": "sqli-error",
      info: { name: "SQL Injection", severity: "high", description: "SQLi detected" },
      "matched-at": "https://example.com/api",
    });
    const adapter = new NucleiAdapter(makeExecutor(line));
    const result = await adapter.scan("https://example.com");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
  });

  it("passes -t flag when templates are provided", async () => {
    let capturedArgs: string[] = [];
    const exec: ShellExecutor = async (_cmd, args) => {
      capturedArgs = args;
      return { stdout: "", stderr: "" };
    };
    const adapter = new NucleiAdapter(exec);
    await adapter.scan("http://t.com", { templates: ["cves/2021/"] });
    expect(capturedArgs).toContain("-t");
    expect(capturedArgs).toContain("cves/2021/");
  });

  it("passes -severity flag when severity filter is provided", async () => {
    let capturedArgs: string[] = [];
    const exec: ShellExecutor = async (_cmd, args) => {
      capturedArgs = args;
      return { stdout: "", stderr: "" };
    };
    const adapter = new NucleiAdapter(exec);
    await adapter.scan("http://t.com", { severity: ["critical", "high"] });
    expect(capturedArgs).toContain("-severity");
    expect(capturedArgs).toContain("critical,high");
  });
});

describe("parseNucleiOutput", () => {
  it("parses a full Nuclei finding with CVE/CWE/remediation", () => {
    const line = JSON.stringify({
      "template-id": "cve-2021-44228-log4j",
      info: {
        name: "Log4j RCE",
        severity: "critical",
        description: "Remote code execution via JNDI injection",
        classification: {
          "cve-id": "CVE-2021-44228",
          "cwe-id": "CWE-917",
        },
        remediation: "Upgrade Log4j to 2.17.1+",
      },
      "matched-at": "https://example.com/login",
    });

    const [f] = parseNucleiOutput(line);
    expect(f.id).toBe("cve-2021-44228-log4j");
    expect(f.title).toBe("Log4j RCE");
    expect(f.severity).toBe("critical");
    expect(f.cve).toBe("CVE-2021-44228");
    expect(f.cwe).toBe("CWE-917");
    expect(f.location?.file).toBe("https://example.com/login");
    expect(f.remediation).toBe("Upgrade Log4j to 2.17.1+");
  });

  it("parses multiple findings from JSON-lines", () => {
    const raw = [
      JSON.stringify({ "template-id": "t1", info: { name: "XSS", severity: "medium", description: "d" }, "matched-at": "http://a.com" }),
      JSON.stringify({ "template-id": "t2", info: { name: "SQLi", severity: "high", description: "d" }, host: "http://b.com" }),
    ].join("\n");

    const findings = parseNucleiOutput(raw);
    expect(findings).toHaveLength(2);
    expect(findings[0].severity).toBe("medium");
    expect(findings[1].severity).toBe("high");
  });

  it("handles cve-id as array (takes first)", () => {
    const line = JSON.stringify({
      "template-id": "t",
      info: { name: "T", severity: "high", description: "d", classification: { "cve-id": ["CVE-2021-001", "CVE-2021-002"] } },
    });
    expect(parseNucleiOutput(line)[0].cve).toBe("CVE-2021-001");
  });

  it("maps unknown severity to info", () => {
    const line = JSON.stringify({ "template-id": "t", info: { name: "T", severity: "unknown", description: "d" } });
    expect(parseNucleiOutput(line)[0].severity).toBe("info");
  });

  it("skips non-JSON lines gracefully", () => {
    const raw = `[INF] starting\n${JSON.stringify({ "template-id": "t", info: { name: "T", severity: "low", description: "d" } })}\n[WRN] done`;
    expect(parseNucleiOutput(raw)).toHaveLength(1);
  });

  it("returns empty findings for empty string", () => {
    expect(parseNucleiOutput("")).toHaveLength(0);
  });
});

// ─── Trivy Adapter ────────────────────────────────────────────────────────────

describe("TrivyAdapter — isAvailable", () => {
  it("returns false when trivy not on PATH", async () => {
    const adapter = new TrivyAdapter({ whichResolver: () => null });
    expect(await adapter.isAvailable()).toBe(false);
  });

  it("returns true when trivy is found", async () => {
    const adapter = new TrivyAdapter({ whichResolver: () => "/usr/local/bin/trivy" });
    expect(await adapter.isAvailable()).toBe(true);
  });
});

describe("TrivyAdapter — binary verification", () => {
  const MOCK_HASH = "aabbccdd" + "0".repeat(56);
  const KNOWN_HASHES = new Set([MOCK_HASH]);
  const mockHasher: BinaryHasher = () => MOCK_HASH;
  const wrongHasher: BinaryHasher = () => "deadbeef" + "0".repeat(56);

  const alwaysExists = () => true;

  it("returns verified=true when hash matches known-good", () => {
    const result = verifyBinaryHash("/usr/local/bin/trivy", KNOWN_HASHES, mockHasher, alwaysExists);
    expect(result.verified).toBe(true);
    expect(result.hash).toBe(MOCK_HASH);
  });

  it("returns verified=false with warning when hash mismatches", () => {
    const result = verifyBinaryHash("/usr/local/bin/trivy", KNOWN_HASHES, wrongHasher, alwaysExists);
    expect(result.verified).toBe(false);
    expect(result.warning).toMatch(/mismatch/);
  });

  it("returns verified=false with placeholder warning when only placeholders registered", () => {
    const result = verifyBinaryHash("/usr/local/bin/trivy", TRIVY_KNOWN_HASHES, mockHasher, alwaysExists);
    expect(result.verified).toBe(false);
    expect(result.warning).toMatch(/placeholder/i);
  });

  it("scan() sets binaryVerified=false in result when hash mismatches", async () => {
    const trivyJson = JSON.stringify({ Results: [] });
    const adapter = new TrivyAdapter({
      executor: makeExecutor(trivyJson),
      whichResolver: () => "/usr/local/bin/trivy",
      hasher: wrongHasher,
      knownHashes: KNOWN_HASHES,
      existsCheck: () => true,
    });
    const result = await adapter.scan("/some/path");
    expect(result.binaryVerified).toBe(false);
    expect(result.warnings?.[0]).toMatch(/mismatch/);
  });

  it("scan() sets binaryVerified=true when hash matches", async () => {
    const trivyJson = JSON.stringify({ Results: [] });
    const adapter = new TrivyAdapter({
      executor: makeExecutor(trivyJson),
      whichResolver: () => "/usr/local/bin/trivy",
      hasher: mockHasher,
      knownHashes: KNOWN_HASHES,
      existsCheck: () => true,
    });
    const result = await adapter.scan("/some/path");
    expect(result.binaryVerified).toBe(true);
    expect(result.warnings).toBeUndefined();
  });

  it("scan() skips verification when skipVerification=true", async () => {
    const adapter = new TrivyAdapter({
      executor: makeExecutor(JSON.stringify({ Results: [] })),
      whichResolver: () => "/usr/local/bin/trivy",
    });
    const result = await adapter.scan("/some/path", { skipVerification: true });
    expect(result.binaryVerified).toBeUndefined();
    expect(result.warnings).toBeUndefined();
  });
});

describe("parseTrivyOutput", () => {
  it("parses vulnerability findings correctly", () => {
    const raw = JSON.stringify({
      Results: [{
        Target: "alpine:3.17",
        Vulnerabilities: [{
          VulnerabilityID: "CVE-2023-1234",
          PkgName: "openssl",
          Title: "OpenSSL buffer overflow",
          Description: "A buffer overflow in OpenSSL",
          Severity: "HIGH",
          FixedVersion: "3.0.8-r3",
          CweIDs: ["CWE-122"],
        }],
      }],
    });

    const [f] = parseTrivyOutput(raw);
    expect(f.id).toBe("CVE-2023-1234");
    expect(f.severity).toBe("high");
    expect(f.cve).toBe("CVE-2023-1234");
    expect(f.cwe).toBe("CWE-122");
    expect(f.remediation).toBe("Upgrade to 3.0.8-r3");
    expect(f.location?.file).toContain("alpine");
  });

  it("parses misconfiguration findings with line number", () => {
    const raw = JSON.stringify({
      Results: [{
        Target: "Dockerfile",
        Misconfigurations: [{
          ID: "DS002",
          Title: "Image user should not be root",
          Description: "Running as root",
          Severity: "CRITICAL",
          Resolution: "Add USER directive",
          CauseMetadata: { StartLine: 10 },
        }],
      }],
    });

    const [f] = parseTrivyOutput(raw);
    expect(f.id).toBe("DS002");
    expect(f.severity).toBe("critical");
    expect(f.location?.line).toBe(10);
    expect(f.remediation).toBe("Add USER directive");
  });

  it("parses secret findings", () => {
    const raw = JSON.stringify({
      Results: [{
        Target: "config/prod.yml",
        Secrets: [{
          RuleID: "aws-access-key-id",
          Title: "AWS Access Key",
          Severity: "CRITICAL",
          StartLine: 42,
          Match: "AKIA***",
        }],
      }],
    });

    const [f] = parseTrivyOutput(raw);
    expect(f.id).toBe("aws-access-key-id");
    expect(f.location?.line).toBe(42);
  });

  it("maps UNKNOWN severity to info", () => {
    const raw = JSON.stringify({
      Results: [{
        Target: "test",
        Vulnerabilities: [{
          VulnerabilityID: "GHSA-xxx",
          Severity: "UNKNOWN",
          Title: "T",
          Description: "D",
        }],
      }],
    });
    expect(parseTrivyOutput(raw)[0].severity).toBe("info");
  });

  it("returns empty for invalid JSON", () => {
    expect(parseTrivyOutput("not json")).toHaveLength(0);
  });

  it("returns empty for empty Results", () => {
    expect(parseTrivyOutput(JSON.stringify({ Results: [] }))).toHaveLength(0);
  });
});

// ─── Semgrep Adapter ──────────────────────────────────────────────────────────

describe("SemgrepAdapter — isAvailable", () => {
  it("returns false when executor throws", async () => {
    const adapter = new SemgrepAdapter(makeExecutor("", true));
    expect(await adapter.isAvailable()).toBe(false);
  });

  it("returns true when semgrep responds", async () => {
    const adapter = new SemgrepAdapter(makeExecutor("semgrep 1.60.0"));
    expect(await adapter.isAvailable()).toBe(true);
  });
});

describe("SemgrepAdapter — scan", () => {
  it("uses --config auto by default", async () => {
    let capturedArgs: string[] = [];
    const exec: ShellExecutor = async (_cmd, args) => {
      capturedArgs = args;
      return { stdout: JSON.stringify({ results: [] }), stderr: "" };
    };
    const adapter = new SemgrepAdapter(exec);
    await adapter.scan("/code");
    expect(capturedArgs).toContain("--config");
    expect(capturedArgs).toContain("auto");
  });

  it("uses custom config when provided", async () => {
    let capturedArgs: string[] = [];
    const exec: ShellExecutor = async (_cmd, args) => {
      capturedArgs = args;
      return { stdout: JSON.stringify({ results: [] }), stderr: "" };
    };
    const adapter = new SemgrepAdapter(exec);
    await adapter.scan("/code", { config: "p/owasp-top-ten" });
    expect(capturedArgs).toContain("p/owasp-top-ten");
  });

  it("returns warning when semgrep fails with stderr and no stdout", async () => {
    const adapter = new SemgrepAdapter(makeFailingExecutor("semgrep: internal error"));
    const result = await adapter.scan("/code");
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings![0]).toContain("semgrep failed");
  });
});

describe("parseSemgrepOutput", () => {
  it("parses a finding with full metadata", () => {
    const raw = JSON.stringify({
      results: [{
        check_id: "javascript.lang.security.audit.sqli.pg-sqli",
        path: "src/db/query.js",
        start: { line: 45 },
        extra: {
          message: "SQL injection via unsanitized input",
          severity: "ERROR",
          metadata: { cwe: ["CWE-89"] },
          fix: "Use parameterized queries",
        },
      }],
    });

    const [f] = parseSemgrepOutput(raw);
    expect(f.id).toBe("javascript.lang.security.audit.sqli.pg-sqli");
    expect(f.severity).toBe("high"); // ERROR → high
    expect(f.cwe).toBe("CWE-89");
    expect(f.location?.file).toBe("src/db/query.js");
    expect(f.location?.line).toBe(45);
    expect(f.remediation).toBe("Use parameterized queries");
  });

  it("maps WARNING → medium", () => {
    const raw = JSON.stringify({
      results: [{ check_id: "t", path: "f.py", extra: { message: "m", severity: "WARNING" } }],
    });
    expect(parseSemgrepOutput(raw)[0].severity).toBe("medium");
  });

  it("maps INFO → info", () => {
    const raw = JSON.stringify({
      results: [{ check_id: "t", path: "f.py", extra: { message: "m", severity: "INFO" } }],
    });
    expect(parseSemgrepOutput(raw)[0].severity).toBe("info");
  });

  it("handles cwe as array (takes first)", () => {
    const raw = JSON.stringify({
      results: [{
        check_id: "t",
        path: "f.js",
        extra: { message: "m", severity: "ERROR", metadata: { cwe: ["CWE-89", "CWE-564"] } },
      }],
    });
    expect(parseSemgrepOutput(raw)[0].cwe).toBe("CWE-89");
  });

  it("returns empty for invalid JSON", () => {
    expect(parseSemgrepOutput("not json")).toHaveLength(0);
  });

  it("returns empty for empty results", () => {
    expect(parseSemgrepOutput(JSON.stringify({ results: [] }))).toHaveLength(0);
  });
});

// ─── TruffleHog Adapter ───────────────────────────────────────────────────────

describe("TruffleHogAdapter — isAvailable", () => {
  it("returns false when trufflehog throws", async () => {
    const adapter = new TruffleHogAdapter(makeExecutor("", true));
    expect(await adapter.isAvailable()).toBe(false);
  });

  it("returns true when trufflehog responds", async () => {
    const adapter = new TruffleHogAdapter(makeExecutor("trufflehog v3.63.4"));
    expect(await adapter.isAvailable()).toBe(true);
  });
});

describe("TruffleHogAdapter — scan", () => {
  it("uses filesystem mode and --no-update", async () => {
    let capturedArgs: string[] = [];
    const exec: ShellExecutor = async (_cmd, args) => {
      capturedArgs = args;
      return { stdout: "", stderr: "" };
    };
    const adapter = new TruffleHogAdapter(exec);
    await adapter.scan("/some/codebase");
    expect(capturedArgs).toContain("filesystem");
    expect(capturedArgs).toContain("/some/codebase");
    expect(capturedArgs).toContain("--no-update");
    expect(capturedArgs).toContain("--json");
  });

  it("returns warning when trufflehog fails with no output", async () => {
    const adapter = new TruffleHogAdapter(makeFailingExecutor("trufflehog: internal error"));
    const result = await adapter.scan("/code");
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toBeDefined();
  });
});

describe("parseTruffleHogOutput", () => {
  it("parses verified secret as critical", () => {
    const line = JSON.stringify({
      DetectorName: "AWS",
      Verified: true,
      Redacted: "AKIA***",
      SourceMetadata: { Data: { Filesystem: { file: "config/prod.env", line: 5 } } },
    });

    const [f] = parseTruffleHogOutput(line);
    expect(f.severity).toBe("critical");
    expect(f.title).toContain("verified live");
    expect(f.location?.file).toBe("config/prod.env");
    expect(f.location?.line).toBe(5);
    expect((f.extra as any).verified).toBe(true);
  });

  it("parses unverified secret as high", () => {
    const line = JSON.stringify({
      DetectorName: "Github",
      Verified: false,
      SourceMetadata: { Data: { Filesystem: { file: "scripts/deploy.sh", line: 12 } } },
    });

    const [f] = parseTruffleHogOutput(line);
    expect(f.severity).toBe("high");
    expect(f.title).not.toContain("verified live");
  });

  it("parses Git source metadata", () => {
    const line = JSON.stringify({
      DetectorName: "Slack",
      Verified: false,
      SourceMetadata: { Data: { Git: { file: "src/notify.ts", line: 20 } } },
    });
    const [f] = parseTruffleHogOutput(line);
    expect(f.location?.file).toBe("src/notify.ts");
    expect(f.location?.line).toBe(20);
  });

  it("handles multiple findings from JSON-lines", () => {
    const lines = [
      JSON.stringify({ DetectorName: "AWS", Verified: true, SourceMetadata: { Data: { Filesystem: { file: "a.env" } } } }),
      JSON.stringify({ DetectorName: "Slack", Verified: false, SourceMetadata: { Data: { Filesystem: { file: "b.ts" } } } }),
    ].join("\n");

    const findings = parseTruffleHogOutput(lines);
    expect(findings).toHaveLength(2);
    expect(findings[0].severity).toBe("critical");
    expect(findings[1].severity).toBe("high");
  });

  it("returns empty for invalid JSON lines", () => {
    expect(parseTruffleHogOutput("not json\nalso not\n")).toHaveLength(0);
  });
});

describe("detectPlaceholderHint — Lyrie AI judgment layer", () => {
  it("flags secrets in test/ directories", () => {
    const hint = detectPlaceholderHint({ file: "tests/fixtures/sample.env", line: 3 }, "some-value");
    expect(hint).toContain("example/fixture placeholder");
  });

  it("flags secrets in example/ directories", () => {
    const hint = detectPlaceholderHint({ file: "examples/basic/config.yml" }, "something");
    expect(hint).toContain("example/fixture placeholder");
  });

  it("flags known AWS example key AKIAIOSFODNN7EXAMPLE", () => {
    const hint = detectPlaceholderHint({ file: "docs/guide.md" }, "AKIAIOSFODNN7EXAMPLE");
    expect(hint).toBeTruthy();
    expect(hint).toContain("placeholder");
  });

  it("does NOT flag secrets in production paths", () => {
    const hint = detectPlaceholderHint({ file: "src/billing/payments.ts", line: 8 }, "sk_live_realkey123");
    expect(hint).toBeUndefined();
  });

  it("returns undefined when no location", () => {
    expect(detectPlaceholderHint(undefined, "anything")).toBeUndefined();
  });

  it("adds placeholder hint to TruffleHog description for test-dir secrets", () => {
    const line = JSON.stringify({
      DetectorName: "AWS",
      Verified: false,
      Redacted: "AKIA***",
      SourceMetadata: { Data: { Filesystem: { file: "spec/fixtures/aws.env" } } },
    });
    const [f] = parseTruffleHogOutput(line);
    expect(f.description).toContain("Lyrie note:");
  });

  it("does NOT add hint for real production secrets", () => {
    const line = JSON.stringify({
      DetectorName: "Stripe",
      Verified: true,
      Redacted: "sk_live_***",
      SourceMetadata: { Data: { Filesystem: { file: "src/billing/stripe.ts", line: 8 } } },
    });
    const [f] = parseTruffleHogOutput(line);
    expect(f.description).not.toContain("Lyrie note:");
    expect(f.severity).toBe("critical");
  });
});

// ─── Orchestrator — Phase 2 adapter dispatch ──────────────────────────────────

function makeMockAdapter(available: boolean, findings: any[] = []) {
  return {
    name: "mock",
    version: "1.0",
    isAvailable: async () => available,
    scan: async () => ({
      findings,
      scannerName: "mock",
      scannerVersion: "1.0",
      durationMs: 10,
    } satisfies AdapterResult),
  } as any;
}

describe("Orchestrator — runAdapterPhase", () => {
  it("skips all adapters when adapters='none'", async () => {
    let scanned = false;
    const mockAdapter = {
      name: "mock",
      version: "1",
      isAvailable: async () => true,
      scan: async () => { scanned = true; return { findings: [], scannerName: "m", scannerVersion: "1", durationMs: 0 }; },
    } as any;

    await runAdapterPhase("/target", {
      adapters: "none",
      _adapterOverrides: { nuclei: mockAdapter, trivy: mockAdapter, semgrep: mockAdapter, trufflehog: mockAdapter },
    });

    expect(scanned).toBe(false);
  });

  it("skips unavailable adapters (isAvailable=false)", async () => {
    const nuclei = makeMockAdapter(false);
    const trivy = makeMockAdapter(false);
    const semgrep = makeMockAdapter(false);
    const trufflehog = makeMockAdapter(false);

    const result = await runAdapterPhase("/target", {
      adapters: "all",
      _adapterOverrides: { nuclei, trivy, semgrep, trufflehog },
    });

    expect(result.adapterFindings).toHaveLength(0);
  });

  it("runs all available adapters when adapters='all'", async () => {
    const finding = { id: "t1", title: "Test", severity: "high" as const, description: "d" };
    const nuclei = makeMockAdapter(true, [finding]);
    const trivy = makeMockAdapter(true, [finding]);
    const semgrep = makeMockAdapter(true, [finding]);
    const trufflehog = makeMockAdapter(true, [{ ...finding, id: "t2" }]);

    const result = await runAdapterPhase("/target", {
      adapters: "all",
      _adapterOverrides: { nuclei, trivy, semgrep, trufflehog },
    });

    expect(result.adapterFindings).toHaveLength(4);
    expect(result.adapterResults).toHaveLength(4);
  });

  it("runs only named adapters from a Set", async () => {
    const finding = { id: "x", title: "T", severity: "medium" as const, description: "d" };
    let semgrepScanned = false;
    let trufflehogScanned = false;

    const semgrepMock = {
      name: "semgrep", version: "1",
      isAvailable: async () => true,
      scan: async () => { semgrepScanned = true; return { findings: [], scannerName: "s", scannerVersion: "1", durationMs: 0 }; },
    } as any;
    const trufflehogMock = {
      name: "trufflehog", version: "1",
      isAvailable: async () => true,
      scan: async () => { trufflehogScanned = true; return { findings: [], scannerName: "t", scannerVersion: "1", durationMs: 0 }; },
    } as any;

    const result = await runAdapterPhase("/target", {
      adapters: new Set(["nuclei", "trivy"]),
      _adapterOverrides: {
        nuclei: makeMockAdapter(true, [finding]),
        trivy: makeMockAdapter(true, [finding]),
        semgrep: semgrepMock,
        trufflehog: trufflehogMock,
      },
    });

    expect(result.adapterFindings).toHaveLength(2);
    expect(semgrepScanned).toBe(false);
    expect(trufflehogScanned).toBe(false);
  });

  it("defaults to 'none' in quick mode", async () => {
    let scanned = false;
    const mockAdapter = {
      name: "m", version: "1",
      isAvailable: async () => true,
      scan: async () => { scanned = true; return { findings: [], scannerName: "m", scannerVersion: "1", durationMs: 0 }; },
    } as any;

    await runAdapterPhase("/target", {
      mode: "quick",
      _adapterOverrides: { nuclei: mockAdapter, trivy: mockAdapter, semgrep: mockAdapter, trufflehog: mockAdapter },
    });

    expect(scanned).toBe(false);
  });

  it("preserves Trivy binaryVerified=false in adapterResults", async () => {
    const trivyResult: AdapterResult = {
      findings: [],
      scannerName: "trivy",
      scannerVersion: "0.x",
      durationMs: 5,
      binaryVerified: false,
      warnings: ["Trivy binary hash mismatch — possible supply-chain compromise."],
    };
    const trivyMock = {
      name: "trivy", version: "0.x",
      isAvailable: async () => true,
      scan: async () => trivyResult,
    } as any;

    const result = await runAdapterPhase("/target", {
      adapters: new Set(["trivy"]),
      _adapterOverrides: {
        nuclei: makeMockAdapter(false),
        trivy: trivyMock,
        semgrep: makeMockAdapter(false),
        trufflehog: makeMockAdapter(false),
      },
    });

    const tr = result.adapterResults.find(r => r.scannerName === "trivy");
    expect(tr?.binaryVerified).toBe(false);
    expect(tr?.warnings?.[0]).toMatch(/supply-chain/);
  });
});

describe("adapterFindingToRaw", () => {
  it("converts AdapterFinding to RawFinding with all fields", () => {
    const f = {
      id: "CVE-2023-1234",
      title: "Test Vuln",
      severity: "critical" as const,
      description: "A critical vulnerability",
      location: { file: "src/app.ts", line: 10 },
      cwe: "CWE-89",
    };

    const raw = adapterFindingToRaw(f, "nuclei");
    expect(raw.id).toBe("nuclei-CVE-2023-1234");
    expect(raw.severity).toBe("critical");
    expect(raw.file).toBe("src/app.ts");
    expect(raw.line).toBe(10);
    expect(raw.cwe).toBe("CWE-89");
  });

  it("defaults category to 'other'", () => {
    const f = { id: "t", title: "T", severity: "info" as const, description: "d" };
    const raw = adapterFindingToRaw(f, "trivy");
    expect(raw.category).toBe("other");
  });

  it("prefixes id with source name", () => {
    const f = { id: "rule-001", title: "T", severity: "low" as const, description: "d" };
    expect(adapterFindingToRaw(f, "semgrep").id).toBe("semgrep-rule-001");
    expect(adapterFindingToRaw(f, "trufflehog").id).toBe("trufflehog-rule-001");
  });
});
