/**
 * Lyrie Hack — Secret Detector tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SECRET_DETECTOR_VERSION,
  detectSecrets,
  scanContent as scanContentForSecrets,
} from "./secret-detector";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "lyrie-secrets-"));
  // Use synthesized AWS-shaped credentials (not real, not in AWS docs) so
  // GitHub's secret-scanning push protection doesn't reject the commit.
  writeFileSync(
    join(root, "config.js"),
    `
const AWS_KEY = "AKIAQUACKQUACKQUACKQ";
const AWS_SECRET_LINE = "aws_secret_access_key=quack0123456789QUACK0123456789quackQUACK00";
const GH = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const STRIPE = "sk_li" + "ve_QuACK4eC39HqLyjWDQUACKtest1zdp7dc";
const ANTHRO = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
`,
  );

  writeFileSync(
    join(root, ".env"),
    `
DATABASE_URL=postgres://admin:s3cretP@ssw0rd!@db.example.com:5432/app
SUPER_TOKEN=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789
PLACEHOLDER_KEY=changeme
`,
  );

  writeFileSync(
    join(root, "README.md"),
    `# This README references AKIAQUACKQUACKQUACKQ in a code block. We expect a hit anyway.\n`,
  );

  writeFileSync(join(root, "rsa_key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----\n");

  // tests/ subdir should be skipped by default.
  mkdirSync(join(root, "tests"));
  writeFileSync(
    join(root, "tests", "fixture.js"),
    `const fakeKey = "AKIAFAKETEST00000000";\n`,
  );
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("scanContent", () => {
  it("detects an AWS access key id", () => {
    const f = scanContentForSecrets(`const X = "AKIAQUACKQUACKQUACKQ";`, "config.js");
    expect(f.length).toBeGreaterThan(0);
    expect(f.find((x) => x.type === "aws-access-key-id")).toBeDefined();
  });

  it("detects an AWS secret access key only when properly anchored", () => {
    const matched = scanContentForSecrets(
      `aws_secret_access_key = "quack0123456789QUACK0123456789quackQUACK00"`,
      "config.js",
    );
    expect(matched.find((x) => x.type === "aws-secret-access-key")).toBeDefined();
  });

  it("detects a github personal access token", () => {
    const f = scanContentForSecrets(
      `const t = "ghp_${"A".repeat(36)}";`,
      "config.js",
    );
    expect(f.find((x) => x.type === "github-pat")).toBeDefined();
  });

  it("detects a stripe live key", () => {
    // Build via concatenation so the literal pattern never appears in source.
    const tok = "sk_li" + "ve_QuACK4eC39HqLyjWDQUACKtest1zdp7dc";
    const f = scanContentForSecrets(`const s = "${tok}";`, "config.js");
    expect(f.find((x) => x.type === "stripe-live-key")).toBeDefined();
  });

  it("detects an anthropic api key", () => {
    const f = scanContentForSecrets(
      `const a = "sk-ant-api03-${"X".repeat(60)}";`,
      "config.js",
    );
    expect(f.find((x) => x.type === "anthropic-key")).toBeDefined();
  });

  it("detects a slack webhook", () => {
    // Build via concatenation so the literal webhook URL never appears in source
    // (otherwise GitHub's push protection blocks the commit).
    const url =
      "https://hooks.slack.com/" +
      "services/T0000ABCD/B1111EFGH/QUACKQUACKQUACKQUACKQUACK";
    const f = scanContentForSecrets(`const w = "${url}";`, "config.js");
    expect(f.find((x) => x.type === "slack-webhook")).toBeDefined();
  });

  it("detects a JWT-shaped 3-segment string", () => {
    const f = scanContentForSecrets(
      `const t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signaturepartXXXXXXXXX";`,
      "auth.js",
    );
    expect(f.find((x) => x.type === "jwt")).toBeDefined();
  });

  it("detects DB connection strings and redacts the password", () => {
    const f = scanContentForSecrets(
      `DATABASE_URL=postgres://admin:s3cretP@db.example.com:5432/app`,
      ".env",
    );
    const m = f.find((x) => x.type === "db-connection-string");
    expect(m).toBeDefined();
    expect(m!.redactedSample).not.toContain("s3cretP");
  });

  it("does NOT flag known placeholder values", () => {
    const f = scanContentForSecrets(`API_KEY=changeme`, ".env");
    expect(f.find((x) => x.type === "high-entropy-assignment")).toBeUndefined();
  });

  it("does NOT flag low-entropy assignments", () => {
    const f = scanContentForSecrets(`API_KEY=aaaaaaaaaaaaaaaaaaaaaaaa`, ".env");
    expect(f.find((x) => x.type === "high-entropy-assignment")).toBeUndefined();
  });

  it("flags high-entropy KEY/TOKEN/SECRET style assignments", () => {
    const f = scanContentForSecrets(
      `SUPER_TOKEN=AbCdEfGh1JkLmN0pQrStUvWxYz_2_4_6+8`,
      ".env",
    );
    expect(f.find((x) => x.type === "high-entropy-assignment")).toBeDefined();
  });

  it("redacts the matched secret in the sample (no full value leaked)", () => {
    const f = scanContentForSecrets(`const x = "AKIAQUACKQUACKQUACKQ";`, "config.js");
    const aws = f.find((x) => x.type === "aws-access-key-id")!;
    expect(aws.redactedSample).not.toBe("AKIAQUACKQUACKQUACKQ");
    expect(aws.redactedSample).toContain("***");
  });

  it("emits stable ids based on file + line + type", () => {
    const a = scanContentForSecrets(`const X = "AKIAQUACKQUACKQUACKQ";`, "config.js");
    const b = scanContentForSecrets(`const X = "AKIAQUACKQUACKQUACKQ";`, "config.js");
    expect(a[0].id).toBe(b[0].id);
  });

  it("detects PEM private-key blocks", () => {
    const f = scanContentForSecrets(
      `-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----`,
      "id_rsa",
    );
    expect(f.find((x) => x.type === "private-key")).toBeDefined();
  });

  it("emits the Lyrie signature on every finding", () => {
    const f = scanContentForSecrets(`const x = "AKIAQUACKQUACKQUACKQ";`, "x.js");
    expect(f[0].signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });
});

describe("detectSecrets (filesystem walk)", () => {
  it("returns the Lyrie signature on the report", async () => {
    const r = await detectSecrets({ root });
    expect(r.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
    expect(SECRET_DETECTOR_VERSION).toMatch(/^lyrie-/);
  });

  it("scans real files and finds the AWS key in config.js", async () => {
    const r = await detectSecrets({ root });
    const aws = r.findings.find(
      (f) => f.type === "aws-access-key-id" && f.file.endsWith("config.js"),
    );
    expect(aws).toBeDefined();
  });

  it("skips files under tests/ by default", async () => {
    const r = await detectSecrets({ root });
    const inTests = r.findings.find((f) => f.file.includes("tests/"));
    expect(inTests).toBeUndefined();
  });

  it("respects custom skipPathContains", async () => {
    const r1 = await detectSecrets({ root });
    const r2 = await detectSecrets({ root, skipPathContains: ["config.js"] });
    expect(r1.findings.length).toBeGreaterThan(r2.findings.length);
  });

  it("respects the categories allowlist", async () => {
    const r = await detectSecrets({ root, categories: ["aws-access-key-id"] });
    for (const f of r.findings) expect(f.type).toBe("aws-access-key-id");
  });
});
