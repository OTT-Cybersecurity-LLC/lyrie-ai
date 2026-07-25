/**
 * diff.test.ts — delta-only finding tests for watch/diff.ts.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { diffPostureSnapshots } from "./diff";
import type { PostureSnapshot } from "./types";

function baseSnapshot(overrides: Partial<PostureSnapshot> = {}): PostureSnapshot {
  return {
    domain: "example.com",
    takenAt: Date.now(),
    headers: {
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=63072000",
    },
    exposedPaths: [
      { path: "/.env", exposed: false, status: 404 },
      { path: "/.git/config", exposed: false, status: 404 },
    ],
    subdomains: [],
    ...overrides,
  };
}

describe("diffPostureSnapshots", () => {
  test("first run (no previous snapshot) produces no findings — establishes baseline", () => {
    const current = baseSnapshot();
    const findings = diffPostureSnapshots("example.com", undefined, current);
    expect(findings).toEqual([]);
  });

  test("no changes between runs produces no findings (idle)", () => {
    const prev = baseSnapshot({ takenAt: Date.now() - 60_000 });
    const current = baseSnapshot();
    const findings = diffPostureSnapshots("example.com", prev, current);
    expect(findings).toEqual([]);
  });

  test("removed CSP header produces a high-severity finding", () => {
    const prev = baseSnapshot();
    const current = baseSnapshot({ headers: { "strict-transport-security": "max-age=63072000" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.id.includes("header-removed-content-security-policy"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  test("changed header value produces a medium-severity finding", () => {
    const prev = baseSnapshot();
    const current = baseSnapshot({
      headers: {
        "content-security-policy": "default-src *", // weakened
        "strict-transport-security": "max-age=63072000",
      },
    });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.id.includes("header-changed-content-security-policy"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  test("newly-exposed path produces a critical finding", () => {
    const prev = baseSnapshot();
    const current = baseSnapshot({
      exposedPaths: [
        { path: "/.env", exposed: true, status: 200 },
        { path: "/.git/config", exposed: false, status: 404 },
      ],
    });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.title.includes("/.env"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  test("server/version header disclosure change produces a low-severity finding", () => {
    const prev = baseSnapshot({ headers: { server: "nginx/1.24" } });
    const current = baseSnapshot({ headers: { server: "nginx/1.25" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.title.includes("server disclosure"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("low");
  });

  test("TLS cert-expiry-approaching produces a warning-severity finding", () => {
    const now = Date.now();
    const prev = baseSnapshot({ takenAt: now - 60_000, tls: { expiresAt: now + 30 * 24 * 60 * 60 * 1000 } });
    const current = baseSnapshot({ takenAt: now, tls: { expiresAt: now + 10 * 24 * 60 * 60 * 1000 } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.id.includes("tls-expiry-approaching"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  test("TLS already-expired produces a critical finding", () => {
    const now = Date.now();
    const prev = baseSnapshot({ takenAt: now - 60_000, tls: { expiresAt: now + 30 * 24 * 60 * 60 * 1000 } });
    const current = baseSnapshot({ takenAt: now, tls: { expiresAt: now - 1000 } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.id.includes("tls-expiry-approaching"));
    expect(finding?.severity).toBe("critical");
  });

  test("TLS expiry warning does not repeat on subsequent ticks once already warned", () => {
    const now = Date.now();
    const prev = baseSnapshot({ takenAt: now - 60_000, tls: { expiresAt: now - 60_000 + 5 * 24 * 60 * 60 * 1000 } });
    const current = baseSnapshot({ takenAt: now, tls: { expiresAt: now + 4 * 24 * 60 * 60 * 1000 } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    expect(findings.find((f) => f.id.includes("tls-expiry-approaching"))).toBeUndefined();
  });

  test("TLS fingerprint change produces a medium-severity finding", () => {
    const prev = baseSnapshot({ tls: { expiresAt: Date.now() + 1e9, fingerprintSha256: "aaa" } });
    const current = baseSnapshot({ tls: { expiresAt: Date.now() + 1e9, fingerprintSha256: "bbb" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.id.includes("tls-fingerprint-changed"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  test("domain becoming unreachable produces a high-severity finding and skips other diffs", () => {
    const prev = baseSnapshot();
    const current = baseSnapshot({ unreachable: true, error: "ECONNREFUSED", headers: {} });
    const findings = diffPostureSnapshots("example.com", prev, current);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("unreachable");
  });

  test("domain recovering from unreachable produces an info finding", () => {
    const prev = baseSnapshot({ unreachable: true, error: "timeout" });
    const current = baseSnapshot();
    const findings = diffPostureSnapshots("example.com", prev, current);
    expect(findings.find((f) => f.title.includes("reachable again"))).toBeDefined();
  });

  test("new subdomains produce a medium-severity finding when enumerator is wired", () => {
    const prev = baseSnapshot({ subdomains: ["api.example.com"] });
    const current = baseSnapshot({ subdomains: ["api.example.com", "staging.example.com"] });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const finding = findings.find((f) => f.id.includes("new-subdomains"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
    expect(finding?.metadata?.subdomains).toEqual(["staging.example.com"]);
  });

  test("added hardening header (improvement) produces only an info finding", () => {
    const prev = baseSnapshot({ headers: {} });
    const current = baseSnapshot({ headers: { "x-frame-options": "DENY" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("info");
  });
});
