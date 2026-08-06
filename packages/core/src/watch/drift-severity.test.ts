/**
 * drift-severity.test.ts — aggregate drift-severity classification tests
 * for watch/drift-severity.ts.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { classifyDriftSeverity } from "./drift-severity";
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

describe("classifyDriftSeverity", () => {
  test("no findings (idle tick) classifies as info with no reasons", () => {
    const result = classifyDriftSeverity([]);
    expect(result.severity).toBe("info");
    expect(result.reasons).toEqual([]);
  });

  test("TLS cert already expired classifies overall severity as critical", () => {
    const now = Date.now();
    const prev = baseSnapshot({ takenAt: now - 60_000, tls: { expiresAt: now + 30 * 24 * 60 * 60 * 1000 } });
    const current = baseSnapshot({ takenAt: now, tls: { expiresAt: now - 1000 } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("critical");
    expect(result.reasons.some((r) => r.includes("CRITICAL"))).toBe(true);
  });

  test("TLS cert expiring soon (within warning window) classifies overall severity as medium", () => {
    const now = Date.now();
    const prev = baseSnapshot({ takenAt: now - 60_000, tls: { expiresAt: now + 30 * 24 * 60 * 60 * 1000 } });
    const current = baseSnapshot({ takenAt: now, tls: { expiresAt: now + 5 * 24 * 60 * 60 * 1000 } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("medium");
  });

  test("newly-exposed path classifies overall severity as critical", () => {
    const prev = baseSnapshot();
    const current = baseSnapshot({
      exposedPaths: [
        { path: "/.env", exposed: true, status: 200 },
        { path: "/.git/config", exposed: false, status: 404 },
      ],
    });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("critical");
    expect(result.reasons.some((r) => r.includes("/.env"))).toBe(true);
  });

  test("removed hardening header classifies overall severity as high", () => {
    const prev = baseSnapshot();
    const current = baseSnapshot({ headers: { "strict-transport-security": "max-age=63072000" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("high");
    expect(result.reasons.some((r) => r.includes("removed"))).toBe(true);
  });

  test("benign disclosure-only header change (Server) classifies overall severity as low, not critical", () => {
    const prev = baseSnapshot({ headers: { server: "nginx/1.24" } });
    const current = baseSnapshot({ headers: { server: "nginx/1.25" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("low");
  });

  test("added hardening header (improvement) classifies overall severity as info", () => {
    const prev = baseSnapshot({ headers: {} });
    const current = baseSnapshot({ headers: { "x-frame-options": "DENY" } });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("info");
  });

  test("new subdomain discovered classifies overall severity as medium", () => {
    const prev = baseSnapshot({ subdomains: ["api.example.com"] });
    const current = baseSnapshot({ subdomains: ["api.example.com", "staging.example.com"] });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("medium");
  });

  test("mixed findings pick the worst severity present and order reasons worst-first", () => {
    const prev = baseSnapshot({ headers: { server: "nginx/1.24", "content-security-policy": "default-src 'self'" } });
    const current = baseSnapshot({
      headers: { server: "nginx/1.25" }, // CSP removed (high) + server changed (low)
      exposedPaths: [
        { path: "/.env", exposed: true, status: 200 }, // critical
        { path: "/.git/config", exposed: false, status: 404 },
      ],
    });
    const findings = diffPostureSnapshots("example.com", prev, current);
    const result = classifyDriftSeverity(findings);
    expect(result.severity).toBe("critical");
    expect(result.reasons[0]).toContain("CRITICAL");
  });
});
