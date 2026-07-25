/**
 * probe.test.ts — pure-function tests for watch/probe.ts, no real network.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { probeDomain } from "./probe";

function fakeFetch(handlers: Record<string, { status: number; headers?: Record<string, string> }>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input.toString();
    const path = new URL(url).pathname;
    const handler = handlers[path] ?? handlers["*"];
    if (!handler) throw new Error(`no fake handler for ${path}`);
    return new Response(null, { status: handler.status, headers: handler.headers });
  }) as typeof fetch;
}

describe("probeDomain", () => {
  test("captures watched headers from the root request", async () => {
    const fetchFn = fakeFetch({
      "/": {
        status: 200,
        headers: {
          "content-security-policy": "default-src 'self'",
          "strict-transport-security": "max-age=63072000",
          server: "nginx/1.25",
        },
      },
      "*": { status: 404 },
    });

    const snap = await probeDomain("example.com", {
      fetchFn,
      tlsInspector: async () => undefined,
    });

    expect(snap.domain).toBe("example.com");
    expect(snap.unreachable).toBeUndefined();
    expect(snap.headers["content-security-policy"]).toBe("default-src 'self'");
    expect(snap.headers["strict-transport-security"]).toBe("max-age=63072000");
    expect(snap.headers.server).toBe("nginx/1.25");
    expect(snap.headers["x-frame-options"]).toBeUndefined();
  });

  test("marks snapshot unreachable when root fetch throws", async () => {
    const fetchFn = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;

    const snap = await probeDomain("down.example.com", { fetchFn, tlsInspector: async () => undefined });
    expect(snap.unreachable).toBe(true);
    expect(snap.error).toBeTruthy();
  });

  test("detects an exposed common path (2xx status)", async () => {
    const fetchFn = fakeFetch({
      "/": { status: 200 },
      "/.env": { status: 200 },
      "*": { status: 404 },
    });

    const snap = await probeDomain("example.com", { fetchFn, tlsInspector: async () => undefined });
    const envResult = snap.exposedPaths.find((p) => p.path === "/.env");
    expect(envResult?.exposed).toBe(true);
    expect(envResult?.status).toBe(200);

    const gitResult = snap.exposedPaths.find((p) => p.path === "/.git/config");
    expect(gitResult?.exposed).toBe(false);
  });

  test("uses injected tlsInspector result verbatim", async () => {
    const fetchFn = fakeFetch({ "/": { status: 200 }, "*": { status: 404 } });
    const expiresAt = Date.now() + 1000;

    const snap = await probeDomain("example.com", {
      fetchFn,
      tlsInspector: async () => ({ expiresAt, fingerprintSha256: "deadbeef" }),
    });

    expect(snap.tls?.expiresAt).toBe(expiresAt);
    expect(snap.tls?.fingerprintSha256).toBe("deadbeef");
  });

  test("subdomains default to empty when no enumerator injected", async () => {
    const fetchFn = fakeFetch({ "/": { status: 200 }, "*": { status: 404 } });
    const snap = await probeDomain("example.com", { fetchFn, tlsInspector: async () => undefined });
    expect(snap.subdomains).toEqual([]);
  });

  test("uses injected subdomainEnum when provided", async () => {
    const fetchFn = fakeFetch({ "/": { status: 200 }, "*": { status: 404 } });
    const snap = await probeDomain("example.com", {
      fetchFn,
      tlsInspector: async () => undefined,
      subdomainEnum: async () => ["api.example.com", "mail.example.com"],
    });
    expect(snap.subdomains).toEqual(["api.example.com", "mail.example.com"]);
  });
});
