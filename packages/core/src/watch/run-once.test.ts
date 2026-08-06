/**
 * run-once.test.ts — single-tick cron entry point tests for watch/run-once.ts.
 * No real network — fetch/tls are injected exactly as in probe.test.ts /
 * engine.test.ts.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runWatchTick } from "./run-once";
import { loadLastSnapshot } from "./store";
import type { ProbeOptions } from "./types";

function withTmpDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "lyrie-watch-run-once-test-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function fakeFetch(status = 200, headers: Record<string, string> = {}): typeof fetch {
  return (async () => new Response(null, { status, headers })) as unknown as typeof fetch;
}

describe("runWatchTick", () => {
  test("first run (no prior snapshot) probes, persists, and returns no diff/driftSeverity", async () => {
    await withTmpDir(async (dir) => {
      const probeOptions: ProbeOptions = { fetchFn: fakeFetch(200), tlsInspector: async () => undefined };

      const result = await runWatchTick("example.com", { storeDir: dir, probeOptions });

      expect(result.snapshot.domain).toBe("example.com");
      expect(result.diff).toBeUndefined();
      expect(result.driftSeverity).toBeUndefined();

      // Persisted as the new baseline for the next tick.
      const stored = loadLastSnapshot("example.com", dir);
      expect(stored).toBeDefined();
      expect(stored?.domain).toBe("example.com");
    });
  });

  test("second run with a prior snapshot and no changes produces an idle diff (info, empty reasons)", async () => {
    await withTmpDir(async (dir) => {
      const probeOptions: ProbeOptions = {
        fetchFn: fakeFetch(200, { server: "nginx/1.25" }),
        tlsInspector: async () => undefined,
      };

      await runWatchTick("example.com", { storeDir: dir, probeOptions });
      const result = await runWatchTick("example.com", { storeDir: dir, probeOptions });

      expect(result.diff).toEqual([]);
      expect(result.driftSeverity).toEqual({ severity: "info", reasons: [] });
    });
  });

  test("second run with a removed hardening header produces a diff and high driftSeverity", async () => {
    await withTmpDir(async (dir) => {
      await runWatchTick("example.com", {
        storeDir: dir,
        probeOptions: {
          fetchFn: fakeFetch(200, { "content-security-policy": "default-src 'self'" }),
          tlsInspector: async () => undefined,
        },
      });

      const result = await runWatchTick("example.com", {
        storeDir: dir,
        probeOptions: {
          fetchFn: fakeFetch(200, {}), // CSP now absent — regression
          tlsInspector: async () => undefined,
        },
      });

      expect(result.diff?.some((f) => f.title.includes("content-security-policy"))).toBe(true);
      expect(result.driftSeverity?.severity).toBe("high");
      expect(result.driftSeverity?.reasons.length).toBeGreaterThan(0);
    });
  });

  test("second run with a newly-exposed path produces critical driftSeverity", async () => {
    await withTmpDir(async (dir) => {
      const fetchFnClean = (async (input: string | URL | Request) => {
        const url = typeof input === "string" ? input : input.toString();
        const path = new URL(url).pathname;
        return new Response(null, { status: path === "/" ? 200 : 404 });
      }) as unknown as typeof fetch;

      const fetchFnExposed = (async (input: string | URL | Request) => {
        const url = typeof input === "string" ? input : input.toString();
        const path = new URL(url).pathname;
        return new Response(null, { status: path === "/.env" || path === "/" ? 200 : 404 });
      }) as unknown as typeof fetch;

      await runWatchTick("example.com", {
        storeDir: dir,
        probeOptions: { fetchFn: fetchFnClean, tlsInspector: async () => undefined },
      });

      const result = await runWatchTick("example.com", {
        storeDir: dir,
        probeOptions: { fetchFn: fetchFnExposed, tlsInspector: async () => undefined },
      });

      expect(result.driftSeverity?.severity).toBe("critical");
      expect(result.driftSeverity?.reasons.some((r) => r.includes("/.env"))).toBe(true);
    });
  });

  test("persist: false does not write a snapshot to disk", async () => {
    await withTmpDir(async (dir) => {
      const probeOptions: ProbeOptions = { fetchFn: fakeFetch(200), tlsInspector: async () => undefined };

      await runWatchTick("example.com", { storeDir: dir, probeOptions, persist: false });

      expect(loadLastSnapshot("example.com", dir)).toBeUndefined();
    });
  });
});
