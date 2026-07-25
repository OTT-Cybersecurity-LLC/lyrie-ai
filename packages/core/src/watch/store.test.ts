/**
 * store.test.ts — snapshot persistence, isolated to a tmp dir per test.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadLastSnapshot, saveSnapshot, snapshotPath } from "./store";
import type { PostureSnapshot } from "./types";

function withTmpDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "lyrie-watch-test-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const sampleSnapshot = (domain: string): PostureSnapshot => ({
  domain,
  takenAt: Date.now(),
  headers: { server: "nginx" },
  exposedPaths: [],
  subdomains: [],
});

describe("watch store", () => {
  test("loadLastSnapshot returns undefined when nothing stored yet", () => {
    withTmpDir((dir) => {
      expect(loadLastSnapshot("example.com", dir)).toBeUndefined();
    });
  });

  test("saveSnapshot then loadLastSnapshot round-trips", () => {
    withTmpDir((dir) => {
      const snap = sampleSnapshot("example.com");
      saveSnapshot(snap, dir);
      const loaded = loadLastSnapshot("example.com", dir);
      expect(loaded).toEqual(snap);
    });
  });

  test("sanitizes domain names for the filesystem path", () => {
    withTmpDir((dir) => {
      const path = snapshotPath("sub.example.com", dir);
      expect(path).toContain("sub.example.com.json");
    });
  });

  test("saving a newer snapshot for the same domain overwrites the old one", () => {
    withTmpDir((dir) => {
      saveSnapshot(sampleSnapshot("example.com"), dir);
      const second = { ...sampleSnapshot("example.com"), headers: { server: "apache" } };
      saveSnapshot(second, dir);
      const loaded = loadLastSnapshot("example.com", dir);
      expect(loaded?.headers.server).toBe("apache");
    });
  });

  test("different domains persist independently", () => {
    withTmpDir((dir) => {
      saveSnapshot(sampleSnapshot("a.example.com"), dir);
      saveSnapshot(sampleSnapshot("b.example.com"), dir);
      expect(loadLastSnapshot("a.example.com", dir)?.domain).toBe("a.example.com");
      expect(loadLastSnapshot("b.example.com", dir)?.domain).toBe("b.example.com");
    });
  });
});
