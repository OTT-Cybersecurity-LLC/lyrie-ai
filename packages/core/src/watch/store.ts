/**
 * watch/store.ts — Persist PostureSnapshots between `lyrie watch` ticks.
 *
 * Follows the same `~/.lyrie/<feature>/<file>` convention as
 * `packages/core/src/evolve/dream-cycle.ts` (outcomes.jsonl under
 * `~/.lyrie/evolve/`) and the top-level `~/.lyrie/config.json` documented
 * in the README, rather than inventing a new storage location.
 *
 * One JSON file per domain: `~/.lyrie/watch/<domain>.json`. Domain names are
 * filesystem-safe (DNS names don't contain path separators) but we still
 * sanitise defensively.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import type { PostureSnapshot } from "./types";

export function watchDir(): string {
  return join(homedir(), ".lyrie", "watch");
}

function sanitizeDomain(domain: string): string {
  return domain.replace(/[^a-zA-Z0-9.-]/g, "_");
}

export function snapshotPath(domain: string, dir: string = watchDir()): string {
  return join(dir, `${sanitizeDomain(domain)}.json`);
}

/** Load the most recent stored snapshot for `domain`, or `undefined` on first run. */
export function loadLastSnapshot(domain: string, dir: string = watchDir()): PostureSnapshot | undefined {
  const path = snapshotPath(domain, dir);
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as PostureSnapshot;
  } catch (err) {
    console.warn(`[watch] failed to parse stored snapshot at ${path}:`, err);
    return undefined;
  }
}

/** Persist `snapshot` as the new "last known" state for its domain. */
export function saveSnapshot(snapshot: PostureSnapshot, dir: string = watchDir()): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(snapshotPath(snapshot.domain, dir), JSON.stringify(snapshot, null, 2), "utf8");
}
