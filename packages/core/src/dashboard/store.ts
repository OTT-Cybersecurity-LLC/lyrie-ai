/**
 * dashboard/store.ts — in-memory (optionally file-backed) ring store for
 * anonymized agentic-attack-compression signals feeding the public radar
 * dashboard (Feature 3).
 *
 * Only ever holds `AnonymizedSignal`s (see aggregate.ts) — by construction
 * nothing host/operator-identifying is retained. Bounded ring buffer so a
 * long-running daemon can't grow this unbounded. Optional JSON file backing
 * lets the feed survive a restart without a database dependency.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import {
  aggregateFeed,
  type AnonymizedSignal,
  type FeedAggregate,
} from "./aggregate";

export interface CompressionStoreOptions {
  /** Maximum signals retained (ring buffer). Default 1000. */
  capacity?: number;
  /** Optional JSON file to persist to / load from. */
  filePath?: string;
  /** Retention window in ms; signals older than this are dropped on read. 0 = keep all in ring. Default 24h. */
  retentionMs?: number;
}

export interface FeedSnapshot {
  generatedAtMs: number;
  retentionMs: number;
  aggregate: FeedAggregate;
  /** Most-recent-first list of anonymized signals within the window. */
  signals: AnonymizedSignal[];
}

const DEFAULT_CAPACITY = 1000;
const DEFAULT_RETENTION_MS = 24 * 60 * 60 * 1000;

export class CompressionSignalStore {
  private ring: AnonymizedSignal[] = [];
  private readonly capacity: number;
  private readonly filePath?: string;
  private readonly retentionMs: number;

  constructor(opts: CompressionStoreOptions = {}) {
    this.capacity = opts.capacity ?? DEFAULT_CAPACITY;
    this.filePath = opts.filePath;
    this.retentionMs = opts.retentionMs ?? DEFAULT_RETENTION_MS;
    if (this.filePath && existsSync(this.filePath)) {
      this.loadFromFile();
    }
  }

  /** Append one anonymized signal, enforcing the ring capacity. */
  publish(signal: AnonymizedSignal): void {
    this.ring.push(signal);
    if (this.ring.length > this.capacity) {
      this.ring.splice(0, this.ring.length - this.capacity);
    }
    if (this.filePath) this.persist();
  }

  /** Number of signals currently retained (pre-retention-filter). */
  size(): number {
    return this.ring.length;
  }

  /** Clear the store (test hook / operator reset). */
  clear(): void {
    this.ring = [];
    if (this.filePath) this.persist();
  }

  /** Signals within the retention window, most-recent-first. */
  private windowed(nowMs: number): AnonymizedSignal[] {
    const cutoff = this.retentionMs > 0 ? nowMs - this.retentionMs : -Infinity;
    return this.ring
      .filter((s) => s.timeBucketMs >= cutoff)
      .sort((a, b) => b.timeBucketMs - a.timeBucketMs);
  }

  /** Build the JSON snapshot served by `/api/compression/feed`. */
  snapshot(nowMs: number = Date.now(), limit = 200): FeedSnapshot {
    const windowed = this.windowed(nowMs);
    const limited = windowed.slice(0, limit);
    return {
      generatedAtMs: nowMs,
      retentionMs: this.retentionMs,
      aggregate: aggregateFeed(windowed),
      signals: limited,
    };
  }

  // ─── File backing ─────────────────────────────────────────────────────────

  private persist(): void {
    if (!this.filePath) return;
    try {
      mkdirSync(dirname(this.filePath), { recursive: true });
      writeFileSync(this.filePath, JSON.stringify({ ring: this.ring }, null, 0), "utf8");
    } catch {
      /* best-effort persistence — never crash the daemon on a disk error */
    }
  }

  private loadFromFile(): void {
    try {
      const raw = readFileSync(this.filePath!, "utf8");
      const parsed = JSON.parse(raw) as { ring?: unknown };
      if (Array.isArray(parsed.ring)) {
        this.ring = (parsed.ring as AnonymizedSignal[]).slice(-this.capacity);
      }
    } catch {
      /* corrupt/absent file — start empty */
    }
  }
}
