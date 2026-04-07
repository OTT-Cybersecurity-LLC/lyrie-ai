/**
 * Lyrie Agent — Migration Utilities
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "fs";
import { join, basename, extname } from "path";
import type { MigrationContext } from "./types";

// ─── File I/O helpers ─────────────────────────────────────────────────────────

export function safeReadJson<T = unknown>(filePath: string): T | null {
  try {
    if (!existsSync(filePath)) return null;
    const raw = readFileSync(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function safeReadText(filePath: string): string | null {
  try {
    if (!existsSync(filePath)) return null;
    return readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

export function safeReadYaml(filePath: string): Record<string, unknown> | null {
  try {
    if (!existsSync(filePath)) return null;
    const raw = readFileSync(filePath, "utf8");
    // Minimal YAML parser for simple key: value files
    // For production, swap with a real yaml lib if available
    return parseSimpleYaml(raw);
  } catch {
    return null;
  }
}

/** Write JSON to a file, creating parent dirs as needed */
export function writeJson(filePath: string, data: unknown, dryRun: boolean): boolean {
  if (dryRun) return true;
  try {
    mkdirSync(join(filePath, ".."), { recursive: true });
    writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
    return true;
  } catch {
    return false;
  }
}

/** Write text to a file */
export function writeText(filePath: string, content: string, dryRun: boolean): boolean {
  if (dryRun) return true;
  try {
    mkdirSync(join(filePath, ".."), { recursive: true });
    writeFileSync(filePath, content);
    return true;
  } catch {
    return false;
  }
}

/** List all files under a directory (recursive) */
export function listFiles(dir: string, ext?: string): string[] {
  const results: string[] = [];

  function walk(current: string) {
    if (!existsSync(current)) return;
    const entries = readdirSync(current);
    for (const entry of entries) {
      const fullPath = join(current, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (!ext || extname(entry) === ext) {
          results.push(fullPath);
        }
      } catch {
        // Skip unreadable entries
      }
    }
  }

  walk(dir);
  return results;
}

/** List immediate subdirectories */
export function listDirs(dir: string): string[] {
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir).filter((entry) => {
      try {
        return statSync(join(dir, entry)).isDirectory();
      } catch {
        return false;
      }
    });
  } catch {
    return [];
  }
}

// ─── Progress logging ─────────────────────────────────────────────────────────

export class MigrationLogger {
  private items: number = 0;
  private errors: string[] = [];
  private warnings: string[] = [];

  constructor(
    private platform: string,
    private verbose: boolean
  ) {}

  step(msg: string): void {
    console.log(`  ⟶  ${msg}`);
  }

  ok(msg: string): void {
    this.items++;
    if (this.verbose) console.log(`  ✓  ${msg}`);
  }

  warn(msg: string): void {
    this.warnings.push(msg);
    console.log(`  ⚠  ${msg}`);
  }

  error(msg: string): void {
    this.errors.push(msg);
    console.log(`  ✗  ${msg}`);
  }

  skip(msg: string): void {
    if (this.verbose) console.log(`  -  ${msg}`);
  }

  getErrors(): string[] {
    return this.errors;
  }

  getWarnings(): string[] {
    return this.warnings;
  }

  getCount(): number {
    return this.items;
  }
}

// ─── Simple YAML parser (no dependency) ──────────────────────────────────────

function parseSimpleYaml(raw: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = raw.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const colonIdx = trimmed.indexOf(":");
    if (colonIdx === -1) continue;

    const key = trimmed.slice(0, colonIdx).trim();
    const value = trimmed.slice(colonIdx + 1).trim();

    if (!key) continue;

    // Parse value
    if (value === "" || value === "null") {
      result[key] = null;
    } else if (value === "true") {
      result[key] = true;
    } else if (value === "false") {
      result[key] = false;
    } else if (!isNaN(Number(value))) {
      result[key] = Number(value);
    } else {
      // Strip surrounding quotes
      result[key] = value.replace(/^["']|["']$/g, "");
    }
  }

  return result;
}

// ─── Normalization helpers ────────────────────────────────────────────────────

/** Generate a UUID v4 (no dependency) */
export function uuidv4(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/** Normalize a string to a safe identifier */
export function slugify(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/** Truncate a string for display */
export function truncate(str: string, max = 60): string {
  return str.length > max ? str.slice(0, max - 3) + "..." : str;
}
