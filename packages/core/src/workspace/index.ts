/**
 * Lyrie Agent — WorkspaceContext
 *
 * Provides OpenClaw-parity workspace file injection:
 *   SOUL.md     — persona / tone
 *   AGENTS.md   — system rules
 *   MEMORY.md   — quick-access facts
 *   USER.md     — about the operator
 *   TOOLS.md    — credential reference
 *   HEARTBEAT.md — proactive intelligence
 *
 * Usage:
 *   const ctx = new WorkspaceContext();
 *   const files = await ctx.load("~/.lyrie/workspace");
 *   const systemPrompt = ctx.buildSystemContext(files);
 *   ctx.watch("~/.lyrie/workspace", () => console.log("workspace changed"));
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readFileSync, watchFile, unwatchFile } from "fs";
import { join, resolve } from "path";
import { homedir } from "os";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface WorkspaceFiles {
  /** SOUL.md — persona/tone */
  soul?: string;
  /** AGENTS.md — system rules */
  agents?: string;
  /** MEMORY.md — quick-access facts */
  memory?: string;
  /** USER.md — about the operator */
  user?: string;
  /** TOOLS.md — credential reference */
  tools?: string;
  /** HEARTBEAT.md — proactive intelligence */
  heartbeat?: string;
  /** Any extra files loaded on-demand */
  [key: string]: string | undefined;
}

export interface WorkspaceLoadResult {
  files: WorkspaceFiles;
  loadedPaths: string[];
  missingPaths: string[];
}

// File names to WorkspaceFiles key mapping
const FILE_MAP: Array<{ file: string; key: keyof WorkspaceFiles }> = [
  { file: "SOUL.md", key: "soul" },
  { file: "AGENTS.md", key: "agents" },
  { file: "MEMORY.md", key: "memory" },
  { file: "USER.md", key: "user" },
  { file: "TOOLS.md", key: "tools" },
  { file: "HEARTBEAT.md", key: "heartbeat" },
];

// ─── WorkspaceContext ────────────────────────────────────────────────────────

export class WorkspaceContext {
  private cachedFiles: WorkspaceFiles = {};
  private watchedDir: string | null = null;
  private watchedPaths: string[] = [];

  /**
   * Load workspace files from a directory.
   * Expands ~ to the home directory.
   */
  async load(workspaceDir: string): Promise<WorkspaceFiles> {
    const dir = resolveDir(workspaceDir);
    const files: WorkspaceFiles = {};
    const loadedPaths: string[] = [];
    const missingPaths: string[] = [];

    for (const { file, key } of FILE_MAP) {
      const filePath = join(dir, file);
      if (existsSync(filePath)) {
        try {
          files[key] = readFileSync(filePath, "utf8");
          loadedPaths.push(filePath);
        } catch {
          missingPaths.push(filePath);
        }
      } else {
        missingPaths.push(filePath);
      }
    }

    this.cachedFiles = files;
    return files;
  }

  /**
   * Build a system prompt string from workspace files.
   * Matches OpenClaw's injection format so prompts are compatible.
   */
  buildSystemContext(files: WorkspaceFiles): string {
    const sections: string[] = [];

    if (files.soul) {
      sections.push(wrapSection("SOUL (Persona & Tone)", files.soul));
    }

    if (files.agents) {
      sections.push(wrapSection("AGENTS (System Rules)", files.agents));
    }

    if (files.memory) {
      sections.push(wrapSection("MEMORY (Quick-Access Facts)", files.memory));
    }

    if (files.user) {
      sections.push(wrapSection("USER (About the Operator)", files.user));
    }

    if (files.tools) {
      sections.push(wrapSection("TOOLS (Credential Reference)", files.tools));
    }

    if (files.heartbeat) {
      sections.push(wrapSection("HEARTBEAT (Proactive Intelligence)", files.heartbeat));
    }

    // Any extra keys
    for (const [key, value] of Object.entries(files)) {
      if (!["soul", "agents", "memory", "user", "tools", "heartbeat"].includes(key) && value) {
        sections.push(wrapSection(key.toUpperCase(), value));
      }
    }

    if (sections.length === 0) {
      return "";
    }

    return [
      "# Workspace Context",
      "The following workspace files have been loaded:",
      "",
      ...sections,
    ].join("\n");
  }

  /**
   * Watch the workspace directory for changes and call onChange when any
   * workspace file is modified.
   */
  watch(workspaceDir: string, onChange: (changedFile: string) => void): void {
    const dir = resolveDir(workspaceDir);

    // Stop existing watchers
    this.unwatch();

    this.watchedDir = dir;
    this.watchedPaths = [];

    for (const { file } of FILE_MAP) {
      const filePath = join(dir, file);
      if (existsSync(filePath)) {
        watchFile(filePath, { interval: 1000 }, (curr, prev) => {
          if (curr.mtime !== prev.mtime) {
            // Reload the changed file
            try {
              const key = FILE_MAP.find((m) => m.file === file)?.key;
              if (key) {
                this.cachedFiles[key] = readFileSync(filePath, "utf8");
              }
            } catch {
              // Ignore read errors during watch
            }
            onChange(file);
          }
        });
        this.watchedPaths.push(filePath);
      }
    }
  }

  /**
   * Stop all active file watchers.
   */
  unwatch(): void {
    for (const filePath of this.watchedPaths) {
      try {
        unwatchFile(filePath);
      } catch {
        // Ignore
      }
    }
    this.watchedPaths = [];
    this.watchedDir = null;
  }

  /**
   * Return the currently cached workspace files.
   */
  getCached(): WorkspaceFiles {
    return { ...this.cachedFiles };
  }

  /**
   * Load a specific extra file by name and merge into cache.
   */
  async loadExtra(workspaceDir: string, filename: string): Promise<string | undefined> {
    const dir = resolveDir(workspaceDir);
    const filePath = join(dir, filename);
    if (!existsSync(filePath)) return undefined;
    try {
      const content = readFileSync(filePath, "utf8");
      const key = filename.toLowerCase().replace(/\.md$/, "");
      this.cachedFiles[key] = content;
      return content;
    } catch {
      return undefined;
    }
  }
}

// ─── Factory / default instance ──────────────────────────────────────────────

let _defaultContext: WorkspaceContext | null = null;

/** Get or create the default singleton WorkspaceContext */
export function getWorkspaceContext(): WorkspaceContext {
  if (!_defaultContext) {
    _defaultContext = new WorkspaceContext();
  }
  return _defaultContext;
}

/**
 * Convenience: load workspace from default Lyrie workspace dir
 * (~/.lyrie/workspace or ./workspace).
 */
export async function loadDefaultWorkspace(
  override?: string
): Promise<WorkspaceFiles> {
  const dir =
    override ??
    (existsSync(join(homedir(), ".lyrie", "workspace"))
      ? join(homedir(), ".lyrie", "workspace")
      : process.cwd());
  return getWorkspaceContext().load(dir);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function resolveDir(dir: string): string {
  if (dir.startsWith("~")) {
    return resolve(join(homedir(), dir.slice(1)));
  }
  return resolve(dir);
}

function wrapSection(title: string, content: string): string {
  return `## ${title}\n\n${content.trim()}\n`;
}

// ─── Re-exports ────────────────────────────────────────────────────────────────

export type { WorkspaceFiles as IWorkspaceFiles };
