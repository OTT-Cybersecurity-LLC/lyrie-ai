/**
 * Lyrie Agent — Migration Type Definitions
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

export type MigratorPlatform =
  | "openclaw"
  | "hermes"
  | "autogpt"
  | "nanoclaw"
  | "zeroclaw"
  | "dify"
  | "superagi"
  | "nanobot"
  | "grip-ai"
  | "claude-code"
  | "cursor";

export interface MigrationResult {
  platform: MigratorPlatform;
  success: boolean;
  itemsMigrated: number;
  errors: string[];
  warnings: string[];
  /** Structured summary of what was imported */
  manifest: MigrationManifest;
  /** Duration in ms */
  duration: number;
}

export interface MigrationManifest {
  memory?: number;
  skills?: number;
  config?: boolean;
  channels?: string[];
  cronJobs?: number;
  agents?: number;
  tools?: number;
  workflows?: number;
  datasets?: number;
  conversations?: number;
  [key: string]: unknown;
}

export type MigrationOnly = "memory" | "skills" | "crons" | "channels";

export interface MigrationContext {
  lyrieDir: string;
  dryRun: boolean;
  verbose: boolean;
  /** Restrict migration to a single section */
  only?: MigrationOnly;
}

// ─── Lyrie native config format ───────────────────────────────────────────────

export interface LyrieConfig {
  version: string;
  agent: {
    name: string;
    persona?: string;
    defaultModel?: string;
  };
  channels?: LyrieChannel[];
  shield?: {
    enabled: boolean;
    level: "passive" | "active" | "aggressive";
  };
  migrated?: {
    from: MigratorPlatform;
    at: string;
    version?: string;
  };
}

export interface LyrieChannel {
  type: string;
  token?: string;
  chatId?: string;
  [key: string]: unknown;
}

export interface LyrieMemoryEntry {
  id: string;
  category: "preference" | "fact" | "decision" | "entity" | "other";
  text: string;
  importance: number;
  source: string;
  createdAt: string;
  tags?: string[];
}

export interface LyrieSkill {
  name: string;
  description: string;
  source: string;
  path?: string;
  enabled: boolean;
  config?: Record<string, unknown>;
}

export interface LyrieCronJob {
  name: string;
  schedule: string;
  task: string;
  model?: string;
  enabled: boolean;
}
