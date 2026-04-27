/**
 * FTS5 Cross-Session Search
 *
 * Adds full-text search across the conversations table using SQLite's FTS5
 * virtual table. Replaces LIKE-based search for ranked, fast cross-session
 * recall — inspired by Hermes's FTS5 + LLM summarization loop.
 *
 * Key design choices:
 *   - The FTS index is a SECONDARY virtual table — the canonical data still
 *     lives in `conversations`. If FTS is missing/corrupt we fall back to
 *     LIKE so memory recall keeps working.
 *   - Triggers keep the FTS index in sync on INSERT/UPDATE/DELETE.
 *   - All recalled snippets pass through `ShieldGuard.scanRecalled()` before
 *     being returned to the agent — no recalled prompt-injection payloads
 *     can hijack the model. (The Shield is Layer 1 in every Lyrie surface.)
 *
 * Migration is idempotent: calling `ensureFtsIndex()` on a database that
 * already has FTS5 set up is a no-op. Calling it on a fresh DB creates the
 * virtual table + triggers + backfills existing rows.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { Database } from "bun:sqlite";

import type { ConversationMessage } from "./memory-core";
import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";

// ─── Public types ────────────────────────────────────────────────────────────

export interface CrossSessionSearchOptions {
  /** Restrict to a single user_id */
  userId?: string;
  /** Restrict to a single channel */
  channel?: string;
  /** Restrict to a list of source identifiers (e.g. specific session keys) */
  sources?: string[];
  /** Max rows to return (default 50) */
  limit?: number;
  /** Skip Shield scanning (NEVER do this for agent recall — debug/admin only) */
  unsafeNoShield?: boolean;
  /** Optional Shield-equivalent (defaults to a built-in heuristic guard) */
  shield?: ShieldGuardLike;
}

export interface CrossSessionHit extends ConversationMessage {
  /** FTS bm25 rank (lower = better match). Null when LIKE fallback is used. */
  rank: number | null;
  /** Snippet with FTS highlight markers around matches when available. */
  snippet?: string;
  /** True if Shield gated/redacted the recalled content. */
  shielded?: boolean;
  /** Shield reason if redacted. */
  shieldReason?: string;
}

export interface SessionSummary {
  /** A short LLM-style summary (heuristic by default; pluggable summarizer). */
  summary: string;
  /** First and last message timestamps in the session. */
  startedAt: string;
  endedAt: string;
  /** Total messages summarized. */
  messageCount: number;
  /** Top entities/keywords mentioned. */
  topics: string[];
}

export type SessionSummarizer = (
  messages: ConversationMessage[],
) => Promise<SessionSummary> | SessionSummary;

// ─── FTS5 schema management ─────────────────────────────────────────────────

const FTS_TABLE = "conversations_fts";

const FTS_SCHEMA_SQL = `
  CREATE VIRTUAL TABLE IF NOT EXISTS ${FTS_TABLE} USING fts5(
    content,
    user_id UNINDEXED,
    channel UNINDEXED,
    role UNINDEXED,
    timestamp UNINDEXED,
    conv_id UNINDEXED,
    tokenize = 'porter unicode61'
  );

  CREATE TRIGGER IF NOT EXISTS conversations_ai AFTER INSERT ON conversations BEGIN
    INSERT INTO ${FTS_TABLE}(content, user_id, channel, role, timestamp, conv_id)
    VALUES (new.content, new.user_id, new.channel, new.role, new.timestamp, new.id);
  END;

  CREATE TRIGGER IF NOT EXISTS conversations_ad AFTER DELETE ON conversations BEGIN
    DELETE FROM ${FTS_TABLE} WHERE conv_id = old.id;
  END;

  CREATE TRIGGER IF NOT EXISTS conversations_au AFTER UPDATE ON conversations BEGIN
    DELETE FROM ${FTS_TABLE} WHERE conv_id = old.id;
    INSERT INTO ${FTS_TABLE}(content, user_id, channel, role, timestamp, conv_id)
    VALUES (new.content, new.user_id, new.channel, new.role, new.timestamp, new.id);
  END;
`;

/**
 * Idempotently create the FTS5 index, triggers, and backfill existing rows.
 * Returns the number of rows backfilled (0 if the index already existed).
 */
export function ensureFtsIndex(db: Database): { created: boolean; backfilled: number } {
  // Probe FTS5 availability — some Bun builds disable extensions
  try {
    db.query("SELECT fts5(?)").get("probe");
  } catch {
    // FTS5 not available; caller will silently fall back to LIKE.
    return { created: false, backfilled: 0 };
  }

  const existed =
    (db.query("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
      .get(FTS_TABLE) as { name?: string } | undefined)?.name === FTS_TABLE;

  db.exec(FTS_SCHEMA_SQL);

  if (existed) return { created: false, backfilled: 0 };

  // Backfill from canonical table
  const rowCount = (db.query("SELECT COUNT(*) AS c FROM conversations").get() as { c: number }).c;
  if (rowCount > 0) {
    db.exec(`
      INSERT INTO ${FTS_TABLE}(content, user_id, channel, role, timestamp, conv_id)
        SELECT content, user_id, channel, role, timestamp, id FROM conversations;
    `);
  }

  return { created: true, backfilled: rowCount };
}

// ─── Search ──────────────────────────────────────────────────────────────────

/**
 * Sanitize a user query into something safe for FTS5 MATCH. We strip any
 * characters that could change the FTS grammar (`- " * ( ) :`) and quote
 * each remaining token. Empty queries return null.
 */
function buildFtsQuery(raw: string): string | null {
  const cleaned = raw
    .replace(/[\u0000-\u001f]/g, " ")
    .replace(/["()]/g, " ")
    .replace(/[-*:]/g, " ")
    .trim();
  if (!cleaned) return null;
  const tokens = cleaned.split(/\s+/).filter((t) => t.length > 0);
  if (tokens.length === 0) return null;
  return tokens.map((t) => `"${t}"`).join(" ");
}

export function searchAcrossSessions(
  db: Database,
  query: string,
  options: CrossSessionSearchOptions = {},
): CrossSessionHit[] {
  const limit = options.limit ?? 50;
  const guard = options.shield ?? ShieldGuard.fallback();
  const ftsQuery = buildFtsQuery(query);
  if (!ftsQuery) return [];

  // Prefer FTS5 if the virtual table exists.
  const hasFts =
    !!(db.query("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
      .get(FTS_TABLE) as { name?: string } | undefined)?.name;

  let rows: any[];
  if (hasFts) {
    let sql = `
      SELECT c.id, c.user_id, c.role, c.content, c.channel, c.timestamp,
             snippet(${FTS_TABLE}, 0, '⟦', '⟧', '…', 16) AS snippet,
             bm25(${FTS_TABLE}) AS rank
      FROM ${FTS_TABLE}
      JOIN conversations c ON c.id = ${FTS_TABLE}.conv_id
      WHERE ${FTS_TABLE} MATCH ?
    `;
    const params: any[] = [ftsQuery];

    if (options.userId) {
      sql += ` AND ${FTS_TABLE}.user_id = ?`;
      params.push(options.userId);
    }
    if (options.channel) {
      sql += ` AND ${FTS_TABLE}.channel = ?`;
      params.push(options.channel);
    }
    if (options.sources && options.sources.length > 0) {
      sql += ` AND ${FTS_TABLE}.channel IN (${options.sources.map(() => "?").join(",")})`;
      params.push(...options.sources);
    }
    sql += " ORDER BY rank LIMIT ?";
    params.push(limit);

    rows = db.query(sql).all(...params) as any[];
  } else {
    // Fallback: LIKE-based scan. No ranking; chronological recency.
    let sql = "SELECT id, user_id, role, content, channel, timestamp, NULL AS snippet, NULL AS rank FROM conversations WHERE content LIKE ?";
    const params: any[] = [`%${query}%`];
    if (options.userId) {
      sql += " AND user_id = ?";
      params.push(options.userId);
    }
    if (options.channel) {
      sql += " AND channel = ?";
      params.push(options.channel);
    }
    sql += " ORDER BY timestamp DESC LIMIT ?";
    params.push(limit);
    rows = db.query(sql).all(...params) as any[];
  }

  if (options.unsafeNoShield) {
    return rows as CrossSessionHit[];
  }

  // Shield gate: scan every recalled snippet for prompt injection /
  // exfiltration / etc. Redact rather than discard so the agent still
  // sees the structural recall but can't be hijacked.
  return rows.map((row) => {
    const verdict = guard.scanRecalled(row.content ?? "");
    if (verdict.blocked) {
      return {
        ...row,
        content: `⟦SHIELDED⟧ ${verdict.reason ?? "blocked"}`,
        snippet: row.snippet ? `⟦SHIELDED⟧` : undefined,
        shielded: true,
        shieldReason: verdict.reason,
      } as CrossSessionHit;
    }
    return row as CrossSessionHit;
  });
}

// ─── Session summarization ──────────────────────────────────────────────────

/**
 * Default heuristic summarizer — pluggable. A Phase-2 LLM-backed summarizer
 * can be passed in via `summarize(db, ..., { summarizer })`.
 *
 * Heuristic logic:
 *   - Pulls the first user prompt + last assistant reply
 *   - Counts user/assistant turns
 *   - Surfaces top 5 keyword-ish tokens by frequency (after stopwords)
 */
export const heuristicSummarizer: SessionSummarizer = (messages) => {
  if (messages.length === 0) {
    return {
      summary: "(empty session)",
      startedAt: "",
      endedAt: "",
      messageCount: 0,
      topics: [],
    };
  }

  const first = messages[0];
  const last = messages[messages.length - 1];

  const firstUser = messages.find((m) => m.role === "user");
  const lastAssistant = [...messages].reverse().find((m) => m.role === "assistant");

  const stopwords = new Set([
    "the", "a", "an", "and", "or", "is", "are", "was", "were", "be", "been",
    "i", "you", "we", "they", "it", "to", "of", "for", "in", "on", "with",
    "this", "that", "have", "has", "but", "not", "do", "does", "did", "if",
    "as", "at", "by", "from", "so", "can", "would", "could", "should",
  ]);
  const counts = new Map<string, number>();
  for (const m of messages) {
    for (const tok of m.content.toLowerCase().split(/[^a-z0-9]+/)) {
      if (tok.length < 4 || stopwords.has(tok)) continue;
      counts.set(tok, (counts.get(tok) ?? 0) + 1);
    }
  }
  const topics = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tok]) => tok);

  const opener = firstUser?.content?.slice(0, 120) ?? "(no user prompt)";
  const closer = lastAssistant?.content?.slice(0, 160) ?? "(no assistant reply)";
  const summary = `Started with: "${opener}". Wrapped with: "${closer}". ${topics.length > 0 ? `Topics: ${topics.join(", ")}.` : ""}`.trim();

  return {
    summary,
    startedAt: first.timestamp,
    endedAt: last.timestamp,
    messageCount: messages.length,
    topics,
  };
};

export interface SummarizeSessionOptions {
  userId: string;
  channel?: string;
  /** Optional max-message cap (default 200) */
  limit?: number;
  /** Pluggable summarizer (defaults to heuristic) */
  summarizer?: SessionSummarizer;
}

export async function summarizeSession(
  db: Database,
  options: SummarizeSessionOptions,
): Promise<SessionSummary> {
  const limit = options.limit ?? 200;
  let sql = "SELECT id, user_id, role, content, channel, timestamp FROM conversations WHERE user_id = ?";
  const params: any[] = [options.userId];
  if (options.channel) {
    sql += " AND channel = ?";
    params.push(options.channel);
  }
  sql += " ORDER BY timestamp ASC LIMIT ?";
  params.push(limit);

  const messages = db.query(sql).all(...params) as ConversationMessage[];
  const summarizer = options.summarizer ?? heuristicSummarizer;
  return await summarizer(messages);
}
