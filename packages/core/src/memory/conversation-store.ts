/**
 * ConversationStore — Per-user, per-channel conversation history for Lyrie Agent.
 *
 * Features:
 * - Store messages per user per channel
 * - Retrieve last N messages for LLM context window
 * - Full-text search across all conversations
 * - Auto-summarize old conversations to save space
 * - Thread support for grouped interactions
 *
 * Backed by MemoryCore's SQLite database.
 *
 * © OTT Cybersecurity LLC — Production quality.
 */

import type { MemoryCore, ConversationMessage } from "./memory-core";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ConversationContext {
  userId: string;
  channel: string;
  messages: ConversationMessage[];
  summary?: string;
  totalMessages: number;
}

export interface ConversationSummary {
  userId: string;
  channel: string;
  period: string;
  summary: string;
  messageCount: number;
  created_at: string;
}

export interface ConversationSearchResult {
  message: ConversationMessage;
  relevance: number;
}

// ─── ConversationStore ───────────────────────────────────────────────────────

export class ConversationStore {
  private memory: MemoryCore;
  private contextWindowSize: number;
  private summarizeThreshold: number;

  constructor(memory: MemoryCore, options: { contextWindowSize?: number; summarizeThreshold?: number } = {}) {
    this.memory = memory;
    this.contextWindowSize = options.contextWindowSize || 50;
    this.summarizeThreshold = options.summarizeThreshold || 200;
  }

  async initialize(): Promise<void> {
    // Ensure summaries table exists
    const db = this.memory.getDb();
    db.exec(`
      CREATE TABLE IF NOT EXISTS conversation_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        channel TEXT NOT NULL DEFAULT 'default',
        period TEXT NOT NULL,
        summary TEXT NOT NULL,
        message_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_summaries_user ON conversation_summaries(user_id, channel);
    `);

    console.log(`   → ConversationStore initialized (window: ${this.contextWindowSize})`);
  }

  // ─── Store ───────────────────────────────────────────────────────────────

  /**
   * Add a message to the conversation history.
   * Auto-triggers summarization when threshold is exceeded.
   */
  async addMessage(
    userId: string,
    role: "user" | "assistant" | "system",
    content: string,
    channel: string = "default"
  ): Promise<number> {
    const id = await this.memory.storeMessage(userId, role, content, channel);

    // Check if we should summarize old messages
    const count = await this.getMessageCount(userId, channel);
    if (count > this.summarizeThreshold) {
      await this.summarizeOldMessages(userId, channel);
    }

    return id;
  }

  // ─── Retrieve ────────────────────────────────────────────────────────────

  /**
   * Get context for the LLM: recent messages + any relevant summary.
   * This is the primary method for building conversation context.
   */
  async getContext(userId: string, channel?: string): Promise<ConversationContext> {
    const messages = await this.memory.getConversationHistory(userId, {
      channel,
      limit: this.contextWindowSize,
    });

    const totalMessages = await this.getMessageCount(userId, channel);

    // Get latest summary if there is one
    let summary: string | undefined;
    if (totalMessages > this.contextWindowSize) {
      const summaries = await this.getSummaries(userId, channel);
      if (summaries.length > 0) {
        summary = summaries[summaries.length - 1].summary;
      }
    }

    return {
      userId,
      channel: channel || "default",
      messages,
      summary,
      totalMessages,
    };
  }

  /**
   * Get last N messages for a user on a channel.
   */
  async getRecentMessages(
    userId: string,
    limit: number = 20,
    channel?: string
  ): Promise<ConversationMessage[]> {
    return this.memory.getConversationHistory(userId, { channel, limit });
  }

  /**
   * Get all channels a user has talked on.
   */
  async getUserChannels(userId: string): Promise<string[]> {
    const db = this.memory.getDb();
    const rows = db.query(
      "SELECT DISTINCT channel FROM conversations WHERE user_id = ? ORDER BY channel"
    ).all(userId) as any[];
    return rows.map((r) => r.channel);
  }

  /**
   * Get all known user IDs.
   */
  async getAllUsers(): Promise<string[]> {
    const db = this.memory.getDb();
    const rows = db.query(
      "SELECT DISTINCT user_id FROM conversations ORDER BY user_id"
    ).all() as any[];
    return rows.map((r) => r.user_id);
  }

  // ─── Search ──────────────────────────────────────────────────────────────

  /**
   * Search across all conversations with relevance scoring.
   */
  async search(
    query: string,
    options: { userId?: string; channel?: string; limit?: number } = {}
  ): Promise<ConversationSearchResult[]> {
    const limit = options.limit || 20;
    const db = this.memory.getDb();

    let sql = "SELECT * FROM conversations WHERE content LIKE ?";
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

    const rows = db.query(sql).all(...params) as ConversationMessage[];

    // Score results by match quality
    const queryLower = query.toLowerCase();
    return rows.map((msg) => {
      let relevance = 1;
      const contentLower = msg.content.toLowerCase();
      // Exact match bonus
      if (contentLower.includes(queryLower)) relevance += 5;
      // Word count matches
      const words = queryLower.split(/\s+/);
      relevance += words.filter((w) => contentLower.includes(w)).length * 2;
      return { message: msg, relevance };
    }).sort((a, b) => b.relevance - a.relevance);
  }

  /**
   * Find conversations where user discussed a topic.
   */
  async findTopic(
    topic: string,
    userId?: string
  ): Promise<{ messages: ConversationMessage[]; channels: string[] }> {
    const results = await this.search(topic, { userId, limit: 50 });
    const messages = results.map((r) => r.message);
    const channels = [...new Set(messages.map((m) => m.channel))];
    return { messages, channels };
  }

  // ─── Summarization ───────────────────────────────────────────────────────

  /**
   * Summarize old messages to save space.
   * Keeps the most recent `contextWindowSize` messages intact and
   * creates a text summary of older messages.
   */
  async summarizeOldMessages(userId: string, channel: string = "default"): Promise<ConversationSummary | null> {
    const db = this.memory.getDb();

    // Get count
    const countRow = db.query(
      "SELECT COUNT(*) as c FROM conversations WHERE user_id = ? AND channel = ?"
    ).get(userId, channel) as any;

    const total = countRow?.c || 0;
    if (total <= this.contextWindowSize) return null;

    const toSummarize = total - this.contextWindowSize;

    // Get the oldest messages that will be summarized
    const oldMessages = db.query(
      `SELECT * FROM conversations WHERE user_id = ? AND channel = ?
       ORDER BY timestamp ASC LIMIT ?`
    ).all(userId, channel, toSummarize) as ConversationMessage[];

    if (oldMessages.length === 0) return null;

    // Build a compact summary (extractive — take key user messages)
    const userMsgs = oldMessages.filter((m) => m.role === "user");
    const topics = extractTopics(userMsgs.map((m) => m.content));
    const firstTs = oldMessages[0].timestamp;
    const lastTs = oldMessages[oldMessages.length - 1].timestamp;

    const summaryText = [
      `Conversation summary for ${userId} on ${channel}:`,
      `Period: ${firstTs.slice(0, 10)} to ${lastTs.slice(0, 10)}`,
      `Messages: ${oldMessages.length} (${userMsgs.length} from user)`,
      `Topics discussed: ${topics.join(", ") || "general conversation"}`,
      `Key messages:`,
      ...userMsgs.slice(-5).map((m) => `  - "${m.content.slice(0, 120)}${m.content.length > 120 ? "..." : ""}"`),
    ].join("\n");

    const period = `${firstTs.slice(0, 10)}_${lastTs.slice(0, 10)}`;

    // Store summary
    db.prepare(
      `INSERT INTO conversation_summaries (user_id, channel, period, summary, message_count, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(userId, channel, period, summaryText, oldMessages.length, new Date().toISOString());

    // Delete the old messages
    const cutoffId = oldMessages[oldMessages.length - 1].id;
    db.prepare(
      "DELETE FROM conversations WHERE user_id = ? AND channel = ? AND id <= ?"
    ).run(userId, channel, cutoffId);

    const summary: ConversationSummary = {
      userId,
      channel,
      period,
      summary: summaryText,
      messageCount: oldMessages.length,
      created_at: new Date().toISOString(),
    };

    console.log(`📝 Summarized ${oldMessages.length} old messages for ${userId}@${channel}`);
    return summary;
  }

  async getSummaries(userId: string, channel?: string): Promise<ConversationSummary[]> {
    const db = this.memory.getDb();
    let sql = "SELECT * FROM conversation_summaries WHERE user_id = ?";
    const params: any[] = [userId];
    if (channel) {
      sql += " AND channel = ?";
      params.push(channel);
    }
    sql += " ORDER BY created_at";
    return db.query(sql).all(...params) as ConversationSummary[];
  }

  // ─── Maintenance ─────────────────────────────────────────────────────────

  async getMessageCount(userId: string, channel?: string): Promise<number> {
    const db = this.memory.getDb();
    let sql = "SELECT COUNT(*) as c FROM conversations WHERE user_id = ?";
    const params: any[] = [userId];
    if (channel) {
      sql += " AND channel = ?";
      params.push(channel);
    }
    const row = db.query(sql).get(...params) as any;
    return row?.c || 0;
  }

  /**
   * Get stats about conversation storage.
   */
  async stats(): Promise<{
    totalMessages: number;
    totalUsers: number;
    totalSummaries: number;
    channels: string[];
  }> {
    const db = this.memory.getDb();
    const msgs = (db.query("SELECT COUNT(*) as c FROM conversations").get() as any)?.c || 0;
    const users = (db.query("SELECT COUNT(DISTINCT user_id) as c FROM conversations").get() as any)?.c || 0;
    const sums = (db.query("SELECT COUNT(*) as c FROM conversation_summaries").get() as any)?.c || 0;
    const channels = (db.query("SELECT DISTINCT channel FROM conversations ORDER BY channel").all() as any[]).map(
      (r) => r.channel
    );

    return { totalMessages: msgs, totalUsers: users, totalSummaries: sums, channels };
  }

  /**
   * Nuke all conversations for a user (GDPR compliance).
   */
  async deleteUserData(userId: string): Promise<{ messagesDeleted: number; summariesDeleted: number }> {
    const db = this.memory.getDb();
    const msgs = db.prepare("DELETE FROM conversations WHERE user_id = ?").run(userId);
    const sums = db.prepare("DELETE FROM conversation_summaries WHERE user_id = ?").run(userId);
    return { messagesDeleted: msgs.changes, summariesDeleted: sums.changes };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Extract key topics from a list of messages (simple keyword extraction).
 * This is a lightweight extractive approach — no LLM needed.
 */
function extractTopics(messages: string[]): string[] {
  const stopWords = new Set([
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "must", "can", "could", "i", "you", "he",
    "she", "it", "we", "they", "me", "him", "her", "us", "them", "my",
    "your", "his", "its", "our", "their", "this", "that", "these", "those",
    "what", "which", "who", "whom", "when", "where", "why", "how", "not",
    "no", "but", "and", "or", "if", "then", "than", "too", "very", "just",
    "about", "up", "out", "in", "on", "at", "to", "for", "of", "with",
    "from", "by", "as", "into", "through", "get", "got", "need", "want",
    "like", "know", "think", "make", "take", "see", "come", "go", "say",
    "tell", "give", "use", "find", "here", "there", "all", "some", "any",
    "each", "every", "both", "few", "more", "most", "other", "so", "also",
  ]);

  const wordFreq: Record<string, number> = {};

  for (const msg of messages) {
    const words = msg.toLowerCase().replace(/[^\w\s-]/g, "").split(/\s+/);
    for (const word of words) {
      if (word.length > 3 && !stopWords.has(word)) {
        wordFreq[word] = (wordFreq[word] || 0) + 1;
      }
    }
  }

  return Object.entries(wordFreq)
    .filter(([_, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([word]) => word);
}
