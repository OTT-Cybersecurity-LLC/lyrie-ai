/**
 * Multi-Group Chat — Config types, FIFO queue, and routing helpers.
 *
 * Supports Telegram, Discord, and Slack group chats with:
 * - Configurable activation modes (all messages vs. mention-only)
 * - Mention gating (bot must be @mentioned to respond)
 * - Per-thread session management (inherits parent model override only)
 * - FIFO message queue with 500 ms debounce to coalesce burst messages
 * - `user:<id>` and `channel:<id>` target syntax for outbound routing
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export type GroupActivationMode =
  | "all"         // respond to every message in the group
  | "mention"     // only respond when @mentioned
  | "command";    // only respond to /command messages

export interface GroupChatConfig {
  /** How the bot activates in group chats. Default: "mention" */
  activationMode: GroupActivationMode;
  /** Whether to require a @mention before responding. Default: true */
  mentionGating: boolean;
  /** Whether to track per-user conversation history in group chats. Default: false */
  historyTracking: boolean;
  /** Use a FIFO queue with debounce. Default: true */
  fifoQueue: boolean;
  /** Debounce window in ms. Default: 500 */
  debounceMs: number;
  /** Maximum queue size before oldest messages are dropped. Default: 100 */
  maxQueueSize: number;
  /** Only respond to messages from these user IDs (empty = all). */
  allowedUsers?: string[];
  /** Only track history for these channels (empty = all). */
  trackedChannels?: string[];
}

export const DEFAULT_GROUP_CHAT_CONFIG: GroupChatConfig = {
  activationMode: "mention",
  mentionGating: true,
  historyTracking: false,
  fifoQueue: true,
  debounceMs: 500,
  maxQueueSize: 100,
};

// ─── Queued Message ───────────────────────────────────────────────────────────

export interface QueuedGroupMessage {
  id: string;
  chatId: string;
  userId: string;
  text: string;
  channel: string;
  timestamp: number;
  /** Thread/reply context if available */
  threadId?: string;
  /** Raw platform payload */
  raw?: unknown;
}

// ─── FIFO Queue ───────────────────────────────────────────────────────────────

type FlushCallback = (messages: QueuedGroupMessage[]) => Promise<void>;

/**
 * FIFO message queue with configurable debounce.
 *
 * Messages arriving within `debounceMs` of each other are batched and
 * delivered together to the flush callback. This prevents the bot from
 * responding to every message in a rapid burst separately.
 */
export class FifoGroupQueue {
  private readonly queue: QueuedGroupMessage[] = [];
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly config: GroupChatConfig;
  private readonly onFlush: FlushCallback;

  constructor(config: GroupChatConfig, onFlush: FlushCallback) {
    this.config = config;
    this.onFlush = onFlush;
  }

  enqueue(msg: QueuedGroupMessage): void {
    // Drop oldest if at capacity
    if (this.queue.length >= this.config.maxQueueSize) {
      this.queue.shift();
    }

    this.queue.push(msg);
    this._scheduleFlush();
  }

  private _scheduleFlush(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => {
      this._flush();
    }, this.config.debounceMs);
  }

  private _flush(): void {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    this.debounceTimer = null;
    this.onFlush(batch).catch((err) => {
      console.error("[group-chat] flush error:", err instanceof Error ? err.message : err);
    });
  }

  /** Force an immediate flush (useful for testing). */
  flushNow(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    this._flush();
  }

  get size(): number {
    return this.queue.length;
  }
}

// ─── Thread Session ───────────────────────────────────────────────────────────

export interface ThreadSession {
  threadId: string;
  parentChatId: string;
  channel: string;
  /**
   * Model override inherited from the parent session (if set).
   * No transcript carryover — each thread starts fresh.
   */
  modelOverride?: string;
  createdAt: number;
  lastActivityAt: number;
}

/**
 * Manage thread sessions for group chats.
 * Thread sessions inherit the parent model override only — no transcript.
 */
export class ThreadSessionManager {
  private readonly sessions = new Map<string, ThreadSession>();

  getOrCreate(
    threadId: string,
    parentChatId: string,
    channel: string,
    parentModelOverride?: string
  ): ThreadSession {
    const key = `${channel}:${threadId}`;
    const existing = this.sessions.get(key);

    if (existing) {
      existing.lastActivityAt = Date.now();
      return existing;
    }

    const session: ThreadSession = {
      threadId,
      parentChatId,
      channel,
      modelOverride: parentModelOverride, // inherit only model override
      createdAt: Date.now(),
      lastActivityAt: Date.now(),
    };
    this.sessions.set(key, session);
    return session;
  }

  get(threadId: string, channel: string): ThreadSession | undefined {
    return this.sessions.get(`${channel}:${threadId}`);
  }

  delete(threadId: string, channel: string): void {
    this.sessions.delete(`${channel}:${threadId}`);
  }

  /** Prune sessions older than maxAgeMs. */
  prune(maxAgeMs: number = 30 * 60 * 1000): number {
    const now = Date.now();
    let pruned = 0;
    for (const [key, session] of this.sessions) {
      if (now - session.lastActivityAt > maxAgeMs) {
        this.sessions.delete(key);
        pruned++;
      }
    }
    return pruned;
  }

  get size(): number {
    return this.sessions.size;
  }
}

// ─── Target syntax ────────────────────────────────────────────────────────────

export interface ParsedTarget {
  type: "user" | "channel" | "raw";
  id: string;
  original: string;
}

/**
 * Parse `user:<id>` / `channel:<id>` target syntax for outbound routing.
 *
 * @example
 *   parseTarget("user:123456")    → { type: "user", id: "123456", ... }
 *   parseTarget("channel:C08XYZ") → { type: "channel", id: "C08XYZ", ... }
 *   parseTarget("@username")      → { type: "raw", id: "@username", ... }
 */
export function parseTarget(target: string): ParsedTarget {
  if (target.startsWith("user:")) {
    return { type: "user", id: target.slice(5), original: target };
  }
  if (target.startsWith("channel:")) {
    return { type: "channel", id: target.slice(8), original: target };
  }
  return { type: "raw", id: target, original: target };
}

/**
 * Determine if a group message should activate the bot based on config.
 */
export function shouldActivate(
  text: string,
  botUsername: string,
  config: GroupChatConfig
): boolean {
  switch (config.activationMode) {
    case "all":
      return true;
    case "command":
      return text.trimStart().startsWith("/");
    case "mention":
    default:
      if (!config.mentionGating) return true;
      const lower = text.toLowerCase();
      return (
        lower.includes(`@${botUsername.toLowerCase()}`) ||
        lower.includes(botUsername.toLowerCase())
      );
  }
}
