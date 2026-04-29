/**
 * Group Chat Tests (Issue #75)
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  FifoGroupQueue,
  ThreadSessionManager,
  parseTarget,
  shouldActivate,
  DEFAULT_GROUP_CHAT_CONFIG,
} from "../../gateway/src/channels/group-chat";
import type { GroupChatConfig, QueuedGroupMessage } from "../../gateway/src/channels/group-chat";

// ─── parseTarget ─────────────────────────────────────────────────────────────

describe("parseTarget", () => {
  it("parses user: prefix", () => {
    const t = parseTarget("user:123456");
    expect(t.type).toBe("user");
    expect(t.id).toBe("123456");
    expect(t.original).toBe("user:123456");
  });

  it("parses channel: prefix", () => {
    const t = parseTarget("channel:C08XYZ");
    expect(t.type).toBe("channel");
    expect(t.id).toBe("C08XYZ");
  });

  it("returns raw type for plain strings", () => {
    const t = parseTarget("@username");
    expect(t.type).toBe("raw");
    expect(t.id).toBe("@username");
  });

  it("returns raw type for Telegram IDs without prefix", () => {
    const t = parseTarget("1234567890");
    expect(t.type).toBe("raw");
    expect(t.id).toBe("1234567890");
  });
});

// ─── shouldActivate ───────────────────────────────────────────────────────────

describe("shouldActivate", () => {
  const mentionConfig: GroupChatConfig = {
    ...DEFAULT_GROUP_CHAT_CONFIG,
    activationMode: "mention",
    mentionGating: true,
  };

  const allConfig: GroupChatConfig = {
    ...DEFAULT_GROUP_CHAT_CONFIG,
    activationMode: "all",
  };

  const commandConfig: GroupChatConfig = {
    ...DEFAULT_GROUP_CHAT_CONFIG,
    activationMode: "command",
  };

  it("activates for all messages in 'all' mode", () => {
    expect(shouldActivate("hello", "lyrie", allConfig)).toBe(true);
    expect(shouldActivate("anything", "lyrie", allConfig)).toBe(true);
  });

  it("activates for /commands in command mode", () => {
    expect(shouldActivate("/scan", "lyrie", commandConfig)).toBe(true);
    expect(shouldActivate("  /help", "lyrie", commandConfig)).toBe(true);
  });

  it("does not activate for non-commands in command mode", () => {
    expect(shouldActivate("hello there", "lyrie", commandConfig)).toBe(false);
  });

  it("activates when @mentioned in mention mode", () => {
    expect(shouldActivate("hey @lyrie, help me", "lyrie", mentionConfig)).toBe(true);
    expect(shouldActivate("Hey @Lyrie scan this", "lyrie", mentionConfig)).toBe(true);
  });

  it("does not activate without mention in mention mode", () => {
    expect(shouldActivate("hi everyone", "lyrie", mentionConfig)).toBe(false);
  });

  it("activates for all messages when mentionGating is false", () => {
    const noGate: GroupChatConfig = { ...mentionConfig, mentionGating: false };
    expect(shouldActivate("hello", "lyrie", noGate)).toBe(true);
  });
});

// ─── FifoGroupQueue ───────────────────────────────────────────────────────────

describe("FifoGroupQueue", () => {
  let flushed: QueuedGroupMessage[][] = [];

  const makeQueue = (debounceMs = 50, maxQueueSize = 10): FifoGroupQueue => {
    flushed = [];
    const config: GroupChatConfig = {
      ...DEFAULT_GROUP_CHAT_CONFIG,
      debounceMs,
      maxQueueSize,
    };
    return new FifoGroupQueue(config, async (batch) => {
      flushed.push(batch);
    });
  };

  const makeMsg = (id: string): QueuedGroupMessage => ({
    id,
    chatId: "chat1",
    userId: "user1",
    text: `msg ${id}`,
    channel: "telegram",
    timestamp: Date.now(),
  });

  it("starts with size 0", () => {
    const q = makeQueue();
    expect(q.size).toBe(0);
  });

  it("enqueues messages", () => {
    const q = makeQueue(1000);
    q.enqueue(makeMsg("1"));
    q.enqueue(makeMsg("2"));
    expect(q.size).toBe(2);
  });

  it("flushes batch via flushNow", async () => {
    const q = makeQueue(1000);
    q.enqueue(makeMsg("1"));
    q.enqueue(makeMsg("2"));
    q.flushNow();
    // After flush, queue should be empty
    expect(q.size).toBe(0);
    expect(flushed.length).toBe(1);
    expect(flushed[0].length).toBe(2);
  });

  it("drops oldest when at max capacity", () => {
    const q = makeQueue(1000, 3);
    q.enqueue(makeMsg("1")); // will be dropped
    q.enqueue(makeMsg("2"));
    q.enqueue(makeMsg("3"));
    q.enqueue(makeMsg("4")); // triggers drop of "1"
    expect(q.size).toBe(3);
    // The queue should not contain the oldest message
    q.flushNow();
    const ids = flushed[0].map((m) => m.id);
    expect(ids).not.toContain("1");
    expect(ids).toContain("4");
  });

  it("debounces messages within window", async () => {
    const q = makeQueue(50);
    q.enqueue(makeMsg("a"));
    q.enqueue(makeMsg("b"));
    // Wait for debounce
    await new Promise((r) => setTimeout(r, 100));
    expect(flushed.length).toBe(1);
    expect(flushed[0].length).toBe(2);
  });
});

// ─── ThreadSessionManager ─────────────────────────────────────────────────────

describe("ThreadSessionManager", () => {
  let mgr: ThreadSessionManager;

  beforeEach(() => {
    mgr = new ThreadSessionManager();
  });

  it("starts with zero sessions", () => {
    expect(mgr.size).toBe(0);
  });

  it("creates a new session", () => {
    const s = mgr.getOrCreate("t1", "chat1", "telegram");
    expect(s.threadId).toBe("t1");
    expect(s.parentChatId).toBe("chat1");
    expect(s.channel).toBe("telegram");
    expect(mgr.size).toBe(1);
  });

  it("returns the same session on subsequent calls", () => {
    const s1 = mgr.getOrCreate("t1", "chat1", "telegram");
    const s2 = mgr.getOrCreate("t1", "chat1", "telegram");
    expect(s1).toBe(s2);
  });

  it("inherits parent model override", () => {
    const s = mgr.getOrCreate("t1", "chat1", "telegram", "opus-4");
    expect(s.modelOverride).toBe("opus-4");
  });

  it("does NOT carry over transcript (no transcriptContext field)", () => {
    const s = mgr.getOrCreate("t1", "chat1", "telegram");
    expect((s as any).transcriptContext).toBeUndefined();
  });

  it("isolates sessions by channel", () => {
    mgr.getOrCreate("t1", "chat1", "telegram");
    mgr.getOrCreate("t1", "chat1", "discord");
    expect(mgr.size).toBe(2);
  });

  it("deletes a session", () => {
    mgr.getOrCreate("t1", "chat1", "telegram");
    mgr.delete("t1", "telegram");
    expect(mgr.get("t1", "telegram")).toBeUndefined();
    expect(mgr.size).toBe(0);
  });

  it("prunes stale sessions", async () => {
    mgr.getOrCreate("t1", "chat1", "telegram");
    await new Promise((r) => setTimeout(r, 10));
    const pruned = mgr.prune(5); // 5ms max age
    expect(pruned).toBe(1);
    expect(mgr.size).toBe(0);
  });

  it("does not prune fresh sessions", () => {
    mgr.getOrCreate("t1", "chat1", "telegram");
    const pruned = mgr.prune(60_000);
    expect(pruned).toBe(0);
  });
});
