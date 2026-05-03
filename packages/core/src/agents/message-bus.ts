/**
 * AgentMessageBus — In-process pub/sub for A2A (agent-to-agent) messaging.
 *
 * Sub-agents currently only return results to their parent. This module adds
 * an in-process pub/sub layer so agents can query each other mid-flight
 * without going through the parent:
 *
 *   - publish / subscribe on agent:<id>:msg channels
 *   - request / reply (one agent asks another a question, waits for answer)
 *   - broadcast to every currently-subscribed agent
 *   - every cross-agent message is Shield-filtered before delivery
 *
 * The bus is a per-process singleton. All concurrent sub-agent tasks share the
 * same instance automatically, which means:
 *   - a spawned sub-agent can call AgentMessageBus.getInstance() and immediately
 *     publish/subscribe on its own channel
 *   - the parent (SubAgentManager) calls registerChannel() when spawning so the
 *     bus knows about the agent before the first message arrives
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { FallbackShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";

// ─── Public types ─────────────────────────────────────────────────────────────

export type AgentMessageType = "query" | "response" | "alert" | "broadcast";

export interface AgentMessage {
  /** Unique message id (auto-assigned by bus on publish/request). */
  id: string;
  fromAgentId: string;
  /** undefined = broadcast */
  toAgentId?: string;
  content: string;
  type: AgentMessageType;
  timestamp: number;
  /** ATP/Shield gate result — set to true when the message passed the shield. */
  shieldPassed?: boolean;
}

/** Call this to remove a subscription. */
export type Unsubscribe = () => void;

// ─── Internal structures ──────────────────────────────────────────────────────

type Handler = (msg: AgentMessage) => void;

interface PendingReply {
  resolve: (msg: AgentMessage) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

let _instance: AgentMessageBus | null = null;
let _msgCounter = 0;

function nextId(): string {
  return `msg-${Date.now()}-${++_msgCounter}`;
}

// ─── AgentMessageBus ──────────────────────────────────────────────────────────

export class AgentMessageBus {
  /** Per-agentId subscriber lists. */
  private subscribers = new Map<string, Set<Handler>>();
  /** In-flight request/reply waiters keyed by message id. */
  private pending = new Map<string, PendingReply>();
  /** Known agent ids (registered by SubAgentManager on spawn). */
  private registered = new Set<string>();
  /** Shield guard — every message body is scanned before delivery. */
  private shield: ShieldGuardLike;

  constructor(shield?: ShieldGuardLike) {
    this.shield = shield ?? new FallbackShieldGuard();
  }

  // ─── Singleton ─────────────────────────────────────────────────────────────

  static getInstance(shield?: ShieldGuardLike): AgentMessageBus {
    if (!_instance) {
      _instance = new AgentMessageBus(shield);
    }
    return _instance;
  }

  /** Replace the singleton (useful in tests). */
  static resetInstance(): void {
    _instance = null;
  }

  // ─── Channel lifecycle ─────────────────────────────────────────────────────

  /**
   * Register an agent channel so the bus is aware of it.
   * Called automatically by SubAgentManager.spawn().
   */
  registerChannel(agentId: string): void {
    if (!this.registered.has(agentId)) {
      this.registered.add(agentId);
      if (!this.subscribers.has(agentId)) {
        this.subscribers.set(agentId, new Set());
      }
    }
  }

  /**
   * Remove an agent's channel and cancel any pending replies addressed to it.
   * Called by SubAgentManager when a sub-agent completes or is cancelled.
   */
  unregisterChannel(agentId: string): void {
    this.registered.delete(agentId);
    this.subscribers.delete(agentId);
  }

  /** Returns the set of currently-registered agent ids. */
  registeredAgents(): ReadonlySet<string> {
    return this.registered;
  }

  // ─── Shield gate ───────────────────────────────────────────────────────────

  private shieldCheck(msg: AgentMessage): { allowed: boolean; msg: AgentMessage } {
    const verdict = this.shield.scanRecalled(msg.content);
    const annotated: AgentMessage = { ...msg, shieldPassed: !verdict.blocked };
    if (verdict.blocked) {
      return { allowed: false, msg: annotated };
    }
    return { allowed: true, msg: annotated };
  }

  // ─── Publish ───────────────────────────────────────────────────────────────

  /**
   * Publish a message to a specific agent's channel.
   *
   * The message is Shield-filtered first. Blocked messages are silently
   * dropped (the sender's content is not delivered).
   */
  publish(agentId: string, message: Omit<AgentMessage, "id" | "timestamp">): void {
    const full: AgentMessage = {
      ...message,
      id: nextId(),
      timestamp: Date.now(),
    };
    this._deliver(agentId, full);
  }

  private _deliver(agentId: string, message: AgentMessage): void {
    const { allowed, msg } = this.shieldCheck(message);
    if (!allowed) return; // shield blocked — drop silently

    // If this is a response and there's a pending request waiter, resolve it.
    if (msg.type === "response") {
      // The waiter is keyed by the original query message id that was stored
      // in content as a reply-to header (format: "re:<queryId>\n<body>").
      const replyToMatch = msg.content.match(/^re:([^\n]+)\n/);
      if (replyToMatch) {
        const queryId = replyToMatch[1];
        const waiter = this.pending.get(queryId);
        if (waiter) {
          clearTimeout(waiter.timer);
          this.pending.delete(queryId);
          waiter.resolve(msg);
          return;
        }
      }
    }

    const subs = this.subscribers.get(agentId);
    if (!subs || subs.size === 0) return;
    for (const handler of subs) {
      try {
        handler(msg);
      } catch {
        // handlers must not crash the bus
      }
    }
  }

  // ─── Subscribe ─────────────────────────────────────────────────────────────

  /**
   * Subscribe to messages delivered to `agentId`.
   * Returns an Unsubscribe function.
   */
  subscribe(agentId: string, handler: Handler): Unsubscribe {
    if (!this.subscribers.has(agentId)) {
      this.subscribers.set(agentId, new Set());
    }
    this.subscribers.get(agentId)!.add(handler);
    return () => {
      this.subscribers.get(agentId)?.delete(handler);
    };
  }

  // ─── Request / reply ───────────────────────────────────────────────────────

  /**
   * Send a query from `fromId` to `toId` and wait for a response.
   *
   * The responding agent must publish a message of type "response" whose
   * content starts with `re:<queryMessageId>\n`.
   *
   * Rejects with a timeout error if no response arrives within `timeoutMs`
   * (default: 5 000 ms).
   */
  async request(
    fromId: string,
    toId: string,
    query: string,
    timeoutMs = 5_000,
  ): Promise<AgentMessage> {
    return new Promise<AgentMessage>((resolve, reject) => {
      const queryId = nextId();
      const msg: AgentMessage = {
        id: queryId,
        fromAgentId: fromId,
        toAgentId: toId,
        content: query,
        type: "query",
        timestamp: Date.now(),
      };

      // Shield-check query before registering it
      const { allowed, msg: checked } = this.shieldCheck(msg);
      if (!allowed) {
        reject(new Error("AgentMessageBus: query blocked by Shield"));
        return;
      }

      const timer = setTimeout(() => {
        this.pending.delete(queryId);
        reject(new Error(`AgentMessageBus: request from ${fromId} to ${toId} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pending.set(queryId, { resolve, reject, timer });

      // Deliver the query to the target's channel
      const subs = this.subscribers.get(toId);
      if (!subs || subs.size === 0) {
        // No subscriber yet — the waiter will time out unless someone subscribes later
        return;
      }
      for (const handler of subs) {
        try {
          handler(checked);
        } catch {
          // handlers must not crash the bus
        }
      }
    });
  }

  // ─── Broadcast ─────────────────────────────────────────────────────────────

  /**
   * Broadcast a message to ALL currently-registered agents (except the sender).
   * The message is Shield-filtered once; if blocked, nothing is delivered.
   */
  broadcast(fromId: string, message: Omit<AgentMessage, "id" | "timestamp" | "toAgentId">): void {
    const full: AgentMessage = {
      ...message,
      id: nextId(),
      fromAgentId: fromId,
      toAgentId: undefined,
      timestamp: Date.now(),
    };

    const { allowed, msg } = this.shieldCheck(full);
    if (!allowed) return;

    for (const agentId of this.registered) {
      if (agentId === fromId) continue;
      const subs = this.subscribers.get(agentId);
      if (!subs || subs.size === 0) continue;
      for (const handler of subs) {
        try {
          handler(msg);
        } catch {
          // handlers must not crash the bus
        }
      }
    }
  }

  // ─── Stats ─────────────────────────────────────────────────────────────────

  /** Returns the number of pending request/reply waiters. */
  pendingRequestCount(): number {
    return this.pending.size;
  }
}
