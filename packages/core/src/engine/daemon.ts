/**
 * LyrieDaemon — Tick-based proactive loop (KAIROS pattern).
 *
 * Keeps Lyrie running continuously between user interactions.
 * Each `<tick>` is a "you are awake, what now?" prompt that lets the
 * agent run scout tasks, monitor deployments, and refresh threat-feed
 * cache without waiting for the user.
 *
 * The tick prompt is intentionally minimal:
 *   "You are running autonomously. The time in this <tick> is the user's
 *    local time. Do whatever seems most useful, or call sleep() if there
 *    is nothing to do. Never invent work."
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export interface DaemonConfig {
  /** Tick interval in milliseconds. Default: 5 minutes. */
  intervalMs?: number;
  /** Maximum consecutive ticks before the daemon stops. 0 = unlimited. */
  maxTicks?: number;
  /** Channel id (e.g. "telegram"). Used for outbound alerts. */
  channel?: string;
  /** True if the daemon should never make external API calls. */
  requireLocalProvider?: boolean;
  /** Tick handler. Receives the tick payload and returns the next-action plan. */
  onTick: (tick: TickEvent) => Promise<TickResult>;
  /** Optional callback when the daemon decides to sleep. */
  onSleep?: (untilMs: number) => Promise<void>;
}

export interface TickEvent {
  /** Sequential tick index. */
  index: number;
  /** ISO local-time string (Asia/Dubai by default — caller can override). */
  localTime: string;
  /** Wall-clock UTC timestamp. */
  timestampMs: number;
  /** Reason this tick fired ("scheduled" | "user_message" | "alert" | …). */
  reason: string;
  /** Free-form payload from the upstream queue. */
  payload?: Record<string, unknown>;
}

export interface TickResult {
  /** True if the daemon should immediately tick again (vs wait for interval). */
  immediate?: boolean;
  /** True to gracefully stop the daemon after this tick. */
  stop?: boolean;
  /** Optional sleep override (ms) — daemon waits this long before next tick. */
  sleepMs?: number;
  /** Free-form notes for diagnostic logging. */
  notes?: string;
}

export const LYRIE_TICK_PROMPT = `# Tick Mode

You are running autonomously. You will receive periodic <tick> prompts as check-ins.

## Rules
1. The time inside each <tick> is the user's current LOCAL time. Use it to judge time of day. External tool timestamps (Slack, GitHub, threat feeds) may be in UTC.
2. Do whatever seems most useful: scout tasks, dependency-CVE check, threat-feed delta, attack-surface drift, MCP server health, agent-fleet sanity.
3. If there is genuinely nothing useful to do, call sleep() and return. **Never invent work.**
4. Never bother the user with non-critical findings during night hours.
5. Dedup: if you alerted on the same finding within the last 4 hours, suppress.
6. Honest tick reports only — see "Report Outcomes Faithfully" rule above.`;

export class LyrieDaemon {
  private cfg: Required<Omit<DaemonConfig, "channel" | "onSleep">> & Pick<DaemonConfig, "channel" | "onSleep">;
  private running = false;
  private tickCount = 0;
  private stopRequested = false;

  constructor(cfg: DaemonConfig) {
    this.cfg = {
      intervalMs: cfg.intervalMs ?? 5 * 60_000,
      maxTicks: cfg.maxTicks ?? 0,
      requireLocalProvider: cfg.requireLocalProvider ?? false,
      onTick: cfg.onTick,
      channel: cfg.channel,
      onSleep: cfg.onSleep,
    };
  }

  isRunning(): boolean {
    return this.running;
  }

  ticksFired(): number {
    return this.tickCount;
  }

  /** Stop the daemon at the next safe checkpoint. */
  stop(): void {
    this.stopRequested = true;
  }

  /** Run a single tick synchronously (used by tests + manual triggers). */
  async runOnce(reason = "manual"): Promise<TickResult> {
    this.tickCount++;
    const tick: TickEvent = {
      index: this.tickCount,
      localTime: new Date().toLocaleString("en-US", { timeZone: "Asia/Dubai" }),
      timestampMs: Date.now(),
      reason,
    };
    return this.cfg.onTick(tick);
  }

  /** Start the tick loop. Resolves when stop() is called or maxTicks is reached. */
  async start(): Promise<void> {
    if (this.running) throw new Error("LyrieDaemon already running");
    this.running = true;
    this.stopRequested = false;
    this.tickCount = 0;

    try {
      while (!this.stopRequested) {
        const result = await this.runOnce("scheduled");
        if (result.stop || this.stopRequested) break;
        if (this.cfg.maxTicks && this.tickCount >= this.cfg.maxTicks) break;
        if (result.immediate) continue;
        const wait = result.sleepMs ?? this.cfg.intervalMs;
        if (this.cfg.onSleep) await this.cfg.onSleep(wait);
        await sleep(wait);
      }
    } finally {
      this.running = false;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
