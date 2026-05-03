/**
 * LyrieDaemon / DaemonEngine — Tick-based proactive loop (KAIROS pattern).
 *
 * Two classes live here:
 *  - LyrieDaemon: callback-based, used by existing start-all / integration code.
 *  - DaemonEngine: event-emitter-based v1.0.0 proactive mode (threat-watch,
 *    self-heal, ASI06-ready).
 *
 * The tick prompt is intentionally minimal — the agent decides what to do,
 * it never invents work.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── LyrieDaemon (original KAIROS pattern) ───────────────────────────────────

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

// ─── DaemonEngine (v1.0.0 proactive mode) ────────────────────────────────────

/**
 * A single finding emitted during a daemon tick.
 * Mirrors RawFinding from the pentest pipeline but kept lightweight
 * so the daemon doesn't pull in the full pentest dependency tree.
 */
export interface AdapterFinding {
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
  /** Source system that produced the finding (e.g. "threat-intel", "cve-feed"). */
  source: string;
  /** Unix ms timestamp. */
  timestamp: number;
  metadata?: Record<string, unknown>;
}

/**
 * Result of a single DaemonEngine tick.
 */
export interface DaemonTickResult {
  status: "alert" | "idle" | "action";
  findings?: AdapterFinding[];
  actionsTriggered?: string[];
  message?: string;
}

/**
 * Configuration passed to DaemonEngine.start().
 * All fields required — CLI parses flags and fills defaults before calling.
 */
export interface DaemonEngineConfig {
  /** Tick interval in milliseconds. */
  intervalMs: number;
  /** When true, pull CVE / threat-intel feed and cross-reference the stack. */
  threatWatch: boolean;
  /** When true, spawn `lyrie hack` automatically on critical findings. */
  selfHeal: boolean;
  /** Provider id for any LLM calls inside ticks. E.g. "hermes". */
  provider: string;
  /** Channel ids to send alerts to. E.g. ["telegram"]. */
  channels: string[];
  /** Stop after this many ticks (for testing / bounded runs). 0 = unlimited. */
  maxTicksBeforeRest?: number;
}

type DaemonEventHandler = (payload: DaemonTickResult) => void;

/**
 * DaemonEngine — proactive continuous-operation mode for Lyrie v1.0.0.
 *
 * Design:
 * - KAIROS-style tick loop: each tick is a deterministic "what needs doing?" check.
 * - Event-emitter pattern for loose coupling: listeners react to alerts/actions/idle.
 * - tick() is async and independently testable without a running loop.
 * - Never invents work: returns "idle" when there is nothing real to act on.
 *
 * The protected check methods (_checkAgentHealth, _checkThreatIntel) are designed
 * to be overridden in tests via subclassing, keeping the core logic testable
 * without any real network calls.
 *
 * Usage:
 * ```ts
 * const engine = new DaemonEngine();
 * engine.on('alert', (r) => sendTelegram(r.findings));
 * engine.on('action', (r) => log(r.actionsTriggered));
 * await engine.start({
 *   intervalMs: 5 * 60_000,
 *   threatWatch: true,
 *   selfHeal: false,
 *   provider: 'hermes',
 *   channels: ['telegram'],
 * });
 * ```
 */
export class DaemonEngine {
  private _running = false;
  private _stopRequested = false;
  private _tickCount = 0;
  private _config: DaemonEngineConfig | null = null;
  private _wakeUp: (() => void) | null = null; // interrupts sleep()

  private _listeners: Record<string, DaemonEventHandler[]> = {
    alert: [],
    idle: [],
    action: [],
  };

  /** The tick prompt used when calling the LLM for contextual analysis. */
  tickPrompt: string = DAEMON_TICK_PROMPT;

  // ─── Event API ─────────────────────────────────────────────────────────────

  /**
   * Register an event listener.
   * Events:
   *   "alert"  — one or more high/critical findings detected
   *   "idle"   — nothing actionable this tick
   *   "action" — one or more self-heal / mitigation actions triggered
   */
  on(event: "alert" | "idle" | "action", handler: DaemonEventHandler): void {
    if (!this._listeners[event]) this._listeners[event] = [];
    this._listeners[event].push(handler);
  }

  private _emit(event: "alert" | "idle" | "action", payload: DaemonTickResult): void {
    for (const h of this._listeners[event] ?? []) {
      try { h(payload); } catch { /* listener errors must not crash the loop */ }
    }
  }

  // ─── State ─────────────────────────────────────────────────────────────────

  /** True while the tick loop is actively running. */
  isRunning(): boolean { return this._running; }

  /** Number of ticks fired since the last start() call. */
  ticksFired(): number { return this._tickCount; }

  // ─── Core: single tick ─────────────────────────────────────────────────────

  /**
   * Run a single tick and return the result.
   * This is the primary testable unit: no timer, no loop, pure logic.
   *
   * Tick logic (never invents work):
   *  1. Check agent health
   *  2. If threatWatch: pull CVE / threat-intel feed, cross-reference lyrie.yml
   *  3. If critical findings + selfHeal: record actionsTriggered
   *  4. Classify result: alert / action / idle
   *  5. Emit corresponding event
   */
  async tick(): Promise<DaemonTickResult> {
    this._tickCount++;
    const config = this._config;
    if (!config) {
      // tick() called before start() — safe no-op (useful in unit tests)
      return { status: "idle", message: "No config — daemon not started" };
    }

    const findings: AdapterFinding[] = [];
    const actionsTriggered: string[] = [];

    // ── 1. Agent health check ─────────────────────────────────────────────
    try {
      const healthFinding = await this._checkAgentHealth(config);
      if (healthFinding) findings.push(healthFinding);
    } catch (err) {
      findings.push({
        id: `health-err-${Date.now()}`,
        title: "Agent health check failed",
        severity: "low",
        description: String(err),
        source: "health-check",
        timestamp: Date.now(),
      });
    }

    // ── 2. Threat-watch: CVE / threat-intel feed ──────────────────────────
    if (config.threatWatch) {
      try {
        const threatFindings = await this._checkThreatIntel(config);
        findings.push(...threatFindings);
      } catch (err) {
        // Feed unavailable is low-severity; don't crash the loop.
        findings.push({
          id: `feed-err-${Date.now()}`,
          title: "Threat-intel feed unavailable",
          severity: "low",
          description: String(err),
          source: "threat-intel",
          timestamp: Date.now(),
        });
      }
    }

    // ── 3. Self-heal: spawn lyrie hack on critical findings ───────────────
    const criticals = findings.filter((f) => f.severity === "critical");
    if (config.selfHeal && criticals.length > 0) {
      for (const f of criticals) {
        actionsTriggered.push(`lyrie hack --target ${f.source} --finding ${f.id}`);
      }
    }

    // ── 4. Classify + emit ────────────────────────────────────────────────
    let result: DaemonTickResult;

    const hasHighOrCritical = findings.some(
      (f) => f.severity === "critical" || f.severity === "high"
    );

    if (hasHighOrCritical) {
      result = {
        status: "alert",
        findings,
        actionsTriggered: actionsTriggered.length ? actionsTriggered : undefined,
        message: `${findings.length} finding(s) — ${criticals.length} critical`,
      };
      this._emit("alert", result);
      if (actionsTriggered.length) this._emit("action", result);
    } else if (actionsTriggered.length > 0) {
      result = {
        status: "action",
        findings: findings.length ? findings : undefined,
        actionsTriggered,
        message: `${actionsTriggered.length} action(s) triggered`,
      };
      this._emit("action", result);
    } else {
      result = {
        status: "idle",
        findings: findings.length ? findings : undefined,
        message: "IDLE",
      };
      this._emit("idle", result);
    }

    return result;
  }

  // ─── Loop ──────────────────────────────────────────────────────────────────

  /**
   * Start the tick loop. Runs until stop() is called or maxTicksBeforeRest is reached.
   */
  async start(config: DaemonEngineConfig): Promise<void> {
    if (this._running) throw new Error("DaemonEngine already running");

    // Validate config
    if (config.intervalMs <= 0) throw new Error("DaemonEngineConfig.intervalMs must be > 0");
    if (!config.provider) throw new Error("DaemonEngineConfig.provider is required");

    this._config = config;
    this._running = true;
    this._stopRequested = false;
    this._tickCount = 0;

    try {
      while (!this._stopRequested) {
        await this.tick();
        if (this._stopRequested) break;
        if (config.maxTicksBeforeRest && this._tickCount >= config.maxTicksBeforeRest) break;
        await this._interruptibleSleep(config.intervalMs);
      }
    } finally {
      this._running = false;
    }
  }

  /**
   * Request the daemon to stop at the next safe checkpoint.
   * Wakes up any in-progress sleep so the loop exits immediately.
   */
  async stop(): Promise<void> {
    this._stopRequested = true;
    if (this._wakeUp) this._wakeUp();
  }

  // ─── Private: interruptible sleep ─────────────────────────────────────────

  private _interruptibleSleep(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms);
      this._wakeUp = () => { clearTimeout(timer); resolve(); };
    }).then(() => { this._wakeUp = null; });
  }

  // ─── Protected: pluggable checks (override in tests / subclass) ────────────

  /**
   * Check agent/system health.
   * Returns an AdapterFinding if something is wrong, null if all clear.
   */
  protected async _checkAgentHealth(_config: DaemonEngineConfig): Promise<AdapterFinding | null> {
    // Default: always healthy (no network calls in base implementation).
    // Real implementation: ping local providers, check disk, memory pressure, etc.
    return null;
  }

  /**
   * Pull threat-intel / CVE feed and cross-reference against the lyrie.yml stack.
   * Returns an array of findings (empty = no threats detected).
   */
  protected async _checkThreatIntel(_config: DaemonEngineConfig): Promise<AdapterFinding[]> {
    // Default: empty (no real feed wired — avoids network calls in tests).
    // Real implementation: fetch NVD/OSV/GitHub Advisory feed, parse, cross-ref.
    return [];
  }
}

// ─── Prompts ──────────────────────────────────────────────────────────────────

export const DAEMON_TICK_PROMPT = `You are running in daemon mode. You receive <tick> events as check-ins.
Check: (1) new CVEs matching the stack, (2) pending scans, (3) incoming alerts.
Do whatever is most useful, or return IDLE if nothing requires action.
Never invent work. Report findings concisely.`;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
