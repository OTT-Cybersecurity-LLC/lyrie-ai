/**
 * CronManager — Scheduled task execution for Lyrie Agent.
 *
 * Supports:
 * - Recurring tasks (every N minutes/hours/seconds)
 * - One-shot delayed tasks
 * - Built-in tasks: memory backup, self-healing, heartbeat
 * - Custom cron jobs added at runtime or via config
 * - Clean shutdown with timer cancellation
 * - Execution history and stats
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type CronInterval = {
  value: number;
  unit: "seconds" | "minutes" | "hours";
};

export interface CronTask {
  /** Unique task identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of what this task does */
  description: string;
  /** Execution interval */
  interval: CronInterval;
  /** The function to execute */
  handler: () => Promise<void>;
  /** Whether this is a one-shot (runs once after delay, then removed) */
  oneShot?: boolean;
  /** Whether this task is currently enabled */
  enabled: boolean;
  /** Tags for filtering */
  tags?: string[];
}

export interface CronExecution {
  taskId: string;
  startTime: number;
  endTime: number;
  success: boolean;
  error?: string;
}

export interface CronManagerConfig {
  /** Maximum concurrent task executions */
  maxConcurrent?: number;
  /** Whether to run tasks immediately on registration */
  runImmediately?: boolean;
  /** Memory core reference for built-in tasks */
  onMemoryBackup?: () => Promise<void>;
  /** Self-healing check handler */
  onSelfHealingCheck?: () => Promise<void>;
  /** Heartbeat handler */
  onHeartbeat?: () => Promise<void>;
}

// ─── CronManager ─────────────────────────────────────────────────────────────

export class CronManager {
  private tasks: Map<string, CronTask> = new Map();
  private timers: Map<string, ReturnType<typeof setInterval> | ReturnType<typeof setTimeout>> = new Map();
  private running = false;
  private executionLog: CronExecution[] = [];
  private maxLogSize = 500;
  private maxConcurrent: number;
  private activeCount = 0;
  private config: CronManagerConfig;

  constructor(config: CronManagerConfig = {}) {
    this.config = config;
    this.maxConcurrent = config.maxConcurrent ?? 5;
  }

  /**
   * Initialize and register built-in tasks.
   */
  async initialize(): Promise<void> {
    this.running = true;

    // ── Built-in: Memory Backup (hourly) ──────────────────────────────
    this.registerTask({
      id: "memory-backup",
      name: "Memory Backup",
      description: "Backs up memory state to disk for disaster recovery",
      interval: { value: 1, unit: "hours" },
      enabled: true,
      tags: ["builtin", "memory"],
      handler: async () => {
        if (this.config.onMemoryBackup) {
          await this.config.onMemoryBackup();
        } else {
          console.log("[cron] Memory backup: no handler configured");
        }
      },
    });

    // ── Built-in: Self-Healing Check (every 30 min) ───────────────────
    this.registerTask({
      id: "self-healing-check",
      name: "Self-Healing Check",
      description:
        "Checks agent health, repairs broken state, restarts stalled components",
      interval: { value: 30, unit: "minutes" },
      enabled: true,
      tags: ["builtin", "health"],
      handler: async () => {
        if (this.config.onSelfHealingCheck) {
          await this.config.onSelfHealingCheck();
        } else {
          // Default: basic health check
          const memUsage = process.memoryUsage();
          const heapUsedMB = memUsage.heapUsed / 1024 / 1024;

          if (heapUsedMB > 512) {
            console.warn(
              `[cron] ⚠️ High memory usage: ${heapUsedMB.toFixed(0)}MB heap`
            );
            // Force GC if available
            if (typeof global.gc === "function") {
              global.gc();
              console.log("[cron] Forced garbage collection");
            }
          }

          console.log(
            `[cron] Health check OK — heap: ${heapUsedMB.toFixed(0)}MB, uptime: ${(process.uptime() / 3600).toFixed(1)}h`
          );
        }
      },
    });

    // ── Built-in: Heartbeat (every 5 min) ─────────────────────────────
    this.registerTask({
      id: "heartbeat",
      name: "Heartbeat",
      description: "Lightweight ping to confirm agent is alive",
      interval: { value: 5, unit: "minutes" },
      enabled: true,
      tags: ["builtin", "health"],
      handler: async () => {
        if (this.config.onHeartbeat) {
          await this.config.onHeartbeat();
        }
        // Heartbeat is silent by default — just keeps the agent "breathing"
      },
    });

    console.log(`   → CronManager active: ${this.tasks.size} tasks registered`);
  }

  // ─── Task Management ───────────────────────────────────────────────────

  /**
   * Register a new cron task and start its timer.
   */
  registerTask(task: CronTask): void {
    // Stop existing timer if re-registering
    if (this.timers.has(task.id)) {
      this.stopTask(task.id);
    }

    this.tasks.set(task.id, task);

    if (task.enabled && this.running) {
      this.startTask(task.id);
    }
  }

  /**
   * Schedule a one-shot task that runs once after a delay.
   */
  scheduleOnce(
    id: string,
    name: string,
    delay: CronInterval,
    handler: () => Promise<void>
  ): void {
    this.registerTask({
      id,
      name,
      description: `One-shot: ${name}`,
      interval: delay,
      handler,
      oneShot: true,
      enabled: true,
      tags: ["oneshot"],
    });
  }

  /**
   * Remove a task entirely.
   */
  removeTask(id: string): boolean {
    this.stopTask(id);
    return this.tasks.delete(id);
  }

  /**
   * Enable a disabled task.
   */
  enableTask(id: string): boolean {
    const task = this.tasks.get(id);
    if (!task) return false;
    task.enabled = true;
    if (this.running) this.startTask(id);
    return true;
  }

  /**
   * Disable a task (stops timer but keeps registration).
   */
  disableTask(id: string): boolean {
    const task = this.tasks.get(id);
    if (!task) return false;
    task.enabled = false;
    this.stopTask(id);
    return true;
  }

  // ─── Timer Control ─────────────────────────────────────────────────────

  private startTask(id: string): void {
    const task = this.tasks.get(id);
    if (!task || this.timers.has(id)) return;

    const intervalMs = this.toMs(task.interval);

    if (task.oneShot) {
      const timer = setTimeout(async () => {
        await this.executeTask(id);
        this.removeTask(id);
      }, intervalMs);
      this.timers.set(id, timer);
    } else {
      // Run immediately if configured
      if (this.config.runImmediately) {
        this.executeTask(id).catch(() => {});
      }

      const timer = setInterval(() => {
        this.executeTask(id).catch(() => {});
      }, intervalMs);
      this.timers.set(id, timer);
    }
  }

  private stopTask(id: string): void {
    const timer = this.timers.get(id);
    if (timer) {
      clearInterval(timer as any);
      clearTimeout(timer as any);
      this.timers.delete(id);
    }
  }

  /**
   * Execute a task with concurrency control and error handling.
   */
  private async executeTask(id: string): Promise<void> {
    const task = this.tasks.get(id);
    if (!task || !task.enabled) return;

    // Concurrency gate
    if (this.activeCount >= this.maxConcurrent) {
      console.warn(
        `[cron] Skipping ${id}: max concurrent (${this.maxConcurrent}) reached`
      );
      return;
    }

    this.activeCount++;
    const start = Date.now();

    try {
      await task.handler();
      this.logExecution({
        taskId: id,
        startTime: start,
        endTime: Date.now(),
        success: true,
      });
    } catch (err: any) {
      console.error(`[cron] Task ${id} failed:`, err.message);
      this.logExecution({
        taskId: id,
        startTime: start,
        endTime: Date.now(),
        success: false,
        error: err.message,
      });
    } finally {
      this.activeCount--;
    }
  }

  // ─── Shutdown ──────────────────────────────────────────────────────────

  /**
   * Stop all timers and shut down cleanly.
   */
  async shutdown(): Promise<void> {
    this.running = false;

    for (const [id] of this.timers) {
      this.stopTask(id);
    }

    // Wait for active tasks to complete (max 10s)
    const deadline = Date.now() + 10000;
    while (this.activeCount > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }

    if (this.activeCount > 0) {
      console.warn(`[cron] Shutdown with ${this.activeCount} tasks still running`);
    }

    console.log("[cron] CronManager shut down");
  }

  // ─── Status & Info ─────────────────────────────────────────────────────

  /**
   * Get all registered tasks.
   */
  listTasks(): Array<{
    id: string;
    name: string;
    description: string;
    interval: string;
    enabled: boolean;
    oneShot: boolean;
    tags: string[];
  }> {
    return Array.from(this.tasks.values()).map((t) => ({
      id: t.id,
      name: t.name,
      description: t.description,
      interval: `${t.interval.value} ${t.interval.unit}`,
      enabled: t.enabled,
      oneShot: t.oneShot ?? false,
      tags: t.tags ?? [],
    }));
  }

  /**
   * Get execution history.
   */
  getHistory(limit = 50): CronExecution[] {
    return this.executionLog.slice(-limit);
  }

  /**
   * Get stats.
   */
  stats(): {
    totalTasks: number;
    activeTasks: number;
    totalExecutions: number;
    successRate: number;
    activeCount: number;
  } {
    const total = this.executionLog.length;
    const successes = this.executionLog.filter((e) => e.success).length;

    return {
      totalTasks: this.tasks.size,
      activeTasks: this.timers.size,
      totalExecutions: total,
      successRate: total > 0 ? successes / total : 1,
      activeCount: this.activeCount,
    };
  }

  get isRunning(): boolean {
    return this.running;
  }

  // ─── Internal ──────────────────────────────────────────────────────────

  private toMs(interval: CronInterval): number {
    switch (interval.unit) {
      case "seconds":
        return interval.value * 1000;
      case "minutes":
        return interval.value * 60 * 1000;
      case "hours":
        return interval.value * 60 * 60 * 1000;
    }
  }

  private logExecution(execution: CronExecution): void {
    this.executionLog.push(execution);
    if (this.executionLog.length > this.maxLogSize) {
      this.executionLog = this.executionLog.slice(-this.maxLogSize);
    }
  }
}
