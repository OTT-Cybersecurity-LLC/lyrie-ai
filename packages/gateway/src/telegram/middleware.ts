/**
 * Telegram Middleware — Rate limiting, auth checking, and logging.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { TgUpdate, TgMessage } from "./types";
import type { TelegramConfig } from "../common/types";

// ─── Rate Limiter ───────────────────────────────────────────────────────────────

interface RateBucket {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private buckets: Map<string, RateBucket> = new Map();
  private maxPerMinute: number;
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(maxPerMinute: number = 30) {
    this.maxPerMinute = maxPerMinute;
    // Clean up stale buckets every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  /**
   * Check if a user is rate-limited. Returns true if allowed, false if blocked.
   */
  check(userId: string): { allowed: boolean; remainingMs?: number } {
    const now = Date.now();
    const bucket = this.buckets.get(userId);

    if (!bucket || now >= bucket.resetAt) {
      this.buckets.set(userId, { count: 1, resetAt: now + 60_000 });
      return { allowed: true };
    }

    if (bucket.count >= this.maxPerMinute) {
      return { allowed: false, remainingMs: bucket.resetAt - now };
    }

    bucket.count++;
    return { allowed: true };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now >= bucket.resetAt) {
        this.buckets.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.buckets.clear();
  }
}

// ─── Auth Checker ───────────────────────────────────────────────────────────────

export class AuthChecker {
  private allowedUsers: Set<string>;
  private allowedChats: Set<string>;
  private allowAll: boolean;

  constructor(config: TelegramConfig) {
    this.allowedUsers = new Set(config.allowedUsers || []);
    this.allowedChats = new Set(config.allowedChats || []);
    // If no restrictions are set, allow all
    this.allowAll = this.allowedUsers.size === 0 && this.allowedChats.size === 0;
  }

  /**
   * Check if an update is from an authorized source.
   */
  isAuthorized(update: TgUpdate): boolean {
    if (this.allowAll) return true;

    const message = update.message || update.callback_query?.message;
    if (!message) return false;

    const userId = String(update.message?.from?.id || update.callback_query?.from?.id);
    const chatId = String(message.chat.id);

    if (this.allowedUsers.has(userId)) return true;
    if (this.allowedChats.has(chatId)) return true;

    return false;
  }

  /**
   * Dynamically add a user to the allow list.
   */
  allowUser(userId: string): void {
    this.allowedUsers.add(userId);
    this.allowAll = false;
  }

  /**
   * Dynamically add a chat to the allow list.
   */
  allowChat(chatId: string): void {
    this.allowedChats.add(chatId);
    this.allowAll = false;
  }
}

// ─── Request Logger ─────────────────────────────────────────────────────────────

export type LogLevel = "debug" | "info" | "warn" | "error";

export class RequestLogger {
  private level: LogLevel;
  private static LEVEL_RANK: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  constructor(level: LogLevel = "info") {
    this.level = level;
  }

  private shouldLog(level: LogLevel): boolean {
    return RequestLogger.LEVEL_RANK[level] >= RequestLogger.LEVEL_RANK[this.level];
  }

  private fmt(level: LogLevel, component: string, msg: string): string {
    const ts = new Date().toISOString();
    return `[${ts}] [${level.toUpperCase()}] [TG:${component}] ${msg}`;
  }

  debug(component: string, msg: string): void {
    if (this.shouldLog("debug")) console.debug(this.fmt("debug", component, msg));
  }

  info(component: string, msg: string): void {
    if (this.shouldLog("info")) console.log(this.fmt("info", component, msg));
  }

  warn(component: string, msg: string): void {
    if (this.shouldLog("warn")) console.warn(this.fmt("warn", component, msg));
  }

  error(component: string, msg: string, err?: unknown): void {
    if (this.shouldLog("error")) {
      console.error(this.fmt("error", component, msg));
      if (err) console.error(err);
    }
  }

  /**
   * Log an incoming update summary.
   */
  logUpdate(update: TgUpdate): void {
    const msg = update.message;
    const cb = update.callback_query;

    if (msg) {
      const from = msg.from ? `${msg.from.first_name}(${msg.from.id})` : "unknown";
      const chat = `${msg.chat.type}:${msg.chat.id}`;
      const text = msg.text?.substring(0, 50) || "[media]";
      this.info("update", `${from} in ${chat}: ${text}`);
    } else if (cb) {
      const from = `${cb.from.first_name}(${cb.from.id})`;
      this.info("callback", `${from}: ${cb.data}`);
    }
  }
}

// ─── Middleware Pipeline ────────────────────────────────────────────────────────

export interface MiddlewareResult {
  allowed: boolean;
  reason?: string;
}

export class MiddlewarePipeline {
  private rateLimiter: RateLimiter;
  private authChecker: AuthChecker;
  private logger: RequestLogger;

  constructor(config: TelegramConfig, logLevel: LogLevel = "info") {
    this.rateLimiter = new RateLimiter(config.rateLimitPerMinute || 30);
    this.authChecker = new AuthChecker(config);
    this.logger = new RequestLogger(logLevel);
  }

  /**
   * Process an update through all middleware. Returns whether to continue.
   */
  process(update: TgUpdate): MiddlewareResult {
    // 1. Log the update
    this.logger.logUpdate(update);

    // 2. Auth check
    if (!this.authChecker.isAuthorized(update)) {
      const userId = update.message?.from?.id || update.callback_query?.from?.id;
      this.logger.warn("auth", `Unauthorized access attempt from user ${userId}`);
      return { allowed: false, reason: "unauthorized" };
    }

    // 3. Rate limit check
    const userId = String(
      update.message?.from?.id || update.callback_query?.from?.id || "unknown"
    );
    const rateCheck = this.rateLimiter.check(userId);
    if (!rateCheck.allowed) {
      this.logger.warn("rate", `User ${userId} rate-limited (retry in ${rateCheck.remainingMs}ms)`);
      return {
        allowed: false,
        reason: `rate_limited:${rateCheck.remainingMs}`,
      };
    }

    return { allowed: true };
  }

  get log(): RequestLogger {
    return this.logger;
  }

  get auth(): AuthChecker {
    return this.authChecker;
  }

  destroy(): void {
    this.rateLimiter.destroy();
  }
}
