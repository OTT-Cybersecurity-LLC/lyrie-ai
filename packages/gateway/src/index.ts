/**
 * Lyrie Gateway — Multi-channel messaging gateway entry point.
 *
 * Starts all enabled channels and routes messages to the Lyrie Engine.
 *
 * Usage:
 *   bun run packages/gateway/src/index.ts
 *
 * Environment variables:
 *   LYRIE_TELEGRAM_TOKEN     — Telegram bot token (required for Telegram)
 *   LYRIE_TELEGRAM_USERS     — Comma-separated allowed user IDs
 *   LYRIE_TELEGRAM_CHATS     — Comma-separated allowed chat IDs
 *   LYRIE_TELEGRAM_RATE      — Rate limit per user per minute (default: 30)
 *   LYRIE_WHATSAPP_PHONE_ID  — WhatsApp Business phone number ID
 *   LYRIE_WHATSAPP_TOKEN     — WhatsApp access token
 *   LYRIE_DISCORD_TOKEN      — Discord bot token
 *   LYRIE_DISCORD_APP_ID     — Discord application ID
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { GatewayConfig } from "./common/types";
import { MessageRouter, type EngineInterface } from "./common/router";
import { TelegramBot } from "./telegram/bot";
import { WhatsAppBot } from "./whatsapp/bot";
import { DiscordBot } from "./discord/bot";
import { registerHandlers } from "./telegram/handlers";

// ─── Config from Environment ────────────────────────────────────────────────────

function loadConfig(): GatewayConfig {
  return {
    telegram: {
      enabled: !!process.env.LYRIE_TELEGRAM_TOKEN,
      token: process.env.LYRIE_TELEGRAM_TOKEN || "",
      allowedUsers: process.env.LYRIE_TELEGRAM_USERS?.split(",").filter(Boolean),
      allowedChats: process.env.LYRIE_TELEGRAM_CHATS?.split(",").filter(Boolean),
      rateLimitPerMinute: Number(process.env.LYRIE_TELEGRAM_RATE) || 30,
    },
    whatsapp: {
      enabled: !!process.env.LYRIE_WHATSAPP_PHONE_ID,
      phoneNumberId: process.env.LYRIE_WHATSAPP_PHONE_ID,
      accessToken: process.env.LYRIE_WHATSAPP_TOKEN,
    },
    discord: {
      enabled: !!process.env.LYRIE_DISCORD_TOKEN,
      token: process.env.LYRIE_DISCORD_TOKEN,
      applicationId: process.env.LYRIE_DISCORD_APP_ID,
    },
  };
}

// ─── Stub Engine (for standalone gateway testing) ───────────────────────────────

class StubEngine implements EngineInterface {
  running = true;

  async process(message: { role: string; content: string; source?: string }) {
    return {
      role: "assistant" as const,
      content: `🛡️ Lyrie received: "${message.content.substring(0, 100)}"\n\n_Engine not connected — running in gateway-only mode._`,
      timestamp: Date.now(),
    };
  }
}

// ─── Gateway Startup ────────────────────────────────────────────────────────────

export class LyrieGateway {
  private router: MessageRouter;
  private bots: Array<TelegramBot | WhatsAppBot | DiscordBot> = [];
  private config: GatewayConfig;

  constructor(engine?: EngineInterface, config?: GatewayConfig) {
    this.config = config || loadConfig();
    this.router = new MessageRouter(engine || new StubEngine());
  }

  async start(): Promise<void> {
    console.log("\n🛡️  Lyrie Gateway v0.1.0");
    console.log("   OTT Cybersecurity LLC — https://lyrie.ai\n");

    // Register command handlers
    registerHandlers(this.router);

    // Start enabled channels
    let channelCount = 0;

    // Telegram
    if (this.config.telegram?.enabled) {
      try {
        const tgBot = new TelegramBot(this.config.telegram);
        tgBot.onMessage(this.router.handler());
        await tgBot.start();
        this.router.registerChannel(tgBot);
        this.bots.push(tgBot);
        channelCount++;
      } catch (err) {
        console.error("  ✗ Failed to start Telegram:", err);
      }
    }

    // WhatsApp
    if (this.config.whatsapp?.enabled) {
      try {
        const waBot = new WhatsAppBot(this.config.whatsapp);
        waBot.onMessage(this.router.handler());
        await waBot.start();
        this.router.registerChannel(waBot);
        this.bots.push(waBot);
        channelCount++;
      } catch (err) {
        console.error("  ✗ Failed to start WhatsApp:", err);
      }
    }

    // Discord
    if (this.config.discord?.enabled) {
      try {
        const dcBot = new DiscordBot(this.config.discord);
        dcBot.onMessage(this.router.handler());
        await dcBot.start();
        this.router.registerChannel(dcBot);
        this.bots.push(dcBot);
        channelCount++;
      } catch (err) {
        console.error("  ✗ Failed to start Discord:", err);
      }
    }

    if (channelCount === 0) {
      console.log("  ⚠️ No channels enabled. Set LYRIE_TELEGRAM_TOKEN or other env vars.");
      console.log("  ℹ️  See: packages/gateway/README.md\n");
    } else {
      console.log(`\n  ✅ Gateway running with ${channelCount} channel(s)\n`);
    }

    // Graceful shutdown
    const shutdown = async () => {
      console.log("\n🛑 Shutting down gateway...");
      await this.stop();
      process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  }

  async stop(): Promise<void> {
    for (const bot of this.bots) {
      await bot.stop();
    }
    this.bots = [];
  }

  get stats() {
    return this.router.stats();
  }
}

// ─── Direct Execution ───────────────────────────────────────────────────────────

// If run directly (not imported), start the gateway
const isDirectRun =
  typeof Bun !== "undefined"
    ? Bun.main === import.meta.path
    : process.argv[1]?.endsWith("gateway/src/index.ts");

if (isDirectRun) {
  const gateway = new LyrieGateway();
  gateway.start().catch((err) => {
    console.error("Fatal error starting gateway:", err);
    process.exit(1);
  });
}

// ─── Exports ────────────────────────────────────────────────────────────────────

export { MessageRouter } from "./common/router";
export { TelegramBot } from "./telegram/bot";
export { WhatsAppBot } from "./whatsapp/bot";
export { DiscordBot } from "./discord/bot";
export { registerHandlers } from "./telegram/handlers";
export type * from "./common/types";
