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
// — v0.3.2 multi-channel expansion (Lyrie.ai by OTT Cybersecurity LLC) —
import { SlackBot } from "./slack/bot";
import { MatrixBot } from "./matrix/bot";
import { MattermostBot } from "./mattermost/bot";
import { IrcBot } from "./irc/bot";
import { FeishuBot } from "./feishu/bot";
import { RocketChatBot } from "./rocketchat/bot";
import { WebChatBot } from "./webchat/bot";
import { registerHandlers } from "./telegram/handlers";

// Re-export core types so consumers can use @lyrie/gateway as the single import
export type { LyrieConfig, LyrieEngineConfig, Message } from "@lyrie/core";

// ─── Config from Environment ────────────────────────────────────────────────────

function parseDmPolicy(raw: string | undefined): "open" | "pairing" | "closed" | undefined {
  if (!raw) return undefined;
  const v = raw.trim().toLowerCase();
  if (v === "open" || v === "pairing" || v === "closed") return v;
  console.warn(`[gateway] ignoring unknown dmPolicy=${raw} (must be open|pairing|closed)`);
  return undefined;
}

function loadConfig(): GatewayConfig {
  return {
    telegram: {
      enabled: !!process.env.LYRIE_TELEGRAM_TOKEN,
      token: process.env.LYRIE_TELEGRAM_TOKEN || "",
      allowedUsers: process.env.LYRIE_TELEGRAM_USERS?.split(",").filter(Boolean),
      allowedChats: process.env.LYRIE_TELEGRAM_CHATS?.split(",").filter(Boolean),
      rateLimitPerMinute: Number(process.env.LYRIE_TELEGRAM_RATE) || 30,
      dmPolicy: parseDmPolicy(process.env.LYRIE_TELEGRAM_DM_POLICY),
    },
    whatsapp: {
      enabled: !!process.env.LYRIE_WHATSAPP_PHONE_ID,
      phoneNumberId: process.env.LYRIE_WHATSAPP_PHONE_ID,
      accessToken: process.env.LYRIE_WHATSAPP_TOKEN,
      allowedUsers: process.env.LYRIE_WHATSAPP_USERS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_WHATSAPP_DM_POLICY),
    },
    discord: {
      enabled: !!process.env.LYRIE_DISCORD_TOKEN,
      token: process.env.LYRIE_DISCORD_TOKEN,
      applicationId: process.env.LYRIE_DISCORD_APP_ID,
      allowedUsers: process.env.LYRIE_DISCORD_USERS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_DISCORD_DM_POLICY),
    },
    slack: {
      enabled: !!process.env.LYRIE_SLACK_BOT_TOKEN,
      botToken: process.env.LYRIE_SLACK_BOT_TOKEN,
      signingSecret: process.env.LYRIE_SLACK_SIGNING_SECRET,
      appToken: process.env.LYRIE_SLACK_APP_TOKEN,
      allowedTeams: process.env.LYRIE_SLACK_TEAMS?.split(",").filter(Boolean),
      allowedUsers: process.env.LYRIE_SLACK_USERS?.split(",").filter(Boolean),
      allowedChannels: process.env.LYRIE_SLACK_CHANNELS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_SLACK_DM_POLICY),
    },
    matrix: {
      enabled: !!(process.env.LYRIE_MATRIX_HOMESERVER && process.env.LYRIE_MATRIX_TOKEN),
      homeserverUrl: process.env.LYRIE_MATRIX_HOMESERVER,
      userId: process.env.LYRIE_MATRIX_USER,
      accessToken: process.env.LYRIE_MATRIX_TOKEN,
      deviceId: process.env.LYRIE_MATRIX_DEVICE,
      allowedUsers: process.env.LYRIE_MATRIX_USERS?.split(",").filter(Boolean),
      allowedRooms: process.env.LYRIE_MATRIX_ROOMS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_MATRIX_DM_POLICY),
    },
    mattermost: {
      enabled: !!(process.env.LYRIE_MATTERMOST_URL && process.env.LYRIE_MATTERMOST_TOKEN),
      serverUrl: process.env.LYRIE_MATTERMOST_URL,
      token: process.env.LYRIE_MATTERMOST_TOKEN,
      allowedTeams: process.env.LYRIE_MATTERMOST_TEAMS?.split(",").filter(Boolean),
      allowedUsers: process.env.LYRIE_MATTERMOST_USERS?.split(",").filter(Boolean),
      allowedChannels: process.env.LYRIE_MATTERMOST_CHANNELS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_MATTERMOST_DM_POLICY),
    },
    irc: {
      enabled: !!(process.env.LYRIE_IRC_SERVER && process.env.LYRIE_IRC_NICK),
      server: process.env.LYRIE_IRC_SERVER,
      port: process.env.LYRIE_IRC_PORT ? Number(process.env.LYRIE_IRC_PORT) : undefined,
      tls: process.env.LYRIE_IRC_TLS !== "false",
      nick: process.env.LYRIE_IRC_NICK,
      user: process.env.LYRIE_IRC_USER,
      password: process.env.LYRIE_IRC_PASS,
      channels: process.env.LYRIE_IRC_CHANNELS?.split(",").filter(Boolean),
      allowedUsers: process.env.LYRIE_IRC_USERS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_IRC_DM_POLICY),
    },
    feishu: {
      enabled: !!(process.env.LYRIE_FEISHU_APP_ID && process.env.LYRIE_FEISHU_APP_SECRET),
      appId: process.env.LYRIE_FEISHU_APP_ID,
      appSecret: process.env.LYRIE_FEISHU_APP_SECRET,
      encryptKey: process.env.LYRIE_FEISHU_ENCRYPT_KEY,
      verificationToken: process.env.LYRIE_FEISHU_VERIFY_TOKEN,
      isLark: process.env.LYRIE_FEISHU_IS_LARK === "true",
      allowedUsers: process.env.LYRIE_FEISHU_USERS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_FEISHU_DM_POLICY),
    },
    rocketchat: {
      enabled: !!(
        process.env.LYRIE_ROCKETCHAT_URL &&
        process.env.LYRIE_ROCKETCHAT_USER_ID &&
        process.env.LYRIE_ROCKETCHAT_TOKEN
      ),
      serverUrl: process.env.LYRIE_ROCKETCHAT_URL,
      userId: process.env.LYRIE_ROCKETCHAT_USER_ID,
      authToken: process.env.LYRIE_ROCKETCHAT_TOKEN,
      allowedUsers: process.env.LYRIE_ROCKETCHAT_USERS?.split(",").filter(Boolean),
      allowedRooms: process.env.LYRIE_ROCKETCHAT_ROOMS?.split(",").filter(Boolean),
      dmPolicy: parseDmPolicy(process.env.LYRIE_ROCKETCHAT_DM_POLICY),
    },
    webchat: {
      enabled: process.env.LYRIE_WEBCHAT_ENABLED === "true",
      host: process.env.LYRIE_WEBCHAT_HOST,
      port: process.env.LYRIE_WEBCHAT_PORT ? Number(process.env.LYRIE_WEBCHAT_PORT) : undefined,
      allowedOrigins: process.env.LYRIE_WEBCHAT_ORIGINS?.split(",").filter(Boolean),
      authToken: process.env.LYRIE_WEBCHAT_TOKEN,
      dmPolicy: parseDmPolicy(process.env.LYRIE_WEBCHAT_DM_POLICY),
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
  private bots: Array<
    | TelegramBot
    | WhatsAppBot
    | DiscordBot
    | SlackBot
    | MatrixBot
    | MattermostBot
    | IrcBot
    | FeishuBot
    | RocketChatBot
    | WebChatBot
  > = [];
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
        if (this.config.telegram.dmPolicy) {
          this.router.configureChannelPolicy("telegram", {
            dmPolicy: this.config.telegram.dmPolicy,
            allowedUsers: this.config.telegram.allowedUsers,
            allowedChats: this.config.telegram.allowedChats,
          });
        }
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
        if (this.config.whatsapp.dmPolicy) {
          this.router.configureChannelPolicy("whatsapp", {
            dmPolicy: this.config.whatsapp.dmPolicy,
            allowedUsers: this.config.whatsapp.allowedUsers,
          });
        }
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
        if (this.config.discord.dmPolicy) {
          this.router.configureChannelPolicy("discord", {
            dmPolicy: this.config.discord.dmPolicy,
            allowedUsers: this.config.discord.allowedUsers,
          });
        }
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

    // — v0.3.2 multi-channel expansion —
    const tryStart = async <T extends { onMessage: (h: ReturnType<typeof this.router.handler>) => void; start: () => Promise<void>; type: never extends never ? string : never }>(
      label: string,
      cfg: { dmPolicy?: "open" | "pairing" | "closed"; allowedUsers?: string[]; allowedChats?: string[] } | undefined,
      enabled: boolean | undefined,
      build: () => T,
      channelType: Parameters<typeof this.router.configureChannelPolicy>[0],
    ) => {
      if (!enabled) return;
      try {
        if (cfg?.dmPolicy) {
          this.router.configureChannelPolicy(channelType, {
            dmPolicy: cfg.dmPolicy,
            allowedUsers: cfg.allowedUsers,
            allowedChats: cfg.allowedChats,
          });
        }
        const bot = build();
        bot.onMessage(this.router.handler());
        await bot.start();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        this.router.registerChannel(bot as any);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        this.bots.push(bot as any);
        channelCount++;
      } catch (err) {
        console.error(`  ✗ Failed to start ${label}:`, err);
      }
    };

    await tryStart("Slack", this.config.slack, this.config.slack?.enabled, () => new SlackBot(this.config.slack!), "slack");
    await tryStart("Matrix", { dmPolicy: this.config.matrix?.dmPolicy, allowedUsers: this.config.matrix?.allowedUsers, allowedChats: this.config.matrix?.allowedRooms }, this.config.matrix?.enabled, () => new MatrixBot(this.config.matrix!), "matrix");
    await tryStart("Mattermost", { dmPolicy: this.config.mattermost?.dmPolicy, allowedUsers: this.config.mattermost?.allowedUsers, allowedChats: this.config.mattermost?.allowedChannels }, this.config.mattermost?.enabled, () => new MattermostBot(this.config.mattermost!), "mattermost");
    await tryStart("IRC", { dmPolicy: this.config.irc?.dmPolicy, allowedUsers: this.config.irc?.allowedUsers, allowedChats: this.config.irc?.channels }, this.config.irc?.enabled, () => new IrcBot(this.config.irc!), "irc");
    await tryStart("Feishu/Lark", { dmPolicy: this.config.feishu?.dmPolicy, allowedUsers: this.config.feishu?.allowedUsers }, this.config.feishu?.enabled, () => new FeishuBot(this.config.feishu!), "feishu");
    await tryStart("Rocket.Chat", { dmPolicy: this.config.rocketchat?.dmPolicy, allowedUsers: this.config.rocketchat?.allowedUsers, allowedChats: this.config.rocketchat?.allowedRooms }, this.config.rocketchat?.enabled, () => new RocketChatBot(this.config.rocketchat!), "rocketchat");
    await tryStart("WebChat", { dmPolicy: this.config.webchat?.dmPolicy }, this.config.webchat?.enabled, () => new WebChatBot(this.config.webchat!), "webchat");

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
// — v0.3.2 multi-channel expansion (Lyrie.ai by OTT Cybersecurity LLC) —
export { SlackBot } from "./slack/bot";
export { MatrixBot } from "./matrix/bot";
export { MattermostBot } from "./mattermost/bot";
export { IrcBot } from "./irc/bot";
export { FeishuBot } from "./feishu/bot";
export { RocketChatBot } from "./rocketchat/bot";
export { WebChatBot } from "./webchat/bot";
export { registerHandlers } from "./telegram/handlers";
export type * from "./common/types";
