/**
 * Message Router — Routes unified messages from any channel to the Lyrie Engine.
 *
 * Handles:
 * - Converting unified messages to engine format
 * - Converting engine responses back to unified responses
 * - Command dispatch
 * - Conversation context tracking
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  ChannelType,
  UnifiedMessage,
  UnifiedResponse,
  ChannelBot,
  MessageHandler,
} from "./types";
import {
  DmPairingManager,
  evaluateDmPolicy,
  type DmPolicy,
  type PolicyContext,
} from "../security/dm-pairing";

// ─── Engine Interface (matches LyrieEngine.process signature) ───────────────────

export interface EngineMessage {
  role: "user" | "assistant" | "system";
  content: string;
  source?: string;
  timestamp?: number;
}

export interface EngineInterface {
  process(message: EngineMessage): Promise<EngineMessage>;
  readonly running: boolean;
}

// ─── Command Handler ────────────────────────────────────────────────────────────

export type CommandHandler = (
  message: UnifiedMessage,
  args: string[],
) => Promise<UnifiedResponse>;

// ─── Router ─────────────────────────────────────────────────────────────────────

export interface ChannelPolicyConfig {
  dmPolicy?: DmPolicy;
  allowedUsers?: string[];
  allowedChats?: string[];
}

export class MessageRouter {
  private engine: EngineInterface;
  private channels: Map<string, ChannelBot> = new Map();
  private commandHandlers: Map<string, CommandHandler> = new Map();
  private messageCount = 0;
  private channelPolicies: Map<ChannelType, ChannelPolicyConfig> = new Map();
  private pairing: DmPairingManager | null = null;

  constructor(engine: EngineInterface) {
    this.engine = engine;
  }

  /**
   * Configure DM policy for a channel. Call once per channel before start().
   * Default behavior (no call) is back-compat: "open" with no extra gating.
   */
  configureChannelPolicy(channel: ChannelType, cfg: ChannelPolicyConfig): void {
    this.channelPolicies.set(channel, cfg);
    if (cfg.dmPolicy === "pairing" && !this.pairing) {
      this.pairing = new DmPairingManager();
    }
  }

  /** Expose the pairing manager so the CLI / admin tools can approve codes. */
  getPairingManager(): DmPairingManager | null {
    return this.pairing;
  }

  // ── Channel Management ──────────────────────────────────────────────────────

  registerChannel(bot: ChannelBot): void {
    this.channels.set(bot.type, bot);
    console.log(`  ✓ Registered channel: ${bot.type}`);
  }

  getChannel(type: string): ChannelBot | undefined {
    return this.channels.get(type);
  }

  // ── Command Registration ────────────────────────────────────────────────────

  registerCommand(name: string, handler: CommandHandler): void {
    this.commandHandlers.set(name.toLowerCase(), handler);
  }

  // ── Main Message Handler ────────────────────────────────────────────────────

  /**
   * Returns a MessageHandler function that channels can call for each inbound message.
   */
  handler(): MessageHandler {
    return async (message: UnifiedMessage): Promise<UnifiedResponse | null> => {
      this.messageCount++;

      try {
        // 0. DM policy gate (additive — defaults to "open" / no-op)
        const policyCfg = this.channelPolicies.get(message.channel);
        if (policyCfg?.dmPolicy && policyCfg.dmPolicy !== "open") {
          const policyCtx: PolicyContext = {
            policy: policyCfg.dmPolicy,
            allowedUsers: policyCfg.allowedUsers,
            allowedChats: policyCfg.allowedChats,
          };
          const manager = this.pairing ?? (this.pairing = new DmPairingManager());
          const gated = evaluateDmPolicy(message, policyCtx, manager);
          if (gated) return gated;
        }

        // 1. If it's a callback (inline button press), route to command system
        if (message.callbackData) {
          return await this.handleCallback(message);
        }

        // 2. If it's a command, dispatch to registered handler
        if (message.command) {
          const handler = this.commandHandlers.get(message.command.name.toLowerCase());
          if (handler) {
            return await handler(message, message.command.argv);
          }
          // Unknown command
          return {
            text: `❓ Unknown command: /${message.command.name}\nType /help for available commands.`,
            parseMode: "markdown",
          };
        }

        // 3. Otherwise, pass to the Lyrie engine for AI processing
        return await this.routeToEngine(message);
      } catch (err) {
        console.error(`[Router] Error processing message from ${message.channel}:`, err);
        return {
          text: "⚠️ Something went wrong processing your message. Please try again.",
        };
      }
    };
  }

  // ── Engine Routing ──────────────────────────────────────────────────────────

  private async routeToEngine(message: UnifiedMessage): Promise<UnifiedResponse> {
    const engineMsg: EngineMessage = {
      role: "user",
      content: message.text,
      source: `${message.channel}:${message.chatId}`,
      timestamp: Date.now(),
    };

    const response = await this.engine.process(engineMsg);

    // Engine returns { message: { content }, toolCallsMade, turns, model, durationMs }
    const content = response?.message?.content || response?.content || "";

    return {
      text: content || "🤔 I didn't generate a response. Try again?",
      parseMode: "markdown",
    };
  }

  // ── Callback Handling ───────────────────────────────────────────────────────

  private async handleCallback(message: UnifiedMessage): Promise<UnifiedResponse> {
    const data = message.callbackData!;

    // Callbacks are formatted as "command:arg1:arg2"
    // Handle pentest button callbacks
    const pentestCallbacks: Record<string, string> = {
      "pentest_scan": "Enter a target to quick scan:\n\n`/scan example.com`",
      "pentest_full": "Enter a target for full pentest:\n\n`/pentest example.com`\n\nRuns all modules: recon + vulns + web app + API (~10 min)",
      "pentest_recon": "Enter a target for recon:\n\n`/recon example.com`\n\nDNS, subdomains, ports, WHOIS, SSL certs",
      "pentest_vuln": "Enter a target for vuln scan:\n\n`/vulnscan example.com`\n\nSQLi, XSS, SSRF, RCE, CORS, CVE lookup",
      "pentest_api": "Enter a target for API scan:\n\n`/apiscan example.com`\n\nEndpoints, GraphQL, JWT bypass, rate limits",
      "pentest_report": "No recent scan report available. Run a scan first with `/scan <target>`",
    };

    if (pentestCallbacks[data]) {
      return { text: pentestCallbacks[data], parseMode: "markdown" };
    }

    const [cmd, ...args] = data.split(":");
    const handler = this.commandHandlers.get(cmd.toLowerCase());

    if (handler) {
      message.command = {
        name: cmd,
        args: args.join(":"),
        argv: args,
      };
      return await handler(message, args);
    }

    return {
      text: `⚠️ Unknown action: ${data}`,
    };
  }

  // ── Stats ─────────────────────────────────────────────────────────────────

  stats(): { messagesProcessed: number; activeChannels: string[] } {
    return {
      messagesProcessed: this.messageCount,
      activeChannels: Array.from(this.channels.entries())
        .filter(([_, bot]) => bot.isConnected())
        .map(([type]) => type),
    };
  }
}
