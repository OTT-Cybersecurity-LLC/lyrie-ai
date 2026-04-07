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
  UnifiedMessage,
  UnifiedResponse,
  ChannelBot,
  MessageHandler,
} from "./types";

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

export class MessageRouter {
  private engine: EngineInterface;
  private channels: Map<string, ChannelBot> = new Map();
  private commandHandlers: Map<string, CommandHandler> = new Map();
  private messageCount = 0;

  constructor(engine: EngineInterface) {
    this.engine = engine;
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

    return {
      text: response.content || "🤔 I didn't generate a response. Try again?",
      parseMode: "markdown",
    };
  }

  // ── Callback Handling ───────────────────────────────────────────────────────

  private async handleCallback(message: UnifiedMessage): Promise<UnifiedResponse> {
    const data = message.callbackData!;

    // Callbacks are formatted as "command:arg1:arg2"
    const [cmd, ...args] = data.split(":");
    const handler = this.commandHandlers.get(cmd.toLowerCase());

    if (handler) {
      // Inject the parsed command info
      message.command = {
        name: cmd,
        args: args.join(":"),
        argv: args,
      };
      return await handler(message, args);
    }

    return {
      text: `⚠️ Unknown action: ${cmd}`,
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
