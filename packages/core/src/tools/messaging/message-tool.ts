/**
 * Lyrie message tool — proactive channel sends
 * Supports: Telegram, Discord, Slack
 *
 * Lyrie.ai by OTT Cybersecurity LLC — MIT License
 */

export interface SendOptions {
  channel: "telegram" | "discord" | "slack";
  target: string;        // chat_id for telegram, webhook URL or channel for others
  message: string;
  parseMode?: "markdown" | "html";
  silent?: boolean;
  replyTo?: string;
  media?: string;        // URL or file path
}

export interface SendResult {
  success: boolean;
  messageId?: string | number;
  error?: string;
}

export class MessageTool {
  private telegramToken: string;

  constructor(telegramToken?: string) {
    this.telegramToken = telegramToken ?? process.env.LYRIE_TELEGRAM_TOKEN ?? process.env.TELEGRAM_BOT_TOKEN ?? "";
  }

  async send(options: SendOptions): Promise<SendResult> {
    switch (options.channel) {
      case "telegram": return this.sendTelegram(options);
      case "discord": return this.sendDiscord(options);
      case "slack": return this.sendSlack(options);
      default: throw new Error(`Unknown channel: ${options.channel}`);
    }
  }

  private async sendTelegram(options: SendOptions): Promise<SendResult> {
    if (!this.telegramToken) throw new Error("LYRIE_TELEGRAM_TOKEN not set");

    const body: Record<string, unknown> = {
      chat_id: options.target,
      text: options.message,
      parse_mode: options.parseMode === "markdown" ? "MarkdownV2" : options.parseMode === "html" ? "HTML" : undefined,
      disable_notification: options.silent ?? false,
    };
    if (options.replyTo) body.reply_to_message_id = options.replyTo;

    const endpoint = options.media
      ? `https://api.telegram.org/bot${this.telegramToken}/sendPhoto`
      : `https://api.telegram.org/bot${this.telegramToken}/sendMessage`;

    if (options.media) {
      body.photo = options.media;
      body.caption = options.message;
      delete body.text;
    }

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await res.json() as any;
    if (!data.ok) throw new Error(`Telegram API error: ${data.description}`);
    return { success: true, messageId: data.result?.message_id };
  }

  private async sendDiscord(options: SendOptions): Promise<SendResult> {
    // target is a webhook URL
    const res = await fetch(options.target, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: options.message }),
    });
    if (!res.ok) throw new Error(`Discord webhook error: ${res.status}`);
    return { success: true };
  }

  private async sendSlack(options: SendOptions): Promise<SendResult> {
    // target is a webhook URL
    const res = await fetch(options.target, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: options.message }),
    });
    if (!res.ok) throw new Error(`Slack webhook error: ${res.status}`);
    return { success: true };
  }
}

export const messageTool = {
  name: "message",
  description: "Send proactive messages to channels. Use for alerts, notifications, and delivering results. Supports Telegram, Discord, Slack.",
  parameters: {
    type: "object",
    properties: {
      action: { type: "string", enum: ["send", "react", "delete"], description: "Action to perform" },
      channel: { type: "string", enum: ["telegram", "discord", "slack"], description: "Channel to send to" },
      target: { type: "string", description: "Chat ID (Telegram) or webhook URL (Discord/Slack)" },
      message: { type: "string", description: "Message text" },
      parseMode: { type: "string", enum: ["markdown", "html"], description: "Text parse mode" },
      silent: { type: "boolean", description: "Send without notification sound" },
      media: { type: "string", description: "Image URL or file path to attach" },
    },
    required: ["action", "channel", "target"],
  },
  async execute(params: { action: string; channel: "telegram" | "discord" | "slack"; target: string; message?: string; parseMode?: "markdown" | "html"; silent?: boolean; media?: string }) {
    if (params.action !== "send") throw new Error(`Action '${params.action}' not yet implemented`);
    if (!params.message) throw new Error("message is required for send action");
    const tool = new MessageTool();
    return await tool.send({ ...params, message: params.message });
  },
};
