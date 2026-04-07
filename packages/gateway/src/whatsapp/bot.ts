/**
 * WhatsApp Bot — Integration skeleton for WhatsApp Business API / Baileys.
 *
 * Ready for implementation with either:
 * - WhatsApp Business Cloud API (Meta)
 * - Baileys (unofficial, Web API)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  ChannelBot,
  UnifiedMessage,
  UnifiedResponse,
  MessageHandler,
  WhatsAppConfig,
} from "../common/types";

export class WhatsAppBot implements ChannelBot {
  readonly type = "whatsapp" as const;

  private config: WhatsAppConfig;
  private handler: MessageHandler | null = null;
  private connected = false;

  constructor(config: WhatsAppConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  async start(): Promise<void> {
    if (!this.config.phoneNumberId || !this.config.accessToken) {
      console.log("  ⚠️ WhatsApp: Missing phoneNumberId or accessToken — skipping");
      return;
    }

    // TODO: Implementation options:
    //
    // Option A: WhatsApp Business Cloud API
    // - Set up webhook endpoint to receive messages
    // - POST to graph.facebook.com/v18.0/{phoneNumberId}/messages to send
    // - Requires Meta Business verification
    //
    // Option B: Baileys (unofficial)
    // - Connect via WebSocket to WhatsApp Web
    // - QR code authentication
    // - Full feature set but unofficial
    //
    // Webhook server for receiving messages:
    // const server = Bun.serve({
    //   port: 3001,
    //   fetch(req) {
    //     if (req.method === "GET") return verifyWebhook(req);
    //     if (req.method === "POST") return handleIncoming(req);
    //     return new Response("Method not allowed", { status: 405 });
    //   },
    // });

    this.connected = true;
    console.log("  ✓ WhatsApp channel configured (skeleton)");
  }

  async stop(): Promise<void> {
    this.connected = false;
    console.log("  ✓ WhatsApp bot stopped");
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;

    // WhatsApp Business API send:
    // const url = `https://graph.facebook.com/v18.0/${this.config.phoneNumberId}/messages`;
    // const body = {
    //   messaging_product: "whatsapp",
    //   to: chatId,
    //   type: "text",
    //   text: { body: response.text },
    // };
    //
    // For interactive messages (buttons):
    // type: "interactive",
    // interactive: {
    //   type: "button",
    //   body: { text: response.text },
    //   action: {
    //     buttons: response.buttons?.flat().slice(0, 3).map((btn, i) => ({
    //       type: "reply",
    //       reply: { id: btn.callbackData, title: btn.text.substring(0, 20) },
    //     })),
    //   },
    // }

    console.log(`[WhatsApp] Would send to ${chatId}: ${response.text.substring(0, 50)}...`);
    return null;
  }

  async edit(chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    // WhatsApp doesn't support message editing
    // Send a new message instead
    await this.send(chatId, response);
    return true;
  }

  isConnected(): boolean {
    return this.connected;
  }
}
