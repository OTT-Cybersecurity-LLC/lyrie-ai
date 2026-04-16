/**
 * Telegram Bot — Raw HTTP implementation against api.telegram.org.
 *
 * Zero external dependencies. Uses native fetch (Bun/Node 18+).
 *
 * Features:
 * - Long polling with configurable interval
 * - Inline keyboard support
 * - Media sending (photo, document, audio, video)
 * - Message editing (for streaming/progressive updates)
 * - Rate limiting & auth middleware
 * - Automatic retry with exponential backoff
 * - Graceful shutdown
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  TgUpdate,
  TgApiResponse,
  TgMessage,
  TgSendMessageParams,
  TgEditMessageParams,
  TgSendPhotoParams,
  TgSendDocumentParams,
  TgAnswerCallbackQueryParams,
  TgInlineKeyboardMarkup,
  TgInlineKeyboardButton,
  TgFile,
} from "./types";

import type {
  ChannelBot,
  UnifiedMessage,
  UnifiedResponse,
  MessageHandler,
  TelegramConfig,
  ParsedCommand,
  MediaAttachment,
  InlineButton,
} from "../common/types";

import { MiddlewarePipeline } from "./middleware";
import { MediaProcessor, buildMediaEnrichedText } from "./media-processor";

// ─── Constants ──────────────────────────────────────────────────────────────────

const TG_API_BASE = "https://api.telegram.org/bot";
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY_MS = 1000;
const MAX_MESSAGE_LENGTH = 4096;
const POLLING_TIMEOUT_SECS = 30;

// ─── Telegram Bot ───────────────────────────────────────────────────────────────

export class TelegramBot implements ChannelBot {
  readonly type = "telegram" as const;

  private token: string;
  private apiBase: string;
  private config: TelegramConfig;
  private middleware: MiddlewarePipeline;
  private handler: MessageHandler | null = null;

  private offset = 0;
  private connected = false;
  private polling = false;
  private pollAbort: AbortController | null = null;
  private shutdownRequested = false;
  private mediaProcessor: MediaProcessor;

  constructor(config: TelegramConfig) {
    this.config = config;
    this.token = config.token;
    this.apiBase = `${TG_API_BASE}${this.token}`;
    this.middleware = new MiddlewarePipeline(config);
    this.mediaProcessor = new MediaProcessor({
      telegramToken: this.token,
      openaiApiKey: process.env.OPENAI_API_KEY,
      anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    });
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  async start(): Promise<void> {
    // Verify token by calling getMe
    const me = await this.callApi<any>("getMe");
    if (!me) {
      throw new Error("Failed to connect to Telegram — invalid token or network error");
    }

    console.log(`  ✓ Telegram bot connected: @${me.username} (${me.first_name})`);
    this.connected = true;

    // Start long polling
    this.startPolling();
  }

  async stop(): Promise<void> {
    this.shutdownRequested = true;
    this.polling = false;

    if (this.pollAbort) {
      this.pollAbort.abort();
      this.pollAbort = null;
    }

    this.middleware.destroy();
    this.connected = false;
    console.log("  ✓ Telegram bot stopped");
  }

  isConnected(): boolean {
    return this.connected;
  }

  // ── Send Message ────────────────────────────────────────────────────────────

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    // If response has media, send media message
    if (response.media) {
      return this.sendMedia(chatId, response);
    }

    // Split long messages
    const chunks = this.splitMessage(response.text);
    let lastMessageId: string | null = null;

    for (let i = 0; i < chunks.length; i++) {
      const isLast = i === chunks.length - 1;
      const params: TgSendMessageParams = {
        chat_id: chatId,
        text: chunks[i],
        parse_mode: this.mapParseMode(response.parseMode),
        disable_web_page_preview: response.disableLinkPreview,
        disable_notification: response.silent,
      };

      // Only attach buttons to the last chunk
      if (isLast && response.buttons) {
        params.reply_markup = this.buildKeyboard(response.buttons);
      }

      if (response.replyToMessageId && i === 0) {
        params.reply_to_message_id = Number(response.replyToMessageId);
      }

      const result = await this.callApi<TgMessage>("sendMessage", params);
      if (result) {
        lastMessageId = String(result.message_id);
      }
    }

    return lastMessageId;
  }

  // ── Edit Message ────────────────────────────────────────────────────────────

  async edit(chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    const params: TgEditMessageParams = {
      chat_id: chatId,
      message_id: Number(messageId),
      text: response.text.substring(0, MAX_MESSAGE_LENGTH),
      parse_mode: this.mapParseMode(response.parseMode),
      disable_web_page_preview: response.disableLinkPreview,
    };

    if (response.buttons) {
      params.reply_markup = this.buildKeyboard(response.buttons);
    }

    const result = await this.callApi<TgMessage>("editMessageText", params);
    return result !== null;
  }

  // ── Send Media ──────────────────────────────────────────────────────────────

  private async sendMedia(chatId: string, response: UnifiedResponse): Promise<string | null> {
    const media = response.media!;
    let method: string;
    let params: Record<string, any> = {
      chat_id: chatId,
      caption: media.caption || response.text,
      parse_mode: this.mapParseMode(response.parseMode),
    };

    if (response.buttons) {
      params.reply_markup = this.buildKeyboard(response.buttons);
    }

    switch (media.type) {
      case "photo":
        method = "sendPhoto";
        params.photo = media.source;
        break;
      case "document":
        method = "sendDocument";
        params.document = media.source;
        break;
      case "audio":
        method = "sendAudio";
        params.audio = media.source;
        break;
      case "video":
        method = "sendVideo";
        params.video = media.source;
        break;
      case "animation":
        method = "sendAnimation";
        params.animation = media.source;
        break;
      default:
        method = "sendDocument";
        params.document = media.source;
    }

    const result = await this.callApi<TgMessage>(method, params);
    return result ? String(result.message_id) : null;
  }

  // ── Answer Callback Query ───────────────────────────────────────────────────

  async answerCallback(callbackQueryId: string, text?: string, showAlert = false): Promise<void> {
    await this.callApi("answerCallbackQuery", {
      callback_query_id: callbackQueryId,
      text,
      show_alert: showAlert,
    });
  }

  // ── Streaming Support ───────────────────────────────────────────────────────

  /**
   * Send an initial message and return an updater function for streaming.
   * Call the updater with partial text to edit the message in-place.
   * Call with `{ done: true }` to finalize.
   */
  async sendStreaming(
    chatId: string,
    initialText: string,
  ): Promise<{
    messageId: string;
    update: (text: string, done?: boolean) => Promise<void>;
  } | null> {
    const msgId = await this.send(chatId, {
      text: initialText + " ⏳",
      parseMode: "markdown",
    });

    if (!msgId) return null;

    let lastUpdate = 0;
    const MIN_UPDATE_INTERVAL_MS = 1000; // Don't edit faster than 1/sec to avoid rate limits

    return {
      messageId: msgId,
      update: async (text: string, done = false) => {
        const now = Date.now();
        if (!done && now - lastUpdate < MIN_UPDATE_INTERVAL_MS) return;
        lastUpdate = now;

        const displayText = done ? text : text + " ⏳";
        await this.edit(chatId, msgId, {
          text: displayText.substring(0, MAX_MESSAGE_LENGTH),
          parseMode: "markdown",
        });
      },
    };
  }

  // ── File Downloads ──────────────────────────────────────────────────────────

  async getFileUrl(fileId: string): Promise<string | null> {
    const file = await this.callApi<TgFile>("getFile", { file_id: fileId });
    if (!file?.file_path) return null;
    return `https://api.telegram.org/file/bot${this.token}/${file.file_path}`;
  }

  // ── Long Polling ────────────────────────────────────────────────────────────

  private startPolling(): void {
    this.polling = true;
    this.pollLoop();
  }

  private async pollLoop(): Promise<void> {
    while (this.polling && !this.shutdownRequested) {
      try {
        this.pollAbort = new AbortController();
        const updates = await this.getUpdates();

        if (updates && updates.length > 0) {
          for (const update of updates) {
            this.offset = update.update_id + 1;
            // Process each update without blocking the poll loop
            this.processUpdate(update).catch((err) => {
              this.middleware.log.error("poll", "Unhandled error in update processing", err);
            });
          }
        }
      } catch (err: any) {
        if (err?.name === "AbortError" || this.shutdownRequested) break;
        this.middleware.log.error("poll", "Polling error, retrying in 5s", err);
        await this.sleep(5000);
      }
    }
  }

  private async getUpdates(): Promise<TgUpdate[] | null> {
    return this.callApi<TgUpdate[]>("getUpdates", {
      offset: this.offset,
      timeout: POLLING_TIMEOUT_SECS,
      allowed_updates: ["message", "edited_message", "callback_query"],
    }, this.pollAbort?.signal);
  }

  // ── Update Processing ───────────────────────────────────────────────────────

  private async processUpdate(update: TgUpdate): Promise<void> {
    // Run middleware
    const middlewareResult = this.middleware.process(update);
    if (!middlewareResult.allowed) {
      const chatId = update.message?.chat.id || update.callback_query?.message?.chat.id;
      if (chatId) {
        if (middlewareResult.reason === "unauthorized") {
          await this.send(String(chatId), {
            text: "🛡️ *Lyrie Agent*\n\nThis is a private AI agent. You are not authorized to use this bot.\n\nTo get access, contact the owner.\n\n_Powered by Lyrie.ai — OTT Cybersecurity LLC_",
            parseMode: "markdown",
          });
        } else if (middlewareResult.reason?.startsWith("rate_limited")) {
          await this.send(String(chatId), {
            text: "⏳ You're sending messages too fast. Please wait a moment.",
          });
        }
      }
      return;
    }

    // Convert to unified message and dispatch
    if (!this.handler) return;

    // Handle callback queries
    if (update.callback_query) {
      const cb = update.callback_query;
      const msg = cb.message;
      if (!msg) return;

      const unified = this.toUnified(msg, cb.data);
      unified.senderId = String(cb.from.id);
      unified.senderName = [cb.from.first_name, cb.from.last_name].filter(Boolean).join(" ");

      // Answer the callback to remove the "loading" state
      await this.answerCallback(cb.id);

      const response = await this.handler(unified);
      if (response) {
        // Edit the original message instead of sending a new one
        await this.edit(String(msg.chat.id), String(msg.message_id), response);
      }
      return;
    }

    // Handle regular messages
    const tgMsg = update.message;
    if (!tgMsg) return;

    // Show "typing..." indicator while processing
    await this.sendChatAction(String(tgMsg.chat.id), "typing");

    const unified = this.toUnified(tgMsg);

    // ── Media Processing ────────────────────────────────────────────────────
    // If the message contains media, download and process it before
    // passing to the engine. Voice → transcription, photos → description, etc.
    if (unified.media && unified.media.length > 0) {
      try {
        const mediaResults = await this.mediaProcessor.processAttachments(
          unified.media,
          tgMsg.caption,
        );
        // Enrich the message text with media processing results
        unified.text = buildMediaEnrichedText(mediaResults, unified.text);
      } catch (err: any) {
        this.middleware.log.error(
          "media",
          `Media processing failed: ${err.message}`,
          err,
        );
        // Don't block the message — send with a note about the failure
        const fallbackNote = `[Media received but processing failed: ${err.message}]`;
        unified.text = unified.text
          ? `${fallbackNote}\n\n${unified.text}`
          : fallbackNote;
      }
    }

    const response = await this.handler(unified);
    if (response) {
      await this.send(String(tgMsg.chat.id), response);
    }
  }

  // ── Conversion ──────────────────────────────────────────────────────────────

  private toUnified(msg: TgMessage, callbackData?: string): UnifiedMessage {
    const text = msg.text || msg.caption || "";
    const unified: UnifiedMessage = {
      id: String(msg.message_id),
      channel: "telegram",
      senderId: String(msg.from?.id || 0),
      senderName: [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(" ") || "Unknown",
      chatId: String(msg.chat.id),
      text,
      timestamp: new Date(msg.date * 1000).toISOString(),
      raw: msg,
    };

    // Parse command
    if (text.startsWith("/")) {
      const parts = text.split(/\s+/);
      const cmdPart = parts[0].replace(/^\//, "").replace(/@.*$/, ""); // Strip @botname
      unified.command = {
        name: cmdPart,
        args: parts.slice(1).join(" "),
        argv: parts.slice(1),
      };
    }

    // Parse media
    const media: MediaAttachment[] = [];
    if (msg.photo && msg.photo.length > 0) {
      const largest = msg.photo[msg.photo.length - 1];
      media.push({
        type: "photo",
        fileId: largest.file_id,
        size: largest.file_size,
      });
    }
    if (msg.document) {
      media.push({
        type: "document",
        fileId: msg.document.file_id,
        filename: msg.document.file_name,
        mimeType: msg.document.mime_type,
        size: msg.document.file_size,
      });
    }
    if (msg.audio) {
      media.push({
        type: "audio",
        fileId: msg.audio.file_id,
        mimeType: msg.audio.mime_type,
        size: msg.audio.file_size,
      });
    }
    if (msg.video) {
      media.push({
        type: "video",
        fileId: msg.video.file_id,
        mimeType: msg.video.mime_type,
        size: msg.video.file_size,
      });
    }
    if (msg.voice) {
      media.push({
        type: "voice",
        fileId: msg.voice.file_id,
        mimeType: msg.voice.mime_type,
        size: msg.voice.file_size,
      });
    }
    if (msg.sticker) {
      media.push({
        type: "sticker",
        fileId: msg.sticker.file_id,
      });
    }
    if (msg.animation) {
      media.push({
        type: "animation",
        fileId: msg.animation.file_id,
        mimeType: msg.animation.mime_type,
        size: msg.animation.file_size,
      });
    }
    if (media.length > 0) unified.media = media;

    // Callback data
    if (callbackData) unified.callbackData = callbackData;

    // Reply
    if (msg.reply_to_message) {
      unified.replyToMessageId = String(msg.reply_to_message.message_id);
    }

    return unified;
  }

  // ── API Layer ───────────────────────────────────────────────────────────────

  private async sendChatAction(chatId: string, action: string = "typing"): Promise<void> {
    await this.callApi("sendChatAction", { chat_id: chatId, action });
  }

  private async callApi<T>(
    method: string,
    params?: Record<string, any>,
    signal?: AbortSignal,
  ): Promise<T | null> {
    const url = `${this.apiBase}/${method}`;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: params ? JSON.stringify(params) : undefined,
          signal,
        });

        const data = (await resp.json()) as TgApiResponse<T>;

        if (data.ok) {
          return data.result ?? null;
        }

        // Handle specific error codes
        if (data.error_code === 429) {
          // Rate limited by Telegram
          const retryAfter = data.parameters?.retry_after || 5;
          this.middleware.log.warn("api", `Rate limited by Telegram, waiting ${retryAfter}s`);
          await this.sleep(retryAfter * 1000);
          continue;
        }

        if (data.error_code === 409) {
          // Conflict: another bot instance is polling
          this.middleware.log.error("api", "Conflict: another instance is polling. Stopping.");
          this.stop();
          return null;
        }

        // Message-specific errors that shouldn't be retried
        if (
          data.error_code === 400 &&
          data.description?.includes("message is not modified")
        ) {
          // Edit called with same content — not an error
          return null;
        }

        if (
          data.error_code === 400 &&
          data.description?.includes("can't parse entities")
        ) {
          // Markdown parse error — retry without parse mode
          if (params?.parse_mode) {
            this.middleware.log.warn("api", "Parse mode error, retrying as plain text");
            const plainParams = { ...params };
            delete plainParams.parse_mode;
            return this.callApi<T>(method, plainParams, signal);
          }
        }

        this.middleware.log.error(
          "api",
          `${method} failed: [${data.error_code}] ${data.description}`,
        );

        // Don't retry 4xx errors (except 429)
        if (data.error_code && data.error_code >= 400 && data.error_code < 500) {
          return null;
        }
      } catch (err: any) {
        if (err?.name === "AbortError") throw err;

        this.middleware.log.error("api", `${method} attempt ${attempt + 1} failed`, err);

        if (attempt < MAX_RETRIES) {
          const delay = BASE_RETRY_DELAY_MS * Math.pow(2, attempt);
          await this.sleep(delay);
        }
      }
    }

    return null;
  }

  // ── Utilities ───────────────────────────────────────────────────────────────

  private mapParseMode(mode?: string): "MarkdownV2" | "HTML" | "Markdown" | undefined {
    switch (mode) {
      case "html":
        return "HTML";
      case "markdown":
        return "Markdown";
      default:
        return undefined;
    }
  }

  private buildKeyboard(buttons: InlineButton[][]): TgInlineKeyboardMarkup {
    return {
      inline_keyboard: buttons.map((row) =>
        row.map((btn): TgInlineKeyboardButton => {
          if (btn.url) {
            return { text: btn.text, url: btn.url };
          }
          return { text: btn.text, callback_data: btn.callbackData || btn.text };
        }),
      ),
    };
  }

  private splitMessage(text: string): string[] {
    if (text.length <= MAX_MESSAGE_LENGTH) return [text];

    const chunks: string[] = [];
    let remaining = text;

    while (remaining.length > 0) {
      if (remaining.length <= MAX_MESSAGE_LENGTH) {
        chunks.push(remaining);
        break;
      }

      // Find a good split point (newline, then space, then hard cut)
      let splitAt = remaining.lastIndexOf("\n", MAX_MESSAGE_LENGTH);
      if (splitAt < MAX_MESSAGE_LENGTH * 0.5) {
        splitAt = remaining.lastIndexOf(" ", MAX_MESSAGE_LENGTH);
      }
      if (splitAt < MAX_MESSAGE_LENGTH * 0.5) {
        splitAt = MAX_MESSAGE_LENGTH;
      }

      chunks.push(remaining.substring(0, splitAt));
      remaining = remaining.substring(splitAt).trimStart();
    }

    return chunks;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
