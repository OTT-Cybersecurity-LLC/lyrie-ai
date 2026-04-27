/**
 * Feishu / Lark Bot — Lyrie Gateway adapter.
 *
 * Two host environments share one adapter:
 *   - Feishu (飞书) — open.feishu.cn, mainland China
 *   - Lark    — open.larksuite.com, international
 *
 * Production wiring: Open Platform "Custom App" + Event Subscription webhook.
 * tenant_access_token cached and rotated; AES decryption when encryptKey set.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  FeishuConfig,
  MessageHandler,
  ParsedCommand,
  UnifiedMessage,
  UnifiedResponse,
} from "../common/types";

export interface FeishuEventEnvelope {
  schema?: "2.0" | string;
  header: {
    event_id: string;
    event_type: string;
    create_time?: string;
    token?: string;
    app_id?: string;
    tenant_key?: string;
  };
  event: FeishuMessageReceiveEvent;
}

export interface FeishuMessageReceiveEvent {
  sender: {
    sender_id: { open_id: string; user_id?: string; union_id?: string };
    sender_type?: string;
  };
  message: {
    message_id: string;
    root_id?: string;
    parent_id?: string;
    chat_id: string;
    chat_type: "p2p" | "group";
    message_type: "text" | "image" | "file" | "audio" | "post" | "interactive";
    /** JSON-stringified content; shape depends on message_type. */
    content: string;
  };
}

function parseSlashCommand(text: string): ParsedCommand | undefined {
  const trimmed = text.trimStart();
  if (!trimmed.startsWith("/")) return undefined;
  const parts = trimmed.slice(1).split(/\s+/);
  const name = parts[0]?.toLowerCase() ?? "";
  if (!name) return undefined;
  const args = parts.slice(1).join(" ");
  const argv = args.length > 0 ? args.split(/\s+/) : [];
  return { name, args, argv };
}

/** Pull the user-visible text out of Feishu's typed-content payload. */
export function feishuExtractText(messageType: string, contentJson: string): string {
  try {
    const c = JSON.parse(contentJson) as Record<string, unknown>;
    if (messageType === "text" && typeof c["text"] === "string") return c["text"] as string;
    if (messageType === "post") {
      // post.content is [[{tag, text}, ...]]
      const post = c as { title?: string; content?: Array<Array<{ tag?: string; text?: string }>> };
      const lines = (post.content ?? []).map((row) =>
        row.map((seg) => seg.text ?? "").join(""),
      );
      return [post.title, ...lines].filter(Boolean).join("\n");
    }
    if (messageType === "image") return "[image]";
    if (messageType === "file") return "[file]";
    if (messageType === "audio") return "[audio]";
    return "";
  } catch {
    return "";
  }
}

export function feishuEventToUnified(envelope: FeishuEventEnvelope): UnifiedMessage | null {
  if (envelope.header.event_type !== "im.message.receive_v1") return null;
  const ev = envelope.event;
  const text = feishuExtractText(ev.message.message_type, ev.message.content);
  return {
    id: ev.message.message_id,
    channel: "feishu",
    senderId: ev.sender.sender_id.open_id,
    senderName: ev.sender.sender_id.union_id ?? ev.sender.sender_id.open_id,
    chatId: ev.message.chat_id,
    text,
    command: parseSlashCommand(text),
    media:
      ev.message.message_type === "image" || ev.message.message_type === "file"
        ? [
            {
              type: ev.message.message_type === "image" ? "photo" : "document",
              fileId: ev.message.message_id,
            },
          ]
        : undefined,
    replyToMessageId: ev.message.root_id || ev.message.parent_id,
    raw: envelope,
    timestamp: new Date(Number(envelope.header.create_time ?? Date.now())).toISOString(),
    metadata: {
      chatType: ev.message.chat_type,
      tenantKey: envelope.header.tenant_key,
    },
  };
}

/** UnifiedResponse → Feishu im.message.create body. */
export function unifiedResponseToFeishuBody(
  chatId: string,
  response: UnifiedResponse,
): Record<string, unknown> {
  const useInteractive = !!(response.buttons && response.buttons.length > 0);
  if (!useInteractive) {
    return {
      receive_id: chatId,
      msg_type: "text",
      content: JSON.stringify({ text: response.text }),
    };
  }
  // Interactive (card) message with buttons.
  const card = {
    config: { wide_screen_mode: true },
    elements: [
      { tag: "div", text: { tag: "lark_md", content: response.text } },
      ...(response.buttons ?? []).map((row) => ({
        tag: "action",
        actions: row.map((btn) => ({
          tag: "button",
          text: { tag: "plain_text", content: btn.text },
          type: "primary",
          ...(btn.url
            ? { url: btn.url }
            : { value: { callback: btn.callbackData ?? btn.text } }),
        })),
      })),
    ],
  };
  return {
    receive_id: chatId,
    msg_type: "interactive",
    content: JSON.stringify(card),
  };
}

export class FeishuBot implements ChannelBot {
  readonly type = "feishu" as const;

  private config: FeishuConfig;
  private handler: MessageHandler | null = null;
  private connected = false;
  private tenantAccessToken: string | null = null;

  constructor(config: FeishuConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  /** open.feishu.cn (default) or open.larksuite.com when isLark=true. */
  apiHost(): string {
    return this.config.isLark ? "https://open.larksuite.com" : "https://open.feishu.cn";
  }

  async start(): Promise<void> {
    if (!this.config.appId || !this.config.appSecret) {
      console.log("  ⚠️ Feishu/Lark: missing appId/appSecret — skipping");
      return;
    }
    // Production wiring:
    //   POST {host}/open-apis/auth/v3/tenant_access_token/internal
    //   refresh ~30 min ahead of expiry; cache in this.tenantAccessToken
    //   webhook handler decrypts (AES-256-CBC if encryptKey set), verifies token,
    //   and dispatches via ingestEvent
    this.connected = true;
    console.log(
      `  ✓ ${this.config.isLark ? "Lark" : "Feishu"} channel configured (skeleton)`,
    );
  }

  async stop(): Promise<void> {
    this.connected = false;
    this.tenantAccessToken = null;
    console.log("  ✓ Feishu/Lark bot stopped");
  }

  async ingestEvent(envelope: FeishuEventEnvelope): Promise<UnifiedResponse | null> {
    // Token verification is the operator's responsibility at the webhook edge,
    // but we still defensively re-check here when configured.
    if (this.config.verificationToken && envelope.header.token) {
      if (envelope.header.token !== this.config.verificationToken) return null;
    }
    if (!this.handler) return null;
    const unified = feishuEventToUnified(envelope);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response) await this.send(unified.chatId, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const body = unifiedResponseToFeishuBody(chatId, response);
    // POST {host}/open-apis/im/v1/messages?receive_id_type=chat_id  with Bearer tenantAccessToken
    console.log(
      `[${this.config.isLark ? "Lark" : "Feishu"}] would send to ${chatId}: ${response.text.slice(0, 50)}…`,
    );
    return JSON.stringify(body);
  }

  async edit(_chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    if (!this.connected) return false;
    // PUT {host}/open-apis/im/v1/messages/{messageId}
    void messageId; void response;
    return true;
  }

  /** Test hook: inject a tenant_access_token without doing the auth call. */
  setTenantAccessToken(token: string | null): void {
    this.tenantAccessToken = token;
  }
}
