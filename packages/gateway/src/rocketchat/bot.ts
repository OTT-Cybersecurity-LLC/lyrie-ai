/**
 * Rocket.Chat Bot — Lyrie Gateway adapter.
 *
 * Self-hosted, popular across EU + LATAM enterprise.  Production wiring uses
 * the realtime DDP (Meteor) API for inbound + REST for sends.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  MessageHandler,
  ParsedCommand,
  RocketChatConfig,
  UnifiedMessage,
  UnifiedResponse,
} from "../common/types";

export interface RocketChatStreamMessage {
  _id: string;
  rid: string;
  msg: string;
  u: { _id: string; username: string; name?: string };
  ts?: { $date: number } | string | number;
  t?: string; // system message type — present means non-user post
  /** Direct-message channel marker. */
  drid?: string;
  /** Thread root, if part of a thread. */
  tmid?: string;
  attachments?: Array<{ title?: string; image_url?: string; type?: string }>;
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

function rcTimestamp(ts: RocketChatStreamMessage["ts"]): string {
  if (!ts) return new Date().toISOString();
  if (typeof ts === "number") return new Date(ts).toISOString();
  if (typeof ts === "string") return new Date(ts).toISOString();
  if (typeof (ts as { $date?: number }).$date === "number") {
    return new Date((ts as { $date: number }).$date).toISOString();
  }
  return new Date().toISOString();
}

export function rocketChatEventToUnified(
  msg: RocketChatStreamMessage,
  selfUserId?: string,
): UnifiedMessage | null {
  if (msg.t && msg.t !== "") return null; // system message (joined room, etc.)
  if (selfUserId && msg.u._id === selfUserId) return null; // ignore self-loop
  return {
    id: msg._id,
    channel: "rocketchat",
    senderId: msg.u._id,
    senderName: msg.u.username,
    chatId: msg.rid,
    text: msg.msg,
    command: parseSlashCommand(msg.msg),
    media: (msg.attachments ?? [])
      .filter((a) => a.image_url)
      .map((a) => ({ type: "photo" as const, fileId: a.image_url ?? "" })),
    replyToMessageId: msg.tmid,
    raw: msg,
    timestamp: rcTimestamp(msg.ts),
  };
}

/** UnifiedResponse → Rocket.Chat REST chat.postMessage body. */
export function unifiedResponseToRocketChatBody(
  channelId: string,
  response: UnifiedResponse,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    roomId: channelId,
    text: response.text,
  };
  if (response.replyToMessageId) body["tmid"] = response.replyToMessageId;
  if (response.buttons && response.buttons.length > 0) {
    body["attachments"] = [
      {
        actions: response.buttons.flatMap((row, i) =>
          row.map((btn, j) => ({
            type: "button",
            text: btn.text,
            msg: btn.callbackData ?? btn.text,
            msg_in_chat_window: true,
            ...(btn.url ? { url: btn.url } : {}),
            id: `btn-${i}-${j}`,
          })),
        ),
      },
    ];
  }
  return body;
}

export class RocketChatBot implements ChannelBot {
  readonly type = "rocketchat" as const;

  private config: RocketChatConfig;
  private handler: MessageHandler | null = null;
  private connected = false;
  private selfUserId: string | undefined;

  constructor(config: RocketChatConfig) {
    this.config = config;
    this.selfUserId = config.userId;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async start(): Promise<void> {
    if (!this.config.serverUrl || !this.config.userId || !this.config.authToken) {
      console.log("  ⚠️ Rocket.Chat: missing serverUrl/userId/authToken — skipping");
      return;
    }
    // Production wiring:
    //   open ws({serverUrl}/websocket), DDP "connect", login by resume token,
    //   subscribe "stream-room-messages", "__my_messages__", flush events to
    //   ingestEvent
    this.connected = true;
    console.log(
      `  ✓ Rocket.Chat channel configured (skeleton, server=${this.config.serverUrl})`,
    );
  }

  async stop(): Promise<void> {
    this.connected = false;
    console.log("  ✓ Rocket.Chat bot stopped");
  }

  async ingestEvent(msg: RocketChatStreamMessage): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const unified = rocketChatEventToUnified(msg, this.selfUserId);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response) await this.send(unified.chatId, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const body = unifiedResponseToRocketChatBody(chatId, response);
    // POST {serverUrl}/api/v1/chat.postMessage with X-User-Id + X-Auth-Token
    console.log(`[RocketChat] would send to ${chatId}: ${response.text.slice(0, 50)}…`);
    return JSON.stringify(body);
  }

  async edit(_chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    if (!this.connected) return false;
    // POST /api/v1/chat.update with { roomId, msgId, text }
    void messageId; void response;
    return true;
  }
}
