/**
 * Matrix Bot — Lyrie Gateway adapter.
 *
 * Federated, open-protocol channel (matrix.org / Element / self-hosted Synapse).
 * Production: matrix-bot-sdk or matrix-js-sdk over a long-lived /sync loop.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  MatrixConfig,
  MessageHandler,
  ParsedCommand,
  UnifiedMessage,
  UnifiedResponse,
} from "../common/types";

// ─── Matrix event shape (subset) ───────────────────────────────────────────────

export interface MatrixRoomMessageEvent {
  type: "m.room.message";
  event_id: string;
  sender: string;
  room_id: string;
  origin_server_ts: number;
  content: {
    msgtype: "m.text" | "m.image" | "m.file" | "m.audio" | "m.video" | string;
    body?: string;
    url?: string;
    info?: { mimetype?: string; size?: number };
    "m.relates_to"?: { "m.in_reply_to"?: { event_id: string } };
  };
}

function parseSlashCommand(text: string): ParsedCommand | undefined {
  const trimmed = text.trimStart();
  if (!trimmed.startsWith("!") && !trimmed.startsWith("/")) return undefined;
  const parts = trimmed.slice(1).split(/\s+/);
  const name = parts[0]?.toLowerCase() ?? "";
  if (!name) return undefined;
  const args = parts.slice(1).join(" ");
  const argv = args.length > 0 ? args.split(/\s+/) : [];
  return { name, args, argv };
}

/** Convert a Matrix room.message event to a Lyrie UnifiedMessage. */
export function matrixEventToUnified(
  event: MatrixRoomMessageEvent,
  selfUserId?: string,
): UnifiedMessage | null {
  if (selfUserId && event.sender === selfUserId) return null;
  const text = event.content.body ?? "";
  const isMedia = event.content.msgtype !== "m.text";
  return {
    id: event.event_id,
    channel: "matrix",
    senderId: event.sender,
    senderName: event.sender,
    chatId: event.room_id,
    text,
    command: parseSlashCommand(text),
    media: isMedia
      ? [
          {
            type: event.content.msgtype === "m.image" ? "photo" : "document",
            fileId: event.content.url ?? "",
            mimeType: event.content.info?.mimetype,
            size: event.content.info?.size,
          },
        ]
      : undefined,
    replyToMessageId: event.content["m.relates_to"]?.["m.in_reply_to"]?.event_id,
    raw: event,
    timestamp: new Date(event.origin_server_ts).toISOString(),
  };
}

/** UnifiedResponse → Matrix room-send body. */
export function unifiedResponseToMatrixContent(
  response: UnifiedResponse,
): Record<string, unknown> {
  const useHtml = response.parseMode === "html" || response.parseMode === "markdown";
  const content: Record<string, unknown> = {
    msgtype: "m.text",
    body: response.text,
  };
  if (useHtml) {
    content["format"] = "org.matrix.custom.html";
    content["formatted_body"] = response.text;
  }
  if (response.replyToMessageId) {
    content["m.relates_to"] = {
      "m.in_reply_to": { event_id: response.replyToMessageId },
    };
  }
  return content;
}

export class MatrixBot implements ChannelBot {
  readonly type = "matrix" as const;

  private config: MatrixConfig;
  private handler: MessageHandler | null = null;
  private connected = false;
  private nextSyncToken: string | null = null;

  constructor(config: MatrixConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async start(): Promise<void> {
    if (!this.config.homeserverUrl || !this.config.accessToken) {
      console.log("  ⚠️ Matrix: missing homeserverUrl/accessToken — skipping");
      return;
    }
    // Production wiring:
    //   import { MatrixClient, SimpleFsStorageProvider } from "matrix-bot-sdk";
    //   const client = new MatrixClient(homeserver, accessToken,
    //     new SimpleFsStorageProvider("/var/lib/lyrie/matrix.json"));
    //   client.on("room.message", (roomId, ev) => this.ingestEvent(ev));
    //   await client.start();
    this.connected = true;
    console.log(
      `  ✓ Matrix channel configured (skeleton, homeserver=${this.config.homeserverUrl})`,
    );
  }

  async stop(): Promise<void> {
    this.connected = false;
    console.log("  ✓ Matrix bot stopped");
  }

  /** Push an inbound Matrix event through the handler chain. */
  async ingestEvent(event: MatrixRoomMessageEvent): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const unified = matrixEventToUnified(event, this.config.userId);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response) await this.send(event.room_id, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const content = unifiedResponseToMatrixContent(response);
    // PUT /_matrix/client/v3/rooms/{chatId}/send/m.room.message/{txnId}
    console.log(`[Matrix] would send to ${chatId}: ${response.text.slice(0, 50)}…`);
    return JSON.stringify(content);
  }

  async edit(chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    if (!this.connected) return false;
    // Matrix edit = m.replace relation event:
    //   { msgtype:"m.text", body:"* "+new, "m.new_content": {...},
    //     "m.relates_to": { rel_type:"m.replace", event_id:messageId } }
    void chatId; void messageId; void response;
    return true;
  }

  /** Internal: advance the long-poll sync token (test hook). */
  setSyncToken(token: string | null): void {
    this.nextSyncToken = token;
  }

  getSyncToken(): string | null {
    return this.nextSyncToken;
  }
}
