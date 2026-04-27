/**
 * Mattermost Bot — Lyrie Gateway adapter.
 *
 * Self-hosted Slack alternative — heavily used in defense / regulated /
 * sovereign-cloud contexts. Production wiring uses Mattermost's WebSocket
 * v4 API + REST for sends.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  MattermostConfig,
  MessageHandler,
  ParsedCommand,
  UnifiedMessage,
  UnifiedResponse,
} from "../common/types";

export interface MattermostPostedEvent {
  event: "posted" | "post_edited" | string;
  data: {
    channel_name?: string;
    channel_type?: "D" | "O" | "P" | "G";
    sender_name?: string;
    team_id?: string;
    /** JSON-stringified post object. */
    post: string;
  };
  broadcast?: { channel_id?: string; team_id?: string; user_id?: string };
}

export interface MattermostPost {
  id: string;
  user_id: string;
  channel_id: string;
  message: string;
  root_id?: string;
  type?: string;
  file_ids?: string[];
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

export function mattermostEventToUnified(
  event: MattermostPostedEvent,
  selfUserId?: string,
): UnifiedMessage | null {
  if (event.event !== "posted") return null;
  let post: MattermostPost;
  try {
    post = JSON.parse(event.data.post) as MattermostPost;
  } catch {
    return null;
  }
  if (selfUserId && post.user_id === selfUserId) return null;
  if (post.type && post.type !== "") return null; // skip system posts
  return {
    id: post.id,
    channel: "mattermost",
    senderId: post.user_id,
    senderName: event.data.sender_name ?? post.user_id,
    chatId: post.channel_id,
    text: post.message,
    command: parseSlashCommand(post.message),
    media: (post.file_ids ?? []).map((id) => ({
      type: "document" as const,
      fileId: id,
    })),
    replyToMessageId: post.root_id || undefined,
    raw: post,
    timestamp: new Date().toISOString(),
    metadata: {
      teamId: event.data.team_id,
      channelType: event.data.channel_type,
    },
  };
}

export function unifiedResponseToMattermostBody(
  channelId: string,
  response: UnifiedResponse,
  rootId?: string,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    channel_id: channelId,
    message: response.text,
  };
  if (rootId || response.replyToMessageId) {
    body["root_id"] = rootId ?? response.replyToMessageId;
  }
  if (response.buttons && response.buttons.length > 0) {
    body["props"] = {
      attachments: [
        {
          text: response.text,
          actions: response.buttons.flatMap((row, i) =>
            row.map((btn, j) => ({
              id: btn.callbackData ?? `btn-${i}-${j}`,
              name: btn.text,
              integration: btn.url
                ? { url: btn.url }
                : { url: "/lyrie/action", context: { value: btn.callbackData } },
            })),
          ),
        },
      ],
    };
  }
  return body;
}

export class MattermostBot implements ChannelBot {
  readonly type = "mattermost" as const;

  private config: MattermostConfig;
  private handler: MessageHandler | null = null;
  private connected = false;
  private selfUserId: string | undefined;

  constructor(config: MattermostConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async start(): Promise<void> {
    if (!this.config.serverUrl || !this.config.token) {
      console.log("  ⚠️ Mattermost: missing serverUrl/token — skipping");
      return;
    }
    // Production wiring:
    //   GET /api/v4/users/me with Bearer token (capture self user id)
    //   open ws://serverUrl/api/v4/websocket, then send {seq:1, action:"authentication_challenge", data:{token}}
    //   on "posted" → ingestEvent
    this.connected = true;
    console.log(
      `  ✓ Mattermost channel configured (skeleton, server=${this.config.serverUrl})`,
    );
  }

  async stop(): Promise<void> {
    this.connected = false;
    console.log("  ✓ Mattermost bot stopped");
  }

  setSelfUserId(id: string): void {
    this.selfUserId = id;
  }

  async ingestEvent(event: MattermostPostedEvent): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const unified = mattermostEventToUnified(event, this.selfUserId);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response) await this.send(unified.chatId, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const body = unifiedResponseToMattermostBody(chatId, response);
    // POST /api/v4/posts with Bearer token
    console.log(`[Mattermost] would send to ${chatId}: ${response.text.slice(0, 50)}…`);
    return JSON.stringify(body);
  }

  async edit(chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    if (!this.connected) return false;
    // PUT /api/v4/posts/{messageId} with { message }
    void chatId; void messageId; void response;
    return true;
  }
}
