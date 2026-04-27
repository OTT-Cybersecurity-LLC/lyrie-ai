/**
 * Slack Bot — Lyrie Gateway adapter.
 *
 * Implements the ChannelBot contract over Slack's Web API + (optionally) Socket
 * Mode. The skeleton pattern matches Discord/WhatsApp: connect, normalize
 * inbound to UnifiedMessage, send via UnifiedResponse → Web API.
 *
 * Production wiring uses @slack/web-api + @slack/socket-mode.  Tests cover
 * normalization + send-shape; live network calls live in a separate integration
 * tier (LYRIE_LIVE=1).
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  MessageHandler,
  ParsedCommand,
  SlackConfig,
  UnifiedMessage,
  UnifiedResponse,
} from "../common/types";

// ─── Inbound event shapes (subset we care about) ───────────────────────────────

export interface SlackEventMessage {
  type: "message";
  user?: string;
  text?: string;
  channel?: string;
  ts?: string;
  thread_ts?: string;
  team?: string;
  bot_id?: string;
  subtype?: string;
  files?: Array<{ id: string; name?: string; mimetype?: string; size?: number }>;
}

export interface SlackBlockAction {
  action_id: string;
  block_id?: string;
  value?: string;
  type: string;
}

export interface SlackInteractionPayload {
  type: "block_actions" | "view_submission" | "shortcut" | string;
  user: { id: string; name?: string; team_id?: string };
  channel?: { id: string; name?: string };
  team?: { id: string; domain?: string };
  actions?: SlackBlockAction[];
  message?: { ts: string; text?: string };
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

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

/** Convert a Slack `message` event into a Lyrie UnifiedMessage. */
export function slackEventToUnified(event: SlackEventMessage): UnifiedMessage | null {
  // Ignore messages from bots and edits — narrow what the engine sees.
  if (event.bot_id) return null;
  if (event.subtype && event.subtype !== "thread_broadcast") return null;
  if (!event.user || !event.channel) return null;

  const text = event.text ?? "";
  return {
    id: event.ts ?? `slack-${Date.now()}`,
    channel: "slack",
    senderId: event.user,
    senderName: event.user,
    chatId: event.channel,
    text,
    command: parseSlashCommand(text),
    media: (event.files ?? []).map((f) => ({
      type: "document" as const,
      fileId: f.id,
      filename: f.name,
      mimeType: f.mimetype,
      size: f.size,
    })),
    replyToMessageId: event.thread_ts,
    raw: event,
    timestamp: new Date().toISOString(),
    metadata: { team: event.team },
  };
}

/** Convert a Slack `block_actions` interaction into a UnifiedMessage. */
export function slackInteractionToUnified(payload: SlackInteractionPayload): UnifiedMessage | null {
  if (payload.type !== "block_actions") return null;
  const action = payload.actions?.[0];
  if (!action) return null;
  return {
    id: payload.message?.ts ?? `slack-int-${Date.now()}`,
    channel: "slack",
    senderId: payload.user.id,
    senderName: payload.user.name ?? payload.user.id,
    chatId: payload.channel?.id ?? payload.user.id,
    text: payload.message?.text ?? "",
    callbackData: action.value ?? action.action_id,
    raw: payload,
    timestamp: new Date().toISOString(),
    metadata: { team: payload.team?.id },
  };
}

/** Convert a Lyrie UnifiedResponse to Slack `chat.postMessage` body. */
export function unifiedResponseToSlackBody(
  channelId: string,
  response: UnifiedResponse,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    channel: channelId,
    text: response.text,
  };
  if (response.replyToMessageId) body["thread_ts"] = response.replyToMessageId;

  if (response.buttons && response.buttons.length > 0) {
    const blocks: unknown[] = [
      { type: "section", text: { type: "mrkdwn", text: response.text || "—" } },
    ];
    for (const row of response.buttons) {
      blocks.push({
        type: "actions",
        elements: row.map((btn) => ({
          type: "button",
          text: { type: "plain_text", text: btn.text },
          action_id: btn.callbackData ?? `btn-${btn.text}`,
          value: btn.callbackData,
          ...(btn.url ? { url: btn.url } : {}),
        })),
      });
    }
    body["blocks"] = blocks;
  }
  return body;
}

// ─── Bot ────────────────────────────────────────────────────────────────────────

export class SlackBot implements ChannelBot {
  readonly type = "slack" as const;

  private config: SlackConfig;
  private handler: MessageHandler | null = null;
  private connected = false;

  constructor(config: SlackConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async start(): Promise<void> {
    if (!this.config.botToken) {
      console.log("  ⚠️ Slack: missing botToken — skipping");
      return;
    }
    // Production wiring (Socket Mode if appToken present, else Events API):
    //   import { App } from "@slack/bolt";
    //   const app = new App({ token: this.config.botToken,
    //     signingSecret: this.config.signingSecret,
    //     socketMode: !!this.config.appToken,
    //     appToken: this.config.appToken });
    //   app.event("message", async ({ event }) => { ... });
    //   app.action(/.+/, async ({ ack, body }) => { await ack(); ... });
    this.connected = true;
    console.log("  ✓ Slack channel configured (skeleton)");
  }

  async stop(): Promise<void> {
    this.connected = false;
    console.log("  ✓ Slack bot stopped");
  }

  /** Process an inbound Slack event — wired up by the Bolt app event handler. */
  async ingestEvent(event: SlackEventMessage): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const unified = slackEventToUnified(event);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response && event.channel) await this.send(event.channel, response);
    return response;
  }

  /** Process a Slack block-actions interaction. */
  async ingestInteraction(payload: SlackInteractionPayload): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const unified = slackInteractionToUnified(payload);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response && payload.channel?.id) await this.send(payload.channel.id, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const body = unifiedResponseToSlackBody(chatId, response);
    // POST https://slack.com/api/chat.postMessage with Bearer botToken
    console.log(`[Slack] would send to ${chatId}: ${response.text.slice(0, 50)}…`);
    return JSON.stringify(body);
  }

  async edit(chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean> {
    if (!this.connected) return false;
    // POST https://slack.com/api/chat.update { channel, ts, text, blocks }
    void chatId; void messageId; void response;
    return true;
  }
}
