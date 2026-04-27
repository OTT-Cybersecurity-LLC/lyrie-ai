/**
 * IRC Bot — Lyrie Gateway adapter.
 *
 * The original. Production wiring uses irc-framework or matrix-irc-bridge style
 * connection — a TCP/TLS socket speaking RFC 2812 with optional SASL PLAIN.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  IrcConfig,
  MessageHandler,
  ParsedCommand,
  UnifiedMessage,
  UnifiedResponse,
} from "../common/types";

export interface IrcPrivmsgEvent {
  /** Sender nick (e.g. "alice"). */
  nick: string;
  /** Full prefix (e.g. "alice!alice@host"). */
  prefix?: string;
  /** Target — channel ("#lyrie") or our own nick (DM). */
  target: string;
  /** Trailing parameter (the actual message text). */
  message: string;
  /** Server timestamp if IRCv3 server-time tag present. */
  serverTime?: string;
}

function parseIrcCommand(text: string): ParsedCommand | undefined {
  const trimmed = text.trimStart();
  if (!trimmed.startsWith("!") && !trimmed.startsWith("/")) return undefined;
  const parts = trimmed.slice(1).split(/\s+/);
  const name = parts[0]?.toLowerCase() ?? "";
  if (!name) return undefined;
  const args = parts.slice(1).join(" ");
  const argv = args.length > 0 ? args.split(/\s+/) : [];
  return { name, args, argv };
}

/** A message is a DM if its target is the bot's own nick (not a channel). */
export function isIrcDirectMessage(target: string, selfNick: string): boolean {
  if (!target) return false;
  if (target.startsWith("#") || target.startsWith("&") || target.startsWith("+")) return false;
  return target.toLowerCase() === selfNick.toLowerCase();
}

export function ircEventToUnified(
  event: IrcPrivmsgEvent,
  selfNick: string,
): UnifiedMessage {
  const isDm = isIrcDirectMessage(event.target, selfNick);
  // For DMs the "chat" identifier is the sender's nick; for channels it's the channel.
  const chatId = isDm ? event.nick : event.target;
  return {
    id: `irc-${event.serverTime ?? Date.now()}-${event.nick}`,
    channel: "irc",
    senderId: event.nick,
    senderName: event.nick,
    chatId,
    text: event.message,
    command: parseIrcCommand(event.message),
    raw: event,
    timestamp: event.serverTime ?? new Date().toISOString(),
    metadata: { isDm, prefix: event.prefix },
  };
}

/** Split an outbound message at IRC's 510-byte trailing limit (UTF-8 safe). */
export function splitForIrc(text: string, maxBytes: number = 400): string[] {
  if (!text) return [];
  const lines: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) continue;
    let buf = "";
    for (const ch of line) {
      const next = buf + ch;
      if (Buffer.byteLength(next, "utf8") > maxBytes) {
        lines.push(buf);
        buf = ch;
      } else {
        buf = next;
      }
    }
    if (buf) lines.push(buf);
  }
  return lines;
}

/** UnifiedResponse → IRC PRIVMSG line list. */
export function unifiedResponseToIrcLines(
  target: string,
  response: UnifiedResponse,
): string[] {
  const out: string[] = [];
  for (const line of splitForIrc(response.text)) {
    out.push(`PRIVMSG ${target} :${line}`);
  }
  // IRC has no native buttons; render link-buttons as bracketed [text](url) lines.
  if (response.buttons && response.buttons.length > 0) {
    const flat = response.buttons.flat();
    const linkLine = flat
      .map((b) => (b.url ? `[${b.text}](${b.url})` : `[${b.text}]`))
      .join("  ");
    if (linkLine) out.push(`PRIVMSG ${target} :${linkLine}`);
  }
  return out;
}

export class IrcBot implements ChannelBot {
  readonly type = "irc" as const;

  private config: IrcConfig;
  private handler: MessageHandler | null = null;
  private connected = false;

  constructor(config: IrcConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async start(): Promise<void> {
    if (!this.config.server || !this.config.nick) {
      console.log("  ⚠️ IRC: missing server/nick — skipping");
      return;
    }
    // Production wiring:
    //   const sock = tls.connect({ host: server, port: port ?? 6697 });
    //   send NICK / USER, optional CAP REQ :sasl + SASL PLAIN, JOIN channels
    //   on "PRIVMSG" → ingest
    this.connected = true;
    console.log(
      `  ✓ IRC channel configured (skeleton, ${this.config.server}:${this.config.port ?? 6697})`,
    );
  }

  async stop(): Promise<void> {
    this.connected = false;
    console.log("  ✓ IRC bot stopped");
  }

  async ingestEvent(event: IrcPrivmsgEvent): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const selfNick = this.config.nick ?? "lyrie";
    const unified = ircEventToUnified(event, selfNick);
    const response = await this.handler(unified);
    if (response) await this.send(unified.chatId, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const lines = unifiedResponseToIrcLines(chatId, response);
    for (const line of lines) console.log(`[IRC] → ${line.slice(0, 80)}…`);
    return lines.join("\r\n");
  }

  async edit(_chatId: string, _messageId: string, _response: UnifiedResponse): Promise<boolean> {
    // IRC has no message-edit primitive (IRCv3 message-tags / TYPING approximate).
    return false;
  }
}
