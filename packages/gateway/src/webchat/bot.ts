/**
 * WebChat Bot — Lyrie Gateway adapter.
 *
 * The channel Lyrie owns end-to-end (chat widget on lyrie.ai or any operator's
 * site). Inbound = WebSocket / SSE from the embedded widget; outbound = same
 * socket. Each browser tab is one ephemeral chatId.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import type {
  ChannelBot,
  MessageHandler,
  ParsedCommand,
  UnifiedMessage,
  UnifiedResponse,
  WebChatConfig,
} from "../common/types";

export interface WebChatInboundFrame {
  type: "message" | "callback" | "presence" | string;
  /** Stable session/visitor id from the widget cookie. */
  sessionId: string;
  /** Optional logical chat id (widget allows multiple tabs / contexts). */
  chatId?: string;
  /** Optional display name from widget profile. */
  name?: string;
  text?: string;
  callback?: string;
  /** Sequence number to detect reorder / dropped frames. */
  seq?: number;
  /** Optional client-side timestamp. */
  ts?: number;
}

export interface WebChatOutboundFrame {
  type: "message" | "ack" | "error" | "presence";
  chatId: string;
  text?: string;
  buttons?: Array<Array<{ text: string; callback?: string; url?: string }>>;
  parseMode?: "markdown" | "html" | "plain";
  replyTo?: string;
  ts: number;
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

export function webchatFrameToUnified(frame: WebChatInboundFrame): UnifiedMessage | null {
  if (!frame.sessionId) return null;
  const chatId = frame.chatId ?? frame.sessionId;
  if (frame.type === "callback") {
    return {
      id: `webchat-${frame.seq ?? Date.now()}`,
      channel: "webchat",
      senderId: frame.sessionId,
      senderName: frame.name ?? frame.sessionId,
      chatId,
      text: "",
      callbackData: frame.callback,
      raw: frame,
      timestamp: new Date(frame.ts ?? Date.now()).toISOString(),
    };
  }
  if (frame.type !== "message" || !frame.text) return null;
  return {
    id: `webchat-${frame.seq ?? Date.now()}`,
    channel: "webchat",
    senderId: frame.sessionId,
    senderName: frame.name ?? frame.sessionId,
    chatId,
    text: frame.text,
    command: parseSlashCommand(frame.text),
    raw: frame,
    timestamp: new Date(frame.ts ?? Date.now()).toISOString(),
  };
}

export function unifiedResponseToWebChatFrame(
  chatId: string,
  response: UnifiedResponse,
): WebChatOutboundFrame {
  return {
    type: "message",
    chatId,
    text: response.text,
    buttons: response.buttons?.map((row) =>
      row.map((b) => ({ text: b.text, callback: b.callbackData, url: b.url })),
    ),
    parseMode: response.parseMode,
    replyTo: response.replyToMessageId,
    ts: Date.now(),
  };
}

/**
 * Origin allow-list check for browser-initiated handshakes.
 * Returns true if `origin` matches any pattern in `allow`. Patterns may use
 * a leading "*." for subdomain wildcarding ("*.lyrie.ai").
 */
export function isWebChatOriginAllowed(origin: string, allow: string[] | undefined): boolean {
  if (!allow || allow.length === 0) return true;
  for (const pattern of allow) {
    if (pattern === "*") return true;
    if (pattern === origin) return true;
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".lyrie.ai"
      if (origin.endsWith(suffix) && origin.length > suffix.length) return true;
    }
  }
  return false;
}

export class WebChatBot implements ChannelBot {
  readonly type = "webchat" as const;

  private config: WebChatConfig;
  private handler: MessageHandler | null = null;
  private connected = false;
  /** Active sockets indexed by chatId.  Tests inject mock sockets. */
  private sockets: Map<string, { send: (frame: WebChatOutboundFrame) => void }> = new Map();

  constructor(config: WebChatConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async start(): Promise<void> {
    // Production wiring:
    //   const server = Bun.serve({ port, hostname, fetch(req, server) {
    //     if (server.upgrade(req, { data: { ... } })) return;
    //     return new Response("lyrie webchat", { status: 200 });
    //   }, websocket: { open(ws){...}, message(ws, raw){
    //     const frame = JSON.parse(raw);
    //     this.ingestFrame(frame);
    //   }}});
    this.connected = true;
    console.log(
      `  ✓ WebChat channel configured (skeleton, ${this.config.host ?? "127.0.0.1"}:${this.config.port ?? 7777})`,
    );
  }

  async stop(): Promise<void> {
    this.connected = false;
    this.sockets.clear();
    console.log("  ✓ WebChat bot stopped");
  }

  registerSocket(chatId: string, sock: { send: (frame: WebChatOutboundFrame) => void }): void {
    this.sockets.set(chatId, sock);
  }

  dropSocket(chatId: string): void {
    this.sockets.delete(chatId);
  }

  async ingestFrame(frame: WebChatInboundFrame): Promise<UnifiedResponse | null> {
    if (!this.handler) return null;
    const unified = webchatFrameToUnified(frame);
    if (!unified) return null;
    const response = await this.handler(unified);
    if (response) await this.send(unified.chatId, response);
    return response;
  }

  async send(chatId: string, response: UnifiedResponse): Promise<string | null> {
    if (!this.connected) return null;
    const frame = unifiedResponseToWebChatFrame(chatId, response);
    const sock = this.sockets.get(chatId);
    if (sock) sock.send(frame);
    return JSON.stringify(frame);
  }

  async edit(_chatId: string, _messageId: string, _response: UnifiedResponse): Promise<boolean> {
    // Edits are out-of-scope for the v0.3.2 widget protocol; clients re-render.
    return false;
  }
}
