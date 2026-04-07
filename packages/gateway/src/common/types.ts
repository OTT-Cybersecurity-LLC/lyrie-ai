/**
 * Unified message types for Lyrie Gateway.
 * All channels convert their native messages to/from these types.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Channel Identifiers ───────────────────────────────────────────────────────

export type ChannelType = "telegram" | "whatsapp" | "discord" | "slack" | "signal" | "cli";

// ─── Unified Inbound Message ────────────────────────────────────────────────────

export interface UnifiedMessage {
  /** Unique message ID within the channel */
  id: string;
  /** Which channel this arrived on */
  channel: ChannelType;
  /** Sender identifier (platform-specific user ID) */
  senderId: string;
  /** Sender display name */
  senderName: string;
  /** Chat/conversation ID */
  chatId: string;
  /** Text content (may be empty for media-only messages) */
  text: string;
  /** Parsed command if the message starts with / */
  command?: ParsedCommand;
  /** Attached media */
  media?: MediaAttachment[];
  /** Callback data from inline buttons */
  callbackData?: string;
  /** ID of the message being replied to */
  replyToMessageId?: string;
  /** Raw platform-specific payload for escape hatches */
  raw?: unknown;
  /** ISO timestamp */
  timestamp: string;
  /** Message metadata */
  metadata?: Record<string, unknown>;
}

export interface ParsedCommand {
  /** Command name without the slash, e.g. "scan" */
  name: string;
  /** Everything after the command */
  args: string;
  /** Arguments split by whitespace */
  argv: string[];
}

export interface MediaAttachment {
  type: "photo" | "document" | "audio" | "video" | "voice" | "sticker" | "animation";
  /** URL or file ID to retrieve the media */
  fileId: string;
  /** Original filename if available */
  filename?: string;
  /** MIME type */
  mimeType?: string;
  /** File size in bytes */
  size?: number;
  /** Caption text */
  caption?: string;
}

// ─── Unified Outbound Response ──────────────────────────────────────────────────

export interface UnifiedResponse {
  /** Text content to send */
  text: string;
  /** Parse mode for rich text */
  parseMode?: "markdown" | "html" | "plain";
  /** Inline keyboard buttons */
  buttons?: InlineButton[][];
  /** Media to send with the message */
  media?: OutboundMedia;
  /** Reply to a specific message */
  replyToMessageId?: string;
  /** Whether to send silently (no notification) */
  silent?: boolean;
  /** Whether to disable link previews */
  disableLinkPreview?: boolean;
  /** Additional channel-specific options */
  extra?: Record<string, unknown>;
}

export interface InlineButton {
  /** Button display text */
  text: string;
  /** Callback data sent when button is pressed */
  callbackData?: string;
  /** URL to open */
  url?: string;
}

export interface OutboundMedia {
  type: "photo" | "document" | "audio" | "video" | "animation";
  /** URL, file path, or file ID */
  source: string;
  /** Caption */
  caption?: string;
  /** MIME type */
  mimeType?: string;
  /** Filename for documents */
  filename?: string;
}

// ─── Channel Interface ──────────────────────────────────────────────────────────

export interface ChannelBot {
  /** Channel type identifier */
  readonly type: ChannelType;
  /** Start receiving messages */
  start(): Promise<void>;
  /** Gracefully stop */
  stop(): Promise<void>;
  /** Send a response to a specific chat */
  send(chatId: string, response: UnifiedResponse): Promise<string | null>;
  /** Edit an existing message */
  edit(chatId: string, messageId: string, response: UnifiedResponse): Promise<boolean>;
  /** Whether this channel is currently connected */
  isConnected(): boolean;
}

// ─── Message Handler ────────────────────────────────────────────────────────────

export type MessageHandler = (message: UnifiedMessage) => Promise<UnifiedResponse | null>;

// ─── Gateway Config ─────────────────────────────────────────────────────────────

export interface GatewayConfig {
  telegram?: TelegramConfig;
  whatsapp?: WhatsAppConfig;
  discord?: DiscordConfig;
}

export interface TelegramConfig {
  enabled: boolean;
  token: string;
  /** Allowed user IDs (empty = allow all) */
  allowedUsers?: string[];
  /** Allowed chat IDs (empty = allow all) */
  allowedChats?: string[];
  /** Webhook URL (if using webhook mode instead of polling) */
  webhookUrl?: string;
  /** Polling interval in ms (default: 1000) */
  pollInterval?: number;
  /** Rate limit: max messages per user per minute (default: 30) */
  rateLimitPerMinute?: number;
}

export interface WhatsAppConfig {
  enabled: boolean;
  /** Phone number ID for WhatsApp Business API */
  phoneNumberId?: string;
  /** Access token */
  accessToken?: string;
  /** Webhook verify token */
  verifyToken?: string;
}

export interface DiscordConfig {
  enabled: boolean;
  /** Bot token */
  token?: string;
  /** Application ID */
  applicationId?: string;
  /** Allowed guild IDs */
  allowedGuilds?: string[];
}
