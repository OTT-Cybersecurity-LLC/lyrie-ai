/**
 * Unified message types for Lyrie Gateway.
 * All channels convert their native messages to/from these types.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Channel Identifiers ───────────────────────────────────────────────────────

export type ChannelType =
  | "telegram"
  | "whatsapp"
  | "discord"
  | "slack"
  | "signal"
  | "cli"
  | "matrix"
  | "mattermost"
  | "irc"
  | "feishu"
  | "rocketchat"
  | "webchat";

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
  slack?: SlackConfig;
  matrix?: MatrixConfig;
  mattermost?: MattermostConfig;
  irc?: IrcConfig;
  feishu?: FeishuConfig;
  rocketchat?: RocketChatConfig;
  webchat?: WebChatConfig;
}

/**
 * DM access policy for any DM-capable channel.
 *
 * - "open"     — anyone can DM (back-compat default; existing allowlists
 *                still enforced if you set them)
 * - "pairing"  — unknown DMs receive a one-time code; operator approves via
 *                `lyrie pairing approve <channel> <code>`
 * - "closed"   — only senders in `allowedUsers`/`allowedChats` reach the agent
 */
export type DmPolicy = "open" | "pairing" | "closed";

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
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface WhatsAppConfig {
  enabled: boolean;
  /** Phone number ID for WhatsApp Business API */
  phoneNumberId?: string;
  /** Access token */
  accessToken?: string;
  /** Webhook verify token */
  verifyToken?: string;
  /** Allowed sender phone numbers / ids */
  allowedUsers?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface DiscordConfig {
  enabled: boolean;
  /** Bot token */
  token?: string;
  /** Application ID */
  applicationId?: string;
  /** Allowed guild IDs */
  allowedGuilds?: string[];
  /** Allowed user IDs (DM allowlist) */
  allowedUsers?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface SlackConfig {
  enabled: boolean;
  /** Bot User OAuth Token (xoxb-…) */
  botToken?: string;
  /** Signing secret for request validation */
  signingSecret?: string;
  /** App-level token for Socket Mode (xapp-…); enables Socket Mode when set */
  appToken?: string;
  /** Allowed workspace (team) IDs */
  allowedTeams?: string[];
  /** Allowed user IDs (DM allowlist) */
  allowedUsers?: string[];
  /** Allowed channel IDs */
  allowedChannels?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface MatrixConfig {
  enabled: boolean;
  /** Homeserver URL, e.g. https://matrix.org */
  homeserverUrl?: string;
  /** Bot user ID, e.g. @lyrie:matrix.org */
  userId?: string;
  /** Access token for the bot account */
  accessToken?: string;
  /** Device ID (optional) */
  deviceId?: string;
  /** Allowed user IDs (DM allowlist) */
  allowedUsers?: string[];
  /** Allowed room IDs */
  allowedRooms?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface MattermostConfig {
  enabled: boolean;
  /** Mattermost server URL, e.g. https://mattermost.example.com */
  serverUrl?: string;
  /** Bot account access token */
  token?: string;
  /** Team ID(s) the bot operates in */
  allowedTeams?: string[];
  /** Allowed user IDs (DM allowlist) */
  allowedUsers?: string[];
  /** Allowed channel IDs */
  allowedChannels?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface IrcConfig {
  enabled: boolean;
  /** IRC server hostname, e.g. irc.libera.chat */
  server?: string;
  /** IRC server port (default 6697 TLS) */
  port?: number;
  /** Whether to use TLS (default true) */
  tls?: boolean;
  /** Bot nickname */
  nick?: string;
  /** SASL username (optional) */
  user?: string;
  /** SASL password (optional) */
  password?: string;
  /** Channels to auto-join, e.g. ["#lyrie"] */
  channels?: string[];
  /** Allowed user nicks/hostmasks for DM */
  allowedUsers?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface FeishuConfig {
  enabled: boolean;
  /** App ID from Feishu Open Platform (or Lark) */
  appId?: string;
  /** App secret */
  appSecret?: string;
  /** Encryption key (optional, for event-callback decryption) */
  encryptKey?: string;
  /** Verification token */
  verificationToken?: string;
  /** Whether this is the international (Lark) edition (default false = Feishu) */
  isLark?: boolean;
  /** Allowed open IDs for DM */
  allowedUsers?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface RocketChatConfig {
  enabled: boolean;
  /** Rocket.Chat server URL, e.g. https://chat.example.com */
  serverUrl?: string;
  /** Bot user ID */
  userId?: string;
  /** Bot auth token */
  authToken?: string;
  /** Allowed user IDs for DM */
  allowedUsers?: string[];
  /** Allowed room IDs (channels/groups) */
  allowedRooms?: string[];
  /** DM access policy (default: "open") */
  dmPolicy?: DmPolicy;
}

export interface WebChatConfig {
  enabled: boolean;
  /** Host the embedded WebSocket server binds to (default 127.0.0.1) */
  host?: string;
  /** Port (default 7777) */
  port?: number;
  /** Origin allowlist for CORS / Origin checking */
  allowedOrigins?: string[];
  /** Auth token required from clients (optional but recommended) */
  authToken?: string;
  /** DM access policy (default: "open"); only "closed" is meaningful for webchat */
  dmPolicy?: DmPolicy;
}
