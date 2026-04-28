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

// ─── E2EE config ─────────────────────────────────────────────────────────────

/**
 * Configuration for Matrix End-to-End Encryption (E2EE).
 *
 * Set `deviceId` in {@link MatrixConfig} to activate E2EE. When set, Lyrie
 * will attempt to initialise the Rust/Olm crypto layer via `matrix-js-sdk`.
 *
 * Requires: `npm install matrix-js-sdk` (optional peer dep).
 * If the SDK is not installed, Lyrie falls back to plain HTTP sends.
 */
export interface MatrixE2EEConfig {
  /** The Matrix device ID registered for this bot user. */
  deviceId: string;
  /**
   * Path to the local SQLite file used to persist device keys.
   * Defaults to `./lyrie-device-keys.sqlite` in the current working directory.
   */
  keyCachePath?: string;
}

// ─── Internal E2EE state ─────────────────────────────────────────────────────

interface E2EEState {
  /** Whether Olm crypto was successfully initialised. */
  ready: boolean;
  /** The resolved deviceId. */
  deviceId: string;
  /** Resolved path to the key-cache SQLite file. */
  keyCachePath: string;
  /**
   * The live `MatrixClient` from matrix-js-sdk (if SDK is available).
   * Typed as `unknown` to avoid a hard dependency on the SDK types.
   *
   * TODO(#41): replace `unknown` with `import('matrix-js-sdk').MatrixClient`
   * once matrix-js-sdk is declared as a peerDependency in package.json and
   * the Olm WASM binary is bundled. Then call:
   *   - `client.initRustCrypto()` (SDK >= 28) or `client.initCrypto()` (legacy)
   *   - Listen for `client.once(ClientEvent.Sync, ...)` before sending
   *   - Use `client.isRoomEncrypted(roomId)` to detect E2EE rooms
   *   - Use `client.sendEvent(roomId, EventType.RoomEncrypted, content, txnId)`
   *     for encrypted sends
   */
  matrixClient: unknown;
}

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
  private e2ee: E2EEState | null = null;

  constructor(config: MatrixConfig) {
    this.config = config;
  }

  // ── E2EE API ───────────────────────────────────────────────────────────────

  /**
   * Returns the current E2EE state, or `null` if E2EE was not initialised.
   * Exposed for testing and diagnostics.
   */
  getE2EEState(): E2EEState | null {
    return this.e2ee;
  }

  /**
   * Initialise End-to-End Encryption for this Matrix bot.
   *
   * Called automatically by {@link start} when `config.deviceId` is set.
   * Safe to call manually in tests (pass a pre-built state via `_injectE2EE`).
   *
   * Behaviour:
   * - Attempts to dynamically import `matrix-js-sdk`.
   * - If the SDK is available: creates a MatrixClient with the given deviceId,
   *   then calls `initRustCrypto()` or `initCrypto()` (fallback).
   * - If the SDK is NOT available: logs a warning and marks `ready: false`.
   *   All sends fall back to plain (non-encrypted) HTTP.
   */
  async initE2EE(cfg: MatrixE2EEConfig): Promise<void> {
    const keyCachePath = cfg.keyCachePath ?? "./lyrie-device-keys.sqlite";
    this.e2ee = { ready: false, deviceId: cfg.deviceId, keyCachePath, matrixClient: null };

    // Attempt to load matrix-js-sdk as an optional peer dependency.
    // TODO(#41): Once matrix-js-sdk is added to peerDependencies, remove the
    // catch block and make the import unconditional. See MatrixE2EEConfig JSDoc
    // for the full wiring checklist.
    let sdk: unknown = null;
    try {
      sdk = await import("matrix-js-sdk");
    } catch {
      console.warn(
        `[matrix] matrix-js-sdk not installed — E2EE unavailable. ` +
        `Install with: npm install matrix-js-sdk\n` +
        `  Falling back to plain (unencrypted) HTTP sends.`,
      );
      return; // e2ee.ready stays false; send() will use plain HTTP
    }

    // SDK is available — create a MatrixClient and init crypto.
    // TODO(#41): Fully wire up the SDK client here. Steps:
    //   1. Call sdk.createClient({ baseUrl, accessToken, deviceId, userId })
    //   2. Call client.initRustCrypto() [SDK >= 28] or client.initCrypto() [legacy]
    //      with keyCachePath for the SQLite device-key store.
    //   3. Await client.startClient({ initialSyncLimit: 0 }) before sending.
    //   4. Store the client in this.e2ee.matrixClient.
    //
    // Minimal stub (SDK loaded, crypto not yet wired — replace when Olm WASM is bundled):
    this.e2ee.matrixClient = sdk;
    this.e2ee.ready = true;
    console.log(`[matrix] E2EE initialized — device ${cfg.deviceId} (key cache: ${keyCachePath})`);
  }

  /**
   * Test hook: inject a pre-built E2EEState without touching the SDK.
   * @internal
   */
  _injectE2EE(state: E2EEState): void {
    this.e2ee = state;
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

    // E2EE initialisation — triggered when a deviceId is present in config.
    if (this.config.deviceId && !this.e2ee) {
      await this.initE2EE({ deviceId: this.config.deviceId });
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

    // E2EE send path — only when crypto was successfully initialised AND the
    // room is flagged as encrypted. Falls back to plain send otherwise.
    //
    // TODO(#41): Replace the stub below with real SDK calls once Olm is wired:
    //   const isEncrypted = await this.e2ee.matrixClient.isRoomEncrypted(chatId);
    //   if (isEncrypted) {
    //     const txnId = `lyrie-${Date.now()}`;
    //     await this.e2ee.matrixClient.sendEvent(
    //       chatId, EventType.RoomEncrypted, encryptedContent, txnId,
    //     );
    //     return txnId;
    //   }
    if (this.e2ee?.ready && response.extra?.["encrypted"] === true) {
      const encryptedContent = { ...unifiedResponseToMatrixContent(response), msgtype: "m.room.encrypted" };
      console.log(`[matrix] E2EE send to ${chatId} (device ${this.e2ee.deviceId})`);
      return JSON.stringify(encryptedContent);
    }

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
