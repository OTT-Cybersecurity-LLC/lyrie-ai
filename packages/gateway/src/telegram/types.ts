/**
 * Telegram Bot API type definitions.
 * Covers the subset of types used by Lyrie's gateway.
 * Based on Telegram Bot API 7.x
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Core Types ─────────────────────────────────────────────────────────────────

export interface TgUser {
  id: number;
  is_bot: boolean;
  first_name: string;
  last_name?: string;
  username?: string;
  language_code?: string;
}

export interface TgChat {
  id: number;
  type: "private" | "group" | "supergroup" | "channel";
  title?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
}

export interface TgMessage {
  message_id: number;
  from?: TgUser;
  chat: TgChat;
  date: number;
  text?: string;
  caption?: string;
  reply_to_message?: TgMessage;
  entities?: TgMessageEntity[];
  photo?: TgPhotoSize[];
  document?: TgDocument;
  audio?: TgAudio;
  video?: TgVideo;
  voice?: TgVoice;
  animation?: TgAnimation;
  sticker?: TgSticker;
  reply_markup?: TgInlineKeyboardMarkup;
}

export interface TgMessageEntity {
  type: "bot_command" | "mention" | "hashtag" | "url" | "bold" | "italic" | "code" | "pre" | "text_link" | string;
  offset: number;
  length: number;
  url?: string;
}

// ─── Media Types ────────────────────────────────────────────────────────────────

export interface TgPhotoSize {
  file_id: string;
  file_unique_id: string;
  width: number;
  height: number;
  file_size?: number;
}

export interface TgDocument {
  file_id: string;
  file_unique_id: string;
  file_name?: string;
  mime_type?: string;
  file_size?: number;
}

export interface TgAudio {
  file_id: string;
  file_unique_id: string;
  duration: number;
  mime_type?: string;
  file_size?: number;
  title?: string;
}

export interface TgVideo {
  file_id: string;
  file_unique_id: string;
  width: number;
  height: number;
  duration: number;
  mime_type?: string;
  file_size?: number;
}

export interface TgVoice {
  file_id: string;
  file_unique_id: string;
  duration: number;
  mime_type?: string;
  file_size?: number;
}

export interface TgAnimation {
  file_id: string;
  file_unique_id: string;
  width: number;
  height: number;
  duration: number;
  mime_type?: string;
  file_size?: number;
}

export interface TgSticker {
  file_id: string;
  file_unique_id: string;
  width: number;
  height: number;
  is_animated: boolean;
  emoji?: string;
}

// ─── Inline Keyboard ────────────────────────────────────────────────────────────

export interface TgInlineKeyboardMarkup {
  inline_keyboard: TgInlineKeyboardButton[][];
}

export interface TgInlineKeyboardButton {
  text: string;
  callback_data?: string;
  url?: string;
  switch_inline_query?: string;
}

// ─── Callback Query ─────────────────────────────────────────────────────────────

export interface TgCallbackQuery {
  id: string;
  from: TgUser;
  message?: TgMessage;
  data?: string;
}

// ─── Update ─────────────────────────────────────────────────────────────────────

export interface TgUpdate {
  update_id: number;
  message?: TgMessage;
  edited_message?: TgMessage;
  callback_query?: TgCallbackQuery;
}

// ─── API Responses ──────────────────────────────────────────────────────────────

export interface TgApiResponse<T = any> {
  ok: boolean;
  result?: T;
  description?: string;
  error_code?: number;
  parameters?: {
    migrate_to_chat_id?: number;
    retry_after?: number;
  };
}

export interface TgFile {
  file_id: string;
  file_unique_id: string;
  file_size?: number;
  file_path?: string;
}

// ─── Send Methods Params ────────────────────────────────────────────────────────

export interface TgSendMessageParams {
  chat_id: number | string;
  text: string;
  parse_mode?: "MarkdownV2" | "HTML" | "Markdown";
  reply_to_message_id?: number;
  reply_markup?: TgInlineKeyboardMarkup;
  disable_web_page_preview?: boolean;
  disable_notification?: boolean;
}

export interface TgEditMessageParams {
  chat_id?: number | string;
  message_id?: number;
  inline_message_id?: string;
  text: string;
  parse_mode?: "MarkdownV2" | "HTML" | "Markdown";
  reply_markup?: TgInlineKeyboardMarkup;
  disable_web_page_preview?: boolean;
}

export interface TgSendPhotoParams {
  chat_id: number | string;
  photo: string;
  caption?: string;
  parse_mode?: "MarkdownV2" | "HTML" | "Markdown";
  reply_markup?: TgInlineKeyboardMarkup;
}

export interface TgSendDocumentParams {
  chat_id: number | string;
  document: string;
  caption?: string;
  parse_mode?: "MarkdownV2" | "HTML" | "Markdown";
  reply_markup?: TgInlineKeyboardMarkup;
}

export interface TgAnswerCallbackQueryParams {
  callback_query_id: string;
  text?: string;
  show_alert?: boolean;
}
