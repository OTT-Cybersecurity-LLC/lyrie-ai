/**
 * Telegram Media Processor — Download, transcribe, and describe media.
 *
 * Handles:
 * - Voice/audio → OpenAI Whisper transcription
 * - Photos/images → Anthropic Claude Vision description
 * - Video → frame extraction + vision description
 * - Documents → text extraction or vision description
 *
 * Zero external dependencies. Uses native fetch (Bun/Node 18+).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { MediaAttachment } from "../common/types";

// ─── Constants ──────────────────────────────────────────────────────────────────

const TG_API_BASE = "https://api.telegram.org";
const OPENAI_API_BASE = "https://api.openai.com/v1";
const ANTHROPIC_API_BASE = "https://api.anthropic.com/v1";

const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB Telegram limit
const VISION_MAX_TOKENS = 1024;

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface MediaProcessorConfig {
  telegramToken: string;
  openaiApiKey?: string;
  anthropicApiKey?: string;
}

export interface MediaProcessingResult {
  /** Processed text to prepend to the message */
  text: string;
  /** Type of processing performed */
  type: "transcription" | "image_description" | "video_description" | "document_content";
  /** Whether processing succeeded */
  success: boolean;
  /** Error message if failed */
  error?: string;
}

// ─── Media Processor ────────────────────────────────────────────────────────────

export class MediaProcessor {
  private config: MediaProcessorConfig;

  constructor(config: MediaProcessorConfig) {
    this.config = config;
  }

  // ── Main Entry Point ────────────────────────────────────────────────────────

  /**
   * Process all media attachments in a message.
   * Returns processed text to prepend to the user's message.
   */
  async processAttachments(
    attachments: MediaAttachment[],
    caption?: string,
  ): Promise<MediaProcessingResult[]> {
    const results: MediaProcessingResult[] = [];

    for (const attachment of attachments) {
      try {
        const result = await this.processOne(attachment, caption);
        results.push(result);
      } catch (err: any) {
        results.push({
          text: `[Media processing failed: ${err.message}]`,
          type: "transcription",
          success: false,
          error: err.message,
        });
      }
    }

    return results;
  }

  /**
   * Process a single media attachment.
   */
  private async processOne(
    attachment: MediaAttachment,
    caption?: string,
  ): Promise<MediaProcessingResult> {
    switch (attachment.type) {
      case "voice":
      case "audio":
        return this.processAudio(attachment);

      case "photo":
        return this.processImage(attachment, caption);

      case "video":
      case "animation":
        return this.processVideo(attachment, caption);

      case "document":
        return this.processDocument(attachment, caption);

      case "sticker":
        return {
          text: "[Sticker received]",
          type: "image_description",
          success: true,
        };

      default:
        return {
          text: `[Unsupported media type: ${attachment.type}]`,
          type: "document_content",
          success: false,
          error: `Unsupported type: ${attachment.type}`,
        };
    }
  }

  // ── File Download ───────────────────────────────────────────────────────────

  /**
   * Download a file from Telegram servers.
   * Uses getFile API to get file_path, then downloads from file endpoint.
   */
  async downloadFile(fileId: string): Promise<Buffer> {
    // Step 1: Get file path
    const fileInfo = await this.tgApi<{ file_id: string; file_path: string; file_size?: number }>(
      "getFile",
      { file_id: fileId },
    );

    if (!fileInfo?.file_path) {
      throw new Error("Failed to get file path from Telegram");
    }

    // Check file size
    if (fileInfo.file_size && fileInfo.file_size > MAX_FILE_SIZE) {
      throw new Error(`File too large: ${(fileInfo.file_size / 1024 / 1024).toFixed(1)}MB (max 20MB)`);
    }

    // Step 2: Download the file
    const fileUrl = `${TG_API_BASE}/file/bot${this.config.telegramToken}/${fileInfo.file_path}`;
    const response = await fetch(fileUrl);

    if (!response.ok) {
      throw new Error(`Failed to download file: HTTP ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  // ── Voice/Audio Processing ──────────────────────────────────────────────────

  /**
   * Download audio → transcribe with OpenAI Whisper.
   */
  private async processAudio(attachment: MediaAttachment): Promise<MediaProcessingResult> {
    if (!this.config.openaiApiKey) {
      return {
        text: "[Voice message received but transcription unavailable — no OpenAI API key]",
        type: "transcription",
        success: false,
        error: "Missing OPENAI_API_KEY",
      };
    }

    const audioBuffer = await this.downloadFile(attachment.fileId);
    const transcription = await this.transcribeVoice(audioBuffer, attachment.mimeType);

    return {
      text: `[Voice message transcription]: ${transcription}`,
      type: "transcription",
      success: true,
    };
  }

  /**
   * Transcribe audio using OpenAI Whisper API.
   */
  async transcribeVoice(audioBuffer: Buffer, mimeType?: string): Promise<string> {
    // Determine file extension from MIME type
    const ext = this.mimeToExtension(mimeType || "audio/ogg");

    // Build multipart form data
    const boundary = `----LyrieMediaBoundary${Date.now()}`;
    const filename = `voice.${ext}`;

    const formParts: Buffer[] = [];

    // File field
    formParts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: ${mimeType || "audio/ogg"}\r\n\r\n`,
      ),
    );
    formParts.push(audioBuffer);
    formParts.push(Buffer.from("\r\n"));

    // Model field
    formParts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\nwhisper-1\r\n`,
      ),
    );

    // Language hint (optional, helps accuracy)
    formParts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="response_format"\r\n\r\ntext\r\n`,
      ),
    );

    // End boundary
    formParts.push(Buffer.from(`--${boundary}--\r\n`));

    const body = Buffer.concat(formParts);

    const response = await fetch(`${OPENAI_API_BASE}/audio/transcriptions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.config.openaiApiKey}`,
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
      },
      body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Whisper API error ${response.status}: ${errorText}`);
    }

    const transcription = await response.text();
    return transcription.trim() || "[Empty transcription]";
  }

  // ── Image Processing ────────────────────────────────────────────────────────

  /**
   * Download image → describe with Anthropic Claude Vision.
   */
  private async processImage(
    attachment: MediaAttachment,
    caption?: string,
  ): Promise<MediaProcessingResult> {
    if (!this.config.anthropicApiKey) {
      return {
        text: "[Image received but description unavailable — no Anthropic API key]",
        type: "image_description",
        success: false,
        error: "Missing ANTHROPIC_API_KEY",
      };
    }

    const imageBuffer = await this.downloadFile(attachment.fileId);
    const description = await this.describeImage(imageBuffer, attachment.mimeType);

    const captionPart = caption ? ` User caption: "${caption}"` : "";
    return {
      text: `[Image received]: ${description}.${captionPart}`,
      type: "image_description",
      success: true,
    };
  }

  /**
   * Describe an image using Anthropic Claude Vision API.
   */
  async describeImage(imageBuffer: Buffer, mimeType?: string): Promise<string> {
    const base64 = imageBuffer.toString("base64");
    const mediaType = this.normalizeImageMime(mimeType || "image/jpeg");

    const response = await fetch(`${ANTHROPIC_API_BASE}/messages`, {
      method: "POST",
      headers: {
        "x-api-key": this.config.anthropicApiKey!,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: VISION_MAX_TOKENS,
        messages: [
          {
            role: "user",
            content: [
              {
                type: "image",
                source: {
                  type: "base64",
                  media_type: mediaType,
                  data: base64,
                },
              },
              {
                type: "text",
                text: "Describe this image concisely but thoroughly. Include: what you see, any text visible, notable details, and the overall context or purpose of the image. Be factual and specific.",
              },
            ],
          },
        ],
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Anthropic Vision error ${response.status}: ${errorText}`);
    }

    const data = await response.json() as {
      content: Array<{ type: string; text?: string }>;
    };

    const textBlock = data.content?.find((b) => b.type === "text");
    return textBlock?.text?.trim() || "[Could not describe image]";
  }

  // ── Video Processing ────────────────────────────────────────────────────────

  /**
   * Download video → describe with vision.
   * Since we can't easily extract frames in pure TS without ffmpeg,
   * we check if the video has a thumbnail, or send the video as-is
   * to vision if small enough.
   */
  private async processVideo(
    attachment: MediaAttachment,
    caption?: string,
  ): Promise<MediaProcessingResult> {
    if (!this.config.anthropicApiKey) {
      return {
        text: "[Video received but description unavailable — no Anthropic API key]",
        type: "video_description",
        success: false,
        error: "Missing ANTHROPIC_API_KEY",
      };
    }

    // Download the video
    const videoBuffer = await this.downloadFile(attachment.fileId);

    // For short videos/GIFs, try to describe the first frame
    // We'll extract a thumbnail by sending to vision with a note about it being video
    const description = await this.describeVideoFrame(videoBuffer, attachment.mimeType);

    const captionPart = caption ? ` User caption: "${caption}"` : "";
    return {
      text: `[Video received]: ${description}.${captionPart}`,
      type: "video_description",
      success: true,
    };
  }

  /**
   * Describe a video by extracting and analyzing its first frame.
   * Uses ffmpeg if available, falls back to sending raw bytes for small files.
   */
  async describeVideoFrame(videoBuffer: Buffer, mimeType?: string): Promise<string> {
    // Try to extract first frame with ffmpeg
    try {
      const frameBuffer = await this.extractFirstFrame(videoBuffer);
      if (frameBuffer) {
        return this.describeImage(frameBuffer, "image/jpeg");
      }
    } catch {
      // ffmpeg not available, fall through
    }

    // Fallback: if the file is small enough and is a GIF, send it as image
    if (
      mimeType === "image/gif" ||
      mimeType?.includes("gif")
    ) {
      if (videoBuffer.length < 5 * 1024 * 1024) {
        return this.describeImage(videoBuffer, "image/gif");
      }
    }

    return "Video received (frame extraction unavailable — install ffmpeg for video analysis)";
  }

  /**
   * Extract the first frame of a video using ffmpeg.
   * Returns JPEG buffer or null if ffmpeg is not available.
   */
  private async extractFirstFrame(videoBuffer: Buffer): Promise<Buffer | null> {
    // Use Bun.spawn or child_process
    const { execSync } = await import("child_process");
    const { writeFileSync, readFileSync, unlinkSync, existsSync } = await import("fs");
    const { tmpdir } = await import("os");
    const { join } = await import("path");

    const tmpIn = join(tmpdir(), `lyrie_vid_${Date.now()}.mp4`);
    const tmpOut = join(tmpdir(), `lyrie_frame_${Date.now()}.jpg`);

    try {
      writeFileSync(tmpIn, videoBuffer);

      execSync(
        `ffmpeg -i "${tmpIn}" -vframes 1 -f image2 -q:v 2 "${tmpOut}" -y 2>/dev/null`,
        { timeout: 10000 },
      );

      if (existsSync(tmpOut)) {
        const frame = readFileSync(tmpOut);
        return frame;
      }
      return null;
    } catch {
      return null;
    } finally {
      // Clean up temp files
      try { unlinkSync(tmpIn); } catch {}
      try { unlinkSync(tmpOut); } catch {}
    }
  }

  // ── Document Processing ─────────────────────────────────────────────────────

  /**
   * Process document based on its MIME type.
   */
  private async processDocument(
    attachment: MediaAttachment,
    caption?: string,
  ): Promise<MediaProcessingResult> {
    const mime = attachment.mimeType || "";
    const filename = attachment.filename || "unknown";

    // Image documents
    if (mime.startsWith("image/")) {
      return this.processImage(attachment, caption);
    }

    // Text/code documents
    if (
      mime.startsWith("text/") ||
      mime === "application/json" ||
      mime === "application/xml" ||
      mime === "application/javascript" ||
      mime === "application/typescript" ||
      mime === "application/x-yaml" ||
      mime === "application/x-python" ||
      mime === "application/x-sh" ||
      filename.match(/\.(txt|md|json|yaml|yml|xml|csv|log|py|js|ts|sh|bash|rs|go|java|c|cpp|h|hpp|toml|ini|cfg|env|html|css|sql)$/i)
    ) {
      return this.processTextDocument(attachment, caption);
    }

    // PDF
    if (mime === "application/pdf") {
      return {
        text: `[PDF document received: "${filename}"]${caption ? ` Caption: "${caption}"` : ""}`,
        type: "document_content",
        success: true,
      };
    }

    // Audio files sent as documents
    if (mime.startsWith("audio/")) {
      return this.processAudio(attachment);
    }

    // Video files sent as documents
    if (mime.startsWith("video/")) {
      return this.processVideo(attachment, caption);
    }

    return {
      text: `[Document received: "${filename}" (${mime || "unknown type"})]${caption ? ` Caption: "${caption}"` : ""}`,
      type: "document_content",
      success: true,
    };
  }

  /**
   * Download and read a text/code document.
   */
  private async processTextDocument(
    attachment: MediaAttachment,
    caption?: string,
  ): Promise<MediaProcessingResult> {
    const buffer = await this.downloadFile(attachment.fileId);
    const text = buffer.toString("utf-8");
    const filename = attachment.filename || "document";

    // Truncate very large files
    const maxChars = 8000;
    const truncated = text.length > maxChars;
    const content = truncated ? text.substring(0, maxChars) + "\n... [truncated]" : text;

    const captionPart = caption ? ` Caption: "${caption}"` : "";
    return {
      text: `[Document "${filename}" content]:\n\`\`\`\n${content}\n\`\`\`${captionPart}`,
      type: "document_content",
      success: true,
    };
  }

  // ── Telegram API Helper ─────────────────────────────────────────────────────

  private async tgApi<T>(method: string, params?: Record<string, any>): Promise<T | null> {
    const url = `${TG_API_BASE}/bot${this.config.telegramToken}/${method}`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: params ? JSON.stringify(params) : undefined,
    });

    const data = await response.json() as { ok: boolean; result?: T; description?: string };
    if (!data.ok) {
      throw new Error(`Telegram API ${method}: ${data.description || "Unknown error"}`);
    }

    return data.result ?? null;
  }

  // ── Utilities ───────────────────────────────────────────────────────────────

  private mimeToExtension(mime: string): string {
    const map: Record<string, string> = {
      "audio/ogg": "ogg",
      "audio/mpeg": "mp3",
      "audio/mp3": "mp3",
      "audio/mp4": "m4a",
      "audio/wav": "wav",
      "audio/webm": "webm",
      "audio/x-m4a": "m4a",
      "audio/aac": "aac",
      "audio/flac": "flac",
      "video/mp4": "mp4",
      "video/webm": "webm",
    };
    return map[mime] || "ogg";
  }

  private normalizeImageMime(
    mime: string,
  ): "image/jpeg" | "image/png" | "image/gif" | "image/webp" {
    if (mime.includes("png")) return "image/png";
    if (mime.includes("gif")) return "image/gif";
    if (mime.includes("webp")) return "image/webp";
    return "image/jpeg";
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────────

/**
 * Build the enriched message text from media processing results.
 */
export function buildMediaEnrichedText(
  results: MediaProcessingResult[],
  originalText: string,
): string {
  const mediaTexts = results
    .filter((r) => r.text)
    .map((r) => r.text);

  if (mediaTexts.length === 0) return originalText;

  // If there's original text, append it after media descriptions
  if (originalText.trim()) {
    return [...mediaTexts, originalText].join("\n\n");
  }

  return mediaTexts.join("\n\n");
}
