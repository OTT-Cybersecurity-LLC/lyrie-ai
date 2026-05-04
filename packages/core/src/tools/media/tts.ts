/**
 * tts — Text-to-speech built-in tool for Lyrie v1.2.
 *
 * Uses OpenAI TTS API (tts-1 model).
 * Default voice: "nova" (Guy's preference per TOOLS.md).
 * Returns audio file path.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { dirname, resolve, join } from "path";
import type { Tool } from "../tool-executor";

// ─── Types ───────────────────────────────────────────────────────────────────

export type TTSVoice = "nova" | "alloy" | "echo" | "fable" | "onyx" | "shimmer";

export interface TTSOptions {
  voice?: TTSVoice;
  outputPath?: string;
}

export interface TTSResult {
  filePath: string;
  voice: string;
  model: string;
  bytes: number;
}

// ─── TextToSpeech ─────────────────────────────────────────────────────────────

export class TextToSpeech {
  private openaiKey: string;

  constructor(openaiKey?: string) {
    this.openaiKey = openaiKey || process.env.OPENAI_API_KEY || "";
  }

  async synthesize(text: string, options: TTSOptions = {}): Promise<TTSResult> {
    if (!this.openaiKey) {
      throw new Error("OPENAI_API_KEY not set");
    }

    const voice: TTSVoice = options.voice ?? "nova"; // Guy's preferred voice
    const model = "tts-1";

    const res = await fetch("https://api.openai.com/v1/audio/speech", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.openaiKey}`,
      },
      body: JSON.stringify({
        model,
        input: text,
        voice,
        response_format: "mp3",
      }),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`OpenAI TTS error ${res.status}: ${errText}`);
    }

    const audioBuffer = Buffer.from(await res.arrayBuffer());

    // Determine output path
    const outputPath = options.outputPath
      ? resolve(options.outputPath)
      : join(
          process.env.HOME || "/tmp",
          ".lyrie",
          "tts",
          `tts_${Date.now().toString(36)}.mp3`
        );

    // Ensure directory exists
    const dir = dirname(outputPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    writeFileSync(outputPath, audioBuffer);

    return {
      filePath: outputPath,
      voice,
      model,
      bytes: audioBuffer.length,
    };
  }
}

// ─── Singleton ───────────────────────────────────────────────────────────────

let _tts: TextToSpeech | null = null;

export function getTTS(): TextToSpeech {
  if (!_tts) _tts = new TextToSpeech();
  return _tts;
}

/** For testing: inject custom TTS. */
export function setTTS(tts: TextToSpeech): void {
  _tts = tts;
}

// ─── Tool: tts ───────────────────────────────────────────────────────────────

export const ttsTool: Tool = {
  name: "tts",
  description:
    "Convert text to speech using OpenAI TTS. Returns audio file path. Default voice: nova.",
  parameters: {
    text: {
      type: "string",
      description: "Text to convert to speech",
      required: true,
    },
    voice: {
      type: "string",
      description:
        'Voice to use (default: nova): nova | alloy | echo | fable | onyx | shimmer',
      enum: ["nova", "alloy", "echo", "fable", "onyx", "shimmer"],
    },
    outputPath: {
      type: "string",
      description: "Optional file path to save the audio (e.g. /tmp/speech.mp3)",
    },
  },
  risk: "safe",
  execute: async (args) => {
    try {
      const tts = getTTS();
      const result = await tts.synthesize(args.text, {
        voice: args.voice as TTSVoice | undefined,
        outputPath: args.outputPath,
      });

      return {
        success: true,
        output: `Audio saved: ${result.filePath} (${result.bytes} bytes, voice=${result.voice})`,
        metadata: result,
      };
    } catch (err: any) {
      return { success: false, output: "", error: `tts failed: ${err.message}` };
    }
  },
};
