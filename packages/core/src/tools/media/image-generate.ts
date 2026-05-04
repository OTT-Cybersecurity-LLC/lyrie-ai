/**
 * image_generate — Lyrie v1.2 built-in tool.
 *
 * Smart image generation:
 *   ✅ Auto-routes to local Stable Diffusion on H200 when available
 *   ✅ Falls back to OpenAI DALL-E 3 if local SD is unreachable
 *   ✅ Returns unified ImageResult regardless of provider
 *   ✅ Optional save-to-disk via outputPath
 *
 * Local SD endpoint: ssh -p 38084 root@210.157.233.86
 * (The H200 runs an A1111/AUTOMATIC1111 or ComfyUI compatible API on port 7860)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { dirname, resolve } from "path";
import type { Tool } from "../tool-executor";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ImageProvider = "openai" | "local" | "auto";
export type ImageSize = "1024x1024" | "1792x1024" | "1024x1792";
export type ImageQuality = "standard" | "hd";

export interface ImageOptions {
  size?: ImageSize;
  quality?: ImageQuality;
  provider?: ImageProvider;
  outputPath?: string;
}

export interface ImageResult {
  url?: string;
  filePath?: string;
  base64?: string;
  provider: string;
  revisedPrompt?: string;
  error?: string;
}

// ─── Local SD config ─────────────────────────────────────────────────────────

/** H200 SD API endpoint (A1111 compatible). Adjust port if needed. */
const LOCAL_SD_URL =
  process.env.LYRIE_SD_URL || "http://210.157.233.86:7860";

const LOCAL_SD_TIMEOUT_MS = 5_000; // 5s availability check; generation itself may take longer

// ─── ImageGenerator ──────────────────────────────────────────────────────────

export class ImageGenerator {
  private openaiKey: string;

  constructor(openaiKey?: string) {
    // When explicitly passed (even ""), use it. Only fall back to env when omitted.
    this.openaiKey = openaiKey !== undefined ? openaiKey : (process.env.OPENAI_API_KEY || "");
  }

  /** Check if a provider is reachable. */
  async isAvailable(provider: "openai" | "local"): Promise<boolean> {
    if (provider === "openai") {
      return !!this.openaiKey;
    }

    if (provider === "local") {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), LOCAL_SD_TIMEOUT_MS);
        const res = await fetch(`${LOCAL_SD_URL}/sdapi/v1/options`, {
          signal: controller.signal,
        });
        clearTimeout(timer);
        return res.ok;
      } catch {
        return false;
      }
    }

    return false;
  }

  /** Generate an image. Auto-routes: local SD first, then OpenAI. */
  async generate(prompt: string, options: ImageOptions = {}): Promise<ImageResult> {
    const requestedProvider = options.provider ?? "auto";

    // Resolve effective provider
    let effectiveProvider: "openai" | "local";
    if (requestedProvider === "local") {
      effectiveProvider = "local";
    } else if (requestedProvider === "openai") {
      effectiveProvider = "openai";
    } else {
      // auto: prefer local (faster, free) if reachable
      effectiveProvider = (await this.isAvailable("local")) ? "local" : "openai";
    }

    let result: ImageResult;
    if (effectiveProvider === "local") {
      result = await this.generateLocal(prompt, options);
      // Fallback to OpenAI if local fails
      if (result.error && requestedProvider === "auto") {
        result = await this.generateOpenAI(prompt, options);
      }
    } else {
      result = await this.generateOpenAI(prompt, options);
    }

    // Save to disk if outputPath specified
    if (options.outputPath && !result.error) {
      const resolved = resolve(options.outputPath);
      const dir = dirname(resolved);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

      if (result.base64) {
        const buf = Buffer.from(result.base64, "base64");
        writeFileSync(resolved, buf);
        result.filePath = resolved;
      } else if (result.url) {
        // Download and save
        try {
          const res = await fetch(result.url);
          if (res.ok) {
            const buf = Buffer.from(await res.arrayBuffer());
            writeFileSync(resolved, buf);
            result.filePath = resolved;
          }
        } catch {
          // Non-fatal: URL still usable
        }
      }
    }

    return result;
  }

  // ─── OpenAI DALL-E 3 ───────────────────────────────────────────────────

  private async generateOpenAI(prompt: string, options: ImageOptions): Promise<ImageResult> {
    if (!this.openaiKey) {
      return {
        provider: "openai",
        error: "OPENAI_API_KEY not set",
      };
    }

    const body = {
      model: "dall-e-3",
      prompt,
      n: 1,
      size: options.size ?? "1024x1024",
      quality: options.quality ?? "standard",
      response_format: "url",
    };

    try {
      const res = await fetch("https://api.openai.com/v1/images/generations", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.openaiKey}`,
        },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.text();
        return { provider: "openai", error: `OpenAI API error ${res.status}: ${err}` };
      }

      const data = (await res.json()) as any;
      const item = data.data?.[0];
      return {
        provider: "openai",
        url: item?.url,
        revisedPrompt: item?.revised_prompt,
      };
    } catch (err: any) {
      return { provider: "openai", error: `OpenAI fetch failed: ${err.message}` };
    }
  }

  // ─── Local Stable Diffusion (A1111 compatible API) ─────────────────────

  private async generateLocal(prompt: string, options: ImageOptions): Promise<ImageResult> {
    const [w, h] = (options.size ?? "1024x1024").split("x").map(Number);

    const body = {
      prompt,
      negative_prompt: "low quality, blurry, deformed",
      width: w,
      height: h,
      steps: options.quality === "hd" ? 50 : 30,
      cfg_scale: 7,
      sampler_name: "DPM++ 2M Karras",
    };

    try {
      const controller = new AbortController();
      // Generation can take up to 120s for HD
      const timer = setTimeout(() => controller.abort(), 120_000);

      const res = await fetch(`${LOCAL_SD_URL}/sdapi/v1/txt2img`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!res.ok) {
        const err = await res.text();
        return { provider: "local", error: `Local SD error ${res.status}: ${err}` };
      }

      const data = (await res.json()) as any;
      const base64 = data.images?.[0];
      if (!base64) {
        return { provider: "local", error: "Local SD returned no image data" };
      }

      return {
        provider: "local",
        base64,
      };
    } catch (err: any) {
      return { provider: "local", error: `Local SD failed: ${err.message}` };
    }
  }
}

// ─── Singleton ───────────────────────────────────────────────────────────────

let _generator: ImageGenerator | null = null;

export function getImageGenerator(): ImageGenerator {
  if (!_generator) _generator = new ImageGenerator();
  return _generator;
}

/** For testing: inject a custom generator. */
export function setImageGenerator(gen: ImageGenerator): void {
  _generator = gen;
}

// ─── Tool: image_generate ─────────────────────────────────────────────────────

export const imageGenerateTool: Tool = {
  name: "image_generate",
  description:
    "Generate an image from a text prompt. Auto-routes to local Stable Diffusion on the H200 GPU server when available, falls back to OpenAI DALL-E 3. Returns URL or base64.",
  parameters: {
    prompt: {
      type: "string",
      description: "Image generation prompt",
      required: true,
    },
    size: {
      type: "string",
      description: 'Image size: "1024x1024" | "1792x1024" | "1024x1792" (default: 1024x1024)',
      enum: ["1024x1024", "1792x1024", "1024x1792"],
    },
    quality: {
      type: "string",
      description: '"standard" | "hd" (default: standard)',
      enum: ["standard", "hd"],
    },
    provider: {
      type: "string",
      description: '"openai" | "local" | "auto" (default: auto — local SD preferred)',
      enum: ["openai", "local", "auto"],
    },
    outputPath: {
      type: "string",
      description: "Optional file path to save the image (e.g. /tmp/output.png)",
    },
  },
  risk: "safe",
  execute: async (args) => {
    try {
      const gen = getImageGenerator();
      const result = await gen.generate(args.prompt, {
        size: args.size as ImageSize | undefined,
        quality: args.quality as ImageQuality | undefined,
        provider: args.provider as ImageProvider | undefined,
        outputPath: args.outputPath,
      });

      if (result.error) {
        return { success: false, output: "", error: result.error, metadata: { provider: result.provider } };
      }

      const lines: string[] = [`provider: ${result.provider}`];
      if (result.url) lines.push(`url: ${result.url}`);
      if (result.filePath) lines.push(`saved: ${result.filePath}`);
      if (result.base64) lines.push(`base64: [${result.base64.length} chars]`);
      if (result.revisedPrompt) lines.push(`revised_prompt: ${result.revisedPrompt}`);

      return {
        success: true,
        output: lines.join("\n"),
        metadata: result,
      };
    } catch (err: any) {
      return { success: false, output: "", error: `image_generate failed: ${err.message}` };
    }
  },
};
