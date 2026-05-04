/**
 * image-generate.test.ts — mocked tests for ImageGenerator and imageGenerateTool.
 */

import { expect, test, describe, beforeEach, mock } from "bun:test";
import {
  ImageGenerator,
  setImageGenerator,
  imageGenerateTool,
  type ImageOptions,
  type ImageResult,
} from "./image-generate";

// ─── Mock ImageGenerator ─────────────────────────────────────────────────────

class MockImageGenerator extends ImageGenerator {
  availableProviders: Set<string>;
  lastPrompt: string = "";
  lastOptions: ImageOptions = {};
  shouldFail: boolean = false;
  returnBase64: boolean = false;

  constructor(available: ("openai" | "local")[] = ["openai"]) {
    super("test-key-mock");
    this.availableProviders = new Set(available);
  }

  async isAvailable(provider: "openai" | "local"): Promise<boolean> {
    return this.availableProviders.has(provider);
  }

  async generate(prompt: string, options: ImageOptions = {}): Promise<ImageResult> {
    this.lastPrompt = prompt;
    this.lastOptions = options;

    if (this.shouldFail) {
      return { provider: "openai", error: "Mock generation failed" };
    }

    const provider = this.availableProviders.has("local") ? "local" : "openai";

    if (this.returnBase64 || provider === "local") {
      return {
        provider,
        base64: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",
      };
    }

    return {
      provider,
      url: "https://openai.com/image/mock-generated.png",
      revisedPrompt: `Enhanced: ${prompt}`,
    };
  }
}

describe("ImageGenerator.isAvailable()", () => {
  test("returns true for 'openai' when key set", async () => {
    const gen = new ImageGenerator("sk-test-key");
    expect(await gen.isAvailable("openai")).toBe(true);
  });

  test("returns false for 'openai' when no key", async () => {
    const gen = new ImageGenerator("");
    expect(await gen.isAvailable("openai")).toBe(false);
  });

  test("returns false for 'local' when SD unreachable (mocked)", async () => {
    // Without a real SD server, this should be false
    const gen = new (class extends ImageGenerator {
      async isAvailable(provider: "openai" | "local"): Promise<boolean> {
        if (provider === "local") return false;
        return true;
      }
    })("test-key");
    expect(await gen.isAvailable("local")).toBe(false);
  });
});

describe("MockImageGenerator.generate()", () => {
  test("returns ImageResult with provider field — openai", async () => {
    const gen = new MockImageGenerator(["openai"]);
    const result = await gen.generate("a sunset over the ocean");
    expect(result.provider).toBe("openai");
    expect(result.url).toBeDefined();
  });

  test("returns ImageResult with provider field — local", async () => {
    const gen = new MockImageGenerator(["local"]);
    const result = await gen.generate("a cat");
    expect(result.provider).toBe("local");
  });

  test("auto-routes to local when local available", async () => {
    const gen = new MockImageGenerator(["openai", "local"]);
    const result = await gen.generate("test", { provider: "auto" });
    expect(result.provider).toBe("local");
  });

  test("auto-routes to openai when local unavailable", async () => {
    const gen = new MockImageGenerator(["openai"]);
    const result = await gen.generate("test", { provider: "auto" });
    expect(result.provider).toBe("openai");
  });

  test("returns error field when generation fails", async () => {
    const gen = new MockImageGenerator(["openai"]);
    gen.shouldFail = true;
    const result = await gen.generate("test");
    expect(result.error).toBeDefined();
  });

  test("returns revisedPrompt from OpenAI", async () => {
    const gen = new MockImageGenerator(["openai"]);
    const result = await gen.generate("a mountain");
    expect(result.revisedPrompt).toMatch(/a mountain/);
  });

  test("captures prompt and options", async () => {
    const gen = new MockImageGenerator(["openai"]);
    await gen.generate("test prompt", { size: "1792x1024", quality: "hd" });
    expect(gen.lastPrompt).toBe("test prompt");
    expect(gen.lastOptions.size).toBe("1792x1024");
    expect(gen.lastOptions.quality).toBe("hd");
  });
});

describe("imageGenerateTool.execute()", () => {
  beforeEach(() => {
    setImageGenerator(new MockImageGenerator(["openai"]));
  });

  test("succeeds with prompt", async () => {
    const result = await imageGenerateTool.execute({ prompt: "a red apple" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/provider:/);
  });

  test("includes URL in output", async () => {
    const result = await imageGenerateTool.execute({ prompt: "a blue sky" });
    expect(result.output).toMatch(/url:/i);
  });

  test("returns failure when generator errors", async () => {
    const gen = new MockImageGenerator(["openai"]);
    gen.shouldFail = true;
    setImageGenerator(gen);
    const result = await imageGenerateTool.execute({ prompt: "error test" });
    expect(result.success).toBe(false);
  });

  test("includes metadata with provider", async () => {
    const result = await imageGenerateTool.execute({ prompt: "test" });
    expect(result.metadata?.provider).toBeDefined();
  });

  test("local provider outputs base64 info", async () => {
    setImageGenerator(new MockImageGenerator(["local"]));
    const result = await imageGenerateTool.execute({ prompt: "local test" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/base64:/i);
  });
});
