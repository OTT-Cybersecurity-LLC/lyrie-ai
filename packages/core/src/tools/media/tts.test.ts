/**
 * tts.test.ts — mocked tests for TextToSpeech and ttsTool.
 */

import { expect, test, describe, beforeEach } from "bun:test";
import { existsSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  TextToSpeech,
  setTTS,
  ttsTool,
  type TTSOptions,
  type TTSResult,
} from "./tts";

// ─── Mock TextToSpeech ────────────────────────────────────────────────────────

class MockTTS extends TextToSpeech {
  lastText: string = "";
  lastOptions: TTSOptions = {};
  shouldFail: boolean = false;
  fakeBytes: number = 1024;

  constructor() {
    super("test-openai-key-mock");
  }

  async synthesize(text: string, options: TTSOptions = {}): Promise<TTSResult> {
    this.lastText = text;
    this.lastOptions = options;

    if (this.shouldFail) {
      throw new Error("Mock TTS API failure");
    }

    const voice = options.voice ?? "nova";
    const outputPath =
      options.outputPath ??
      join(tmpdir(), `tts_mock_${Date.now().toString(36)}.mp3`);

    // Write fake audio bytes so file exists
    const { writeFileSync, mkdirSync, existsSync } = await import("fs");
    const { dirname } = await import("path");
    const dir = dirname(outputPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(outputPath, Buffer.alloc(this.fakeBytes));

    return {
      filePath: outputPath,
      voice,
      model: "tts-1",
      bytes: this.fakeBytes,
    };
  }
}

describe("MockTTS.synthesize()", () => {
  test("returns TTSResult with filePath", async () => {
    const tts = new MockTTS();
    const result = await tts.synthesize("Hello world");
    expect(result.filePath).toBeDefined();
    expect(result.filePath).toMatch(/\.mp3$/);
  });

  test("defaults voice to 'nova'", async () => {
    const tts = new MockTTS();
    const result = await tts.synthesize("Hello");
    expect(result.voice).toBe("nova");
  });

  test("uses specified voice", async () => {
    const tts = new MockTTS();
    const result = await tts.synthesize("Hello", { voice: "onyx" });
    expect(result.voice).toBe("onyx");
  });

  test("uses all valid voices", async () => {
    const voices = ["nova", "alloy", "echo", "fable", "onyx", "shimmer"] as const;
    const tts = new MockTTS();
    for (const voice of voices) {
      const result = await tts.synthesize("test", { voice });
      expect(result.voice).toBe(voice);
    }
  });

  test("constructs correct model name", async () => {
    const tts = new MockTTS();
    const result = await tts.synthesize("test");
    expect(result.model).toBe("tts-1");
  });

  test("returns byte count", async () => {
    const tts = new MockTTS();
    tts.fakeBytes = 4096;
    const result = await tts.synthesize("test");
    expect(result.bytes).toBe(4096);
  });

  test("saves to custom outputPath", async () => {
    const tts = new MockTTS();
    const outPath = join(tmpdir(), `test_tts_custom_${Date.now()}.mp3`);
    const result = await tts.synthesize("test", { outputPath: outPath });
    expect(result.filePath).toBe(outPath);
    expect(existsSync(outPath)).toBe(true);
    try { unlinkSync(outPath); } catch {}
  });

  test("captures text passed to synthesize", async () => {
    const tts = new MockTTS();
    await tts.synthesize("The quick brown fox");
    expect(tts.lastText).toBe("The quick brown fox");
  });

  test("throws when shouldFail=true", async () => {
    const tts = new MockTTS();
    tts.shouldFail = true;
    expect(tts.synthesize("fail")).rejects.toThrow("Mock TTS API failure");
  });
});

describe("ttsTool.execute()", () => {
  beforeEach(() => {
    setTTS(new MockTTS());
  });

  test("succeeds with text", async () => {
    const result = await ttsTool.execute({ text: "Hello Lyrie" });
    expect(result.success).toBe(true);
    expect(result.output).toMatch(/Audio saved:/);
  });

  test("output includes file path", async () => {
    const result = await ttsTool.execute({ text: "Test output" });
    expect(result.output).toMatch(/\.mp3/);
  });

  test("output includes voice=nova by default", async () => {
    const result = await ttsTool.execute({ text: "Default voice" });
    expect(result.output).toMatch(/voice=nova/);
  });

  test("output includes byte count", async () => {
    const result = await ttsTool.execute({ text: "Byte count test" });
    expect(result.output).toMatch(/bytes/);
  });

  test("returns failure when TTS throws", async () => {
    const mock = new MockTTS();
    mock.shouldFail = true;
    setTTS(mock);
    const result = await ttsTool.execute({ text: "fail test" });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/tts failed/);
  });

  test("passes voice parameter", async () => {
    const mock = new MockTTS();
    setTTS(mock);
    await ttsTool.execute({ text: "voice test", voice: "onyx" });
    expect(mock.lastOptions.voice).toBe("onyx");
  });

  test("passes outputPath parameter", async () => {
    const mock = new MockTTS();
    setTTS(mock);
    const outPath = "/tmp/test_tts_output.mp3";
    await ttsTool.execute({ text: "path test", outputPath: outPath });
    expect(mock.lastOptions.outputPath).toBe(outPath);
  });

  test("metadata includes filePath and voice", async () => {
    const result = await ttsTool.execute({ text: "meta test" });
    expect(result.metadata?.filePath).toBeDefined();
    expect(result.metadata?.voice).toBe("nova");
  });
});
