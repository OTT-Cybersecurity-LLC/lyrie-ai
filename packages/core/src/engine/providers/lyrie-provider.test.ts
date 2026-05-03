/**
 * LyrieProvider Independence Layer — tests
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  LyrieProviderRegistry,
  ExternalCallBlocked,
  assertProviderAllowed,
  bootstrapLyrieProviders,
  OllamaLyrieProvider,
  LMStudioProvider,
  HermesProvider,
} from "./index";
import type { LyrieProvider } from "./lyrie-provider";

const fakeLocal: LyrieProvider = {
  id: "fakelocal",
  name: "Fake Local",
  endpoint: "http://localhost:9999",
  models: ["m1"],
  defaultModel: "m1",
  isLocal: true,
  supportsToolUse: true,
  supportsFunctionCalling: true,
  maxContextTokens: 8192,
  async complete() {
    return {
      content: "ok",
      toolCalls: [],
      stopReason: "stop",
      model: "m1",
      usage: { promptTokens: 1, completionTokens: 1, totalTokens: 2 },
    };
  },
};

const fakeRemote: LyrieProvider = {
  ...fakeLocal,
  id: "fakeremote",
  name: "Fake Remote",
  endpoint: "https://api.example.com",
  isLocal: false,
};

describe("LyrieProviderRegistry", () => {
  test("registers and retrieves providers by id", () => {
    const r = new LyrieProviderRegistry();
    r.register(fakeLocal);
    expect(r.has("fakelocal")).toBe(true);
    expect(r.get("fakelocal")?.id).toBe("fakelocal");
  });

  test("listLocal returns only local providers", () => {
    const r = new LyrieProviderRegistry();
    r.register(fakeLocal);
    r.register(fakeRemote);
    const locals = r.listLocal();
    expect(locals.length).toBe(1);
    expect(locals[0].id).toBe("fakelocal");
  });

  test("bootstrap creates Ollama + LM Studio + Hermes by default", () => {
    const r = bootstrapLyrieProviders();
    expect(r.has("ollama")).toBe(true);
    expect(r.has("lmstudio")).toBe(true);
    expect(r.has("hermes")).toBe(true);
    // All three are local by construction
    expect(r.listLocal().length).toBeGreaterThanOrEqual(3);
  });

  test("bootstrap honors opt-out flags", () => {
    const r = bootstrapLyrieProviders({ lmstudio: false, hermes: false });
    expect(r.has("ollama")).toBe(true);
    expect(r.has("lmstudio")).toBe(false);
    expect(r.has("hermes")).toBe(false);
  });
});

describe("ExternalCallBlocked guard", () => {
  test("allows local provider when requireLocalProvider=true", () => {
    expect(() => assertProviderAllowed(fakeLocal, true)).not.toThrow();
  });

  test("blocks non-local provider when requireLocalProvider=true", () => {
    expect(() => assertProviderAllowed(fakeRemote, true)).toThrow(ExternalCallBlocked);
  });

  test("allows non-local provider when requireLocalProvider=false", () => {
    expect(() => assertProviderAllowed(fakeRemote, false)).not.toThrow();
  });
});

describe("OllamaLyrieProvider — interface conformance", () => {
  test("implements LyrieProvider with isLocal=true", () => {
    const p = new OllamaLyrieProvider();
    expect(p.id).toBe("ollama");
    expect(p.isLocal).toBe(true);
    expect(p.endpoint).toMatch(/(localhost|127\.0\.0\.1|11434)/);
    expect(p.supportsToolUse).toBe(true);
    expect(p.supportsFunctionCalling).toBe(true);
    expect(p.defaultModel.length).toBeGreaterThan(0);
    expect(p.models.length).toBeGreaterThan(0);
  });
});

describe("LMStudioProvider — interface conformance", () => {
  test("implements LyrieProvider with isLocal=true", () => {
    const p = new LMStudioProvider();
    expect(p.id).toBe("lmstudio");
    expect(p.isLocal).toBe(true);
    expect(p.endpoint).toContain("1234");
    expect(p.supportsToolUse).toBe(true);
  });
});

describe("HermesProvider — interface conformance + tool-call parser", () => {
  test("local Hermes pointed at Ollama is isLocal=true", () => {
    const p = new HermesProvider();
    expect(p.id).toBe("hermes");
    expect(p.isLocal).toBe(true);
    expect(p.defaultModel).toContain("hermes");
  });

  test("Hermes with API key + remote endpoint becomes non-local", () => {
    const p = new HermesProvider({
      endpoint: "https://openrouter.ai/api/v1",
      apiKey: "sk-test",
      protocol: "openai",
    });
    expect(p.isLocal).toBe(false);
  });

  test("parseToolCalls extracts a single <tool_call> block", () => {
    const p = new HermesProvider();
    const text = `Sure, I'll do that.
<tool_call>
{"name": "exec", "arguments": {"command": "ls"}}
</tool_call>`;
    const r = p.parseToolCalls(text);
    expect(r.toolCalls.length).toBe(1);
    expect(r.toolCalls[0].name).toBe("exec");
    expect(r.toolCalls[0].arguments.command).toBe("ls");
    expect(r.content).toBe("Sure, I'll do that.");
  });

  test("parseToolCalls extracts multiple blocks", () => {
    const p = new HermesProvider();
    const text = `<tool_call>{"name":"a","arguments":{}}</tool_call><tool_call>{"name":"b","arguments":{"x":1}}</tool_call>`;
    const r = p.parseToolCalls(text);
    expect(r.toolCalls.length).toBe(2);
    expect(r.toolCalls[0].name).toBe("a");
    expect(r.toolCalls[1].name).toBe("b");
    expect(r.toolCalls[1].arguments.x).toBe(1);
  });

  test("parseToolCalls returns empty when no tool call present", () => {
    const p = new HermesProvider();
    const r = p.parseToolCalls("just a text reply");
    expect(r.toolCalls.length).toBe(0);
    expect(r.content).toBe("just a text reply");
  });

  test("buildSystemPrompt injects <tools> block", () => {
    const p = new HermesProvider();
    const out = p.buildSystemPrompt("base prompt", [
      { name: "exec", description: "run cmd", parameters: { type: "object", properties: {}, required: [] } },
    ]);
    expect(out).toContain("<tools>");
    expect(out).toContain("<name>exec</name>");
    expect(out).toContain("<tool_call>");
  });

  test("formatMessages uses ChatML tokens", () => {
    const p = new HermesProvider();
    const out = p.formatMessages([
      { role: "system", content: "be terse" },
      { role: "user", content: "hi" },
    ]);
    expect(out).toContain("<|im_start|>system");
    expect(out).toContain("<|im_start|>user");
    expect(out).toContain("<|im_end|>");
  });
});
