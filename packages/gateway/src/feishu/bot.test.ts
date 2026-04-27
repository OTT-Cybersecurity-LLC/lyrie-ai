/**
 * Tests for the Feishu / Lark channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  FeishuBot,
  feishuEventToUnified,
  feishuExtractText,
  unifiedResponseToFeishuBody,
  type FeishuEventEnvelope,
} from "./bot";

const baseEnvelope = (overrides: Partial<FeishuEventEnvelope> = {}): FeishuEventEnvelope => ({
  schema: "2.0",
  header: {
    event_id: "evt-1",
    event_type: "im.message.receive_v1",
    create_time: String(Date.now()),
    token: "tok-good",
    app_id: "cli_app",
    tenant_key: "tnt_a",
  },
  event: {
    sender: { sender_id: { open_id: "ou_alice" } },
    message: {
      message_id: "om_1",
      chat_id: "oc_1",
      chat_type: "p2p",
      message_type: "text",
      content: JSON.stringify({ text: "/help" }),
    },
  },
  ...overrides,
});

describe("FeishuBot", () => {
  it("extracts text from typed-content shapes", () => {
    expect(feishuExtractText("text", JSON.stringify({ text: "hi" }))).toBe("hi");
    expect(feishuExtractText("image", "{}")).toBe("[image]");
    expect(feishuExtractText("file", "{}")).toBe("[file]");
    expect(
      feishuExtractText(
        "post",
        JSON.stringify({
          title: "Title",
          content: [[{ tag: "text", text: "line1" }], [{ tag: "text", text: "line2" }]],
        }),
      ),
    ).toBe("Title\nline1\nline2");
  });

  it("normalises a receive_v1 envelope", () => {
    const u = feishuEventToUnified(baseEnvelope());
    expect(u).not.toBeNull();
    expect(u!.channel).toBe("feishu");
    expect(u!.command?.name).toBe("help");
    expect(u!.metadata?.chatType).toBe("p2p");
  });

  it("ignores non-receive event types", () => {
    const env = baseEnvelope();
    env.header.event_type = "im.message.read";
    expect(feishuEventToUnified(env)).toBeNull();
  });

  it("renders text-only UnifiedResponse as msg_type=text", () => {
    const body = unifiedResponseToFeishuBody("oc_1", { text: "hello" });
    expect(body["msg_type"]).toBe("text");
    const content = JSON.parse(body["content"] as string) as { text: string };
    expect(content.text).toBe("hello");
  });

  it("renders UnifiedResponse with buttons as msg_type=interactive (card)", () => {
    const body = unifiedResponseToFeishuBody("oc_1", {
      text: "Choose",
      buttons: [[{ text: "Approve", callbackData: "approve" }]],
    });
    expect(body["msg_type"]).toBe("interactive");
    const card = JSON.parse(body["content"] as string) as {
      elements: Array<{ tag: string; actions?: unknown[] }>;
    };
    const actions = card.elements.find((e) => e.tag === "action")?.actions;
    expect(actions).toBeDefined();
    expect((actions as unknown[]).length).toBe(1);
  });

  it("apiHost switches between Feishu and Lark", () => {
    expect(new FeishuBot({ enabled: true, isLark: false }).apiHost()).toBe("https://open.feishu.cn");
    expect(new FeishuBot({ enabled: true, isLark: true }).apiHost()).toBe("https://open.larksuite.com");
  });

  it("start() bails without appId/appSecret", async () => {
    const bot = new FeishuBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(false);
  });

  it("rejects events that fail verificationToken check", async () => {
    const bot = new FeishuBot({
      enabled: true,
      appId: "a",
      appSecret: "s",
      verificationToken: "tok-good",
    });
    await bot.start();
    let called = false;
    bot.onMessage(async () => {
      called = true;
      return { text: "x" };
    });
    const env = baseEnvelope();
    env.header.token = "tok-WRONG";
    const out = await bot.ingestEvent(env);
    expect(called).toBe(false);
    expect(out).toBeNull();
  });

  it("dispatches valid events to the handler", async () => {
    const bot = new FeishuBot({ enabled: true, appId: "a", appSecret: "s" });
    bot.onMessage(async (m) => ({ text: `echo:${m.text}` }));
    await bot.start();
    const resp = await bot.ingestEvent(baseEnvelope());
    expect(resp?.text).toBe("echo:/help");
  });
});
