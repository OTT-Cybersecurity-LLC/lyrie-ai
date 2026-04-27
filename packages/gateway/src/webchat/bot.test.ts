/**
 * Tests for the WebChat channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  WebChatBot,
  isWebChatOriginAllowed,
  unifiedResponseToWebChatFrame,
  webchatFrameToUnified,
  type WebChatOutboundFrame,
} from "./bot";

describe("WebChatBot", () => {
  it("normalises a 'message' frame into a UnifiedMessage", () => {
    const u = webchatFrameToUnified({
      type: "message",
      sessionId: "sess-1",
      chatId: "tab-A",
      name: "Visitor",
      text: "/help",
      seq: 1,
      ts: 1700000000000,
    });
    expect(u).not.toBeNull();
    expect(u!.channel).toBe("webchat");
    expect(u!.chatId).toBe("tab-A");
    expect(u!.command?.name).toBe("help");
  });

  it("normalises a 'callback' frame and surfaces callbackData", () => {
    const u = webchatFrameToUnified({
      type: "callback",
      sessionId: "sess-1",
      callback: "approve",
    });
    expect(u!.callbackData).toBe("approve");
  });

  it("rejects frames with no sessionId", () => {
    expect(webchatFrameToUnified({ type: "message", sessionId: "", text: "x" })).toBeNull();
  });

  it("rejects 'message' frames without text", () => {
    expect(webchatFrameToUnified({ type: "message", sessionId: "s" })).toBeNull();
  });

  it("origin allow-list supports exact, wildcard subdomain, and '*'", () => {
    expect(isWebChatOriginAllowed("https://lyrie.ai", undefined)).toBe(true);
    expect(isWebChatOriginAllowed("https://lyrie.ai", [])).toBe(true);
    expect(isWebChatOriginAllowed("https://lyrie.ai", ["https://lyrie.ai"])).toBe(true);
    expect(isWebChatOriginAllowed("https://app.lyrie.ai", ["*.lyrie.ai"])).toBe(true);
    expect(isWebChatOriginAllowed("https://lyrie.ai", ["*.lyrie.ai"])).toBe(false);
    expect(isWebChatOriginAllowed("https://attacker.example", ["*.lyrie.ai"])).toBe(false);
    expect(isWebChatOriginAllowed("https://x", ["*"])).toBe(true);
  });

  it("renders UnifiedResponse into a WebChatOutboundFrame", () => {
    const frame = unifiedResponseToWebChatFrame("tab-A", {
      text: "hi",
      buttons: [[{ text: "Yes", callbackData: "yes" }]],
      parseMode: "markdown",
    });
    expect(frame.type).toBe("message");
    expect(frame.chatId).toBe("tab-A");
    expect(frame.buttons?.[0][0].callback).toBe("yes");
    expect(frame.parseMode).toBe("markdown");
  });

  it("start() always succeeds (no required secrets); registerSocket dispatches outbound frames", async () => {
    const bot = new WebChatBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(true);

    const captured: WebChatOutboundFrame[] = [];
    bot.registerSocket("tab-A", { send: (f) => captured.push(f) });

    bot.onMessage(async (m) => ({ text: `echo:${m.text}` }));
    await bot.ingestFrame({ type: "message", sessionId: "sess", chatId: "tab-A", text: "ping" });

    expect(captured.length).toBe(1);
    expect(captured[0].text).toBe("echo:ping");
  });

  it("dropSocket removes the registered transport", async () => {
    const bot = new WebChatBot({ enabled: true });
    await bot.start();
    let count = 0;
    bot.registerSocket("tab-A", { send: () => count++ });
    bot.dropSocket("tab-A");
    bot.onMessage(async () => ({ text: "x" }));
    await bot.ingestFrame({ type: "message", sessionId: "s", chatId: "tab-A", text: "y" });
    expect(count).toBe(0);
  });
});
