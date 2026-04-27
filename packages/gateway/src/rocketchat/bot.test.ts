/**
 * Tests for the Rocket.Chat channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  RocketChatBot,
  rocketChatEventToUnified,
  unifiedResponseToRocketChatBody,
} from "./bot";

describe("RocketChatBot", () => {
  it("normalises a regular chat message", () => {
    const u = rocketChatEventToUnified({
      _id: "m1",
      rid: "GENERAL",
      msg: "/scan example.com",
      u: { _id: "U1", username: "alice" },
      ts: 1700000000000,
    });
    expect(u).not.toBeNull();
    expect(u!.channel).toBe("rocketchat");
    expect(u!.senderName).toBe("alice");
    expect(u!.command?.name).toBe("scan");
  });

  it("filters out system messages", () => {
    const u = rocketChatEventToUnified({
      _id: "m1",
      rid: "G",
      msg: "joined",
      u: { _id: "U1", username: "x" },
      t: "uj",
    });
    expect(u).toBeNull();
  });

  it("filters out self-loop messages when selfUserId is set", () => {
    const u = rocketChatEventToUnified(
      { _id: "m1", rid: "G", msg: "hi", u: { _id: "U_SELF", username: "lyrie" } },
      "U_SELF",
    );
    expect(u).toBeNull();
  });

  it("converts $date timestamp shape", () => {
    const u = rocketChatEventToUnified({
      _id: "m1",
      rid: "G",
      msg: "hi",
      u: { _id: "U1", username: "a" },
      ts: { $date: 1700000000000 },
    });
    expect(new Date(u!.timestamp).getTime()).toBe(1700000000000);
  });

  it("captures image attachments as photo media", () => {
    const u = rocketChatEventToUnified({
      _id: "m1",
      rid: "G",
      msg: "see image",
      u: { _id: "U1", username: "a" },
      attachments: [{ image_url: "https://x/y.png" }],
    });
    expect(u!.media).toHaveLength(1);
    expect(u!.media![0].type).toBe("photo");
  });

  it("renders UnifiedResponse with buttons into chat.postMessage attachments", () => {
    const body = unifiedResponseToRocketChatBody("GENERAL", {
      text: "Pick one",
      buttons: [[{ text: "A", callbackData: "a" }, { text: "B", url: "https://x" }]],
    });
    const attachments = body["attachments"] as Array<{ actions: Array<{ text: string; url?: string }> }>;
    expect(attachments[0].actions[0].text).toBe("A");
    expect(attachments[0].actions[1].url).toBe("https://x");
  });

  it("start() bails without serverUrl/userId/authToken", async () => {
    const bot = new RocketChatBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(false);
  });

  it("ingestEvent dispatches to handler", async () => {
    const bot = new RocketChatBot({
      enabled: true,
      serverUrl: "https://chat.example.com",
      userId: "U_BOT",
      authToken: "tok",
    });
    bot.onMessage(async (m) => ({ text: `echo:${m.text}` }));
    await bot.start();
    const resp = await bot.ingestEvent({
      _id: "m1",
      rid: "G",
      msg: "hi",
      u: { _id: "U1", username: "alice" },
    });
    expect(resp?.text).toBe("echo:hi");
  });
});
