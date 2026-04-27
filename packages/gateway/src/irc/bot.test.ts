/**
 * Tests for the IRC channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  IrcBot,
  ircEventToUnified,
  isIrcDirectMessage,
  splitForIrc,
  unifiedResponseToIrcLines,
} from "./bot";

describe("IrcBot", () => {
  it("recognises channel vs DM targets", () => {
    expect(isIrcDirectMessage("#lyrie", "lyrie")).toBe(false);
    expect(isIrcDirectMessage("&private", "lyrie")).toBe(false);
    expect(isIrcDirectMessage("lyrie", "lyrie")).toBe(true);
    expect(isIrcDirectMessage("LYRIE", "lyrie")).toBe(true);
    expect(isIrcDirectMessage("alice", "lyrie")).toBe(false);
  });

  it("normalises a channel PRIVMSG", () => {
    const u = ircEventToUnified(
      { nick: "alice", target: "#lyrie", message: "!scan example.com" },
      "lyriebot",
    );
    expect(u.channel).toBe("irc");
    expect(u.chatId).toBe("#lyrie");
    expect(u.command?.name).toBe("scan");
    expect(u.metadata?.isDm).toBe(false);
  });

  it("normalises a DM PRIVMSG with chatId=sender", () => {
    const u = ircEventToUnified(
      { nick: "alice", target: "lyriebot", message: "hi" },
      "lyriebot",
    );
    expect(u.chatId).toBe("alice");
    expect(u.metadata?.isDm).toBe(true);
  });

  it("splits long lines under the IRC byte budget", () => {
    const long = "x".repeat(900);
    const parts = splitForIrc(long, 400);
    expect(parts.length).toBeGreaterThanOrEqual(3);
    for (const p of parts) {
      expect(Buffer.byteLength(p, "utf8")).toBeLessThanOrEqual(400);
    }
  });

  it("renders buttons as bracketed link lines (no native buttons in IRC)", () => {
    const lines = unifiedResponseToIrcLines("#lyrie", {
      text: "Choose",
      buttons: [[{ text: "Docs", url: "https://lyrie.ai" }, { text: "Yes" }]],
    });
    expect(lines.some((l) => l.includes("[Docs](https://lyrie.ai)"))).toBe(true);
    expect(lines.some((l) => l.includes("[Yes]"))).toBe(true);
  });

  it("start() bails without server/nick", async () => {
    const bot = new IrcBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(false);
  });

  it("ingestEvent dispatches to handler", async () => {
    const bot = new IrcBot({ enabled: true, server: "irc.libera.chat", nick: "lyrie" });
    let seen: string | null = null;
    bot.onMessage(async (m) => {
      seen = `${m.senderId}:${m.text}`;
      return { text: "ok" };
    });
    await bot.start();
    await bot.ingestEvent({ nick: "alice", target: "#lyrie", message: "hello" });
    expect(seen).toBe("alice:hello");
  });
});
