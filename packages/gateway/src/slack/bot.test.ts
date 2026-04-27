/**
 * Tests for the Slack channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  SlackBot,
  slackEventToUnified,
  slackInteractionToUnified,
  unifiedResponseToSlackBody,
} from "./bot";
import type { UnifiedResponse } from "../common/types";

describe("SlackBot", () => {
  it("normalises a regular Slack message event", () => {
    const u = slackEventToUnified({
      type: "message",
      user: "U123",
      text: "/scan example.com",
      channel: "C456",
      ts: "1700000000.000100",
      team: "T1",
    });
    expect(u).not.toBeNull();
    expect(u!.channel).toBe("slack");
    expect(u!.senderId).toBe("U123");
    expect(u!.chatId).toBe("C456");
    expect(u!.command?.name).toBe("scan");
    expect(u!.command?.argv).toEqual(["example.com"]);
  });

  it("filters out bot-authored events", () => {
    const u = slackEventToUnified({
      type: "message",
      user: "U1",
      text: "x",
      channel: "C1",
      bot_id: "B999",
      ts: "1.2",
    });
    expect(u).toBeNull();
  });

  it("captures file attachments as media", () => {
    const u = slackEventToUnified({
      type: "message",
      user: "U1",
      channel: "C1",
      text: "see file",
      ts: "1.2",
      files: [{ id: "F1", name: "report.pdf", mimetype: "application/pdf", size: 1234 }],
    });
    expect(u!.media).toHaveLength(1);
    expect(u!.media![0].fileId).toBe("F1");
    expect(u!.media![0].mimeType).toBe("application/pdf");
  });

  it("normalises a block_actions interaction into a callback message", () => {
    const u = slackInteractionToUnified({
      type: "block_actions",
      user: { id: "U1", name: "alice" },
      channel: { id: "C1" },
      actions: [{ action_id: "lyrie_scan", value: "scan:example.com", type: "button" }],
    });
    expect(u).not.toBeNull();
    expect(u!.callbackData).toBe("scan:example.com");
    expect(u!.senderName).toBe("alice");
  });

  it("renders UnifiedResponse with buttons into Block Kit", () => {
    const resp: UnifiedResponse = {
      text: "*Lyrie Shield*",
      buttons: [
        [
          { text: "Approve", callbackData: "approve" },
          { text: "Deny", callbackData: "deny" },
        ],
      ],
    };
    const body = unifiedResponseToSlackBody("C1", resp);
    expect(body["channel"]).toBe("C1");
    expect(body["text"]).toBe("*Lyrie Shield*");
    const blocks = body["blocks"] as Array<{ type: string; elements?: unknown[] }>;
    expect(Array.isArray(blocks)).toBe(true);
    expect(blocks.length).toBe(2);
    const actions = blocks[1].elements as Array<{ action_id: string }>;
    expect(actions[0].action_id).toBe("approve");
  });

  it("start() bails when no botToken is provided", async () => {
    const bot = new SlackBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(false);
  });

  it("ingestEvent dispatches to handler and returns its response", async () => {
    const bot = new SlackBot({ enabled: true, botToken: "xoxb-test" });
    bot.onMessage(async (m) => ({ text: `echo:${m.text}` }));
    await bot.start();
    const resp = await bot.ingestEvent({
      type: "message",
      user: "U9",
      channel: "C9",
      text: "hi",
      ts: "1.2",
    });
    expect(resp?.text).toBe("echo:hi");
  });
});
