/**
 * Tests for the Mattermost channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  MattermostBot,
  mattermostEventToUnified,
  unifiedResponseToMattermostBody,
} from "./bot";

const samplePost = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    id: "p123",
    user_id: "U1",
    channel_id: "C1",
    message: "/recon example.com",
    ...overrides,
  });

describe("MattermostBot", () => {
  it("normalises a 'posted' event", () => {
    const u = mattermostEventToUnified({
      event: "posted",
      data: { sender_name: "alice", post: samplePost(), team_id: "T1" },
    });
    expect(u).not.toBeNull();
    expect(u!.channel).toBe("mattermost");
    expect(u!.senderId).toBe("U1");
    expect(u!.command?.name).toBe("recon");
    expect(u!.metadata?.teamId).toBe("T1");
  });

  it("filters out non-'posted' system events", () => {
    const u = mattermostEventToUnified({
      event: "post_edited",
      data: { post: samplePost() },
    });
    expect(u).toBeNull();
  });

  it("filters self-posts when selfUserId provided", () => {
    const u = mattermostEventToUnified(
      { event: "posted", data: { post: samplePost() } },
      "U1",
    );
    expect(u).toBeNull();
  });

  it("filters typed (system) posts", () => {
    const u = mattermostEventToUnified({
      event: "posted",
      data: { post: samplePost({ type: "system_join_channel", message: "joined" }) },
    });
    expect(u).toBeNull();
  });

  it("collects file_ids as document attachments", () => {
    const u = mattermostEventToUnified({
      event: "posted",
      data: { post: samplePost({ message: "see file", file_ids: ["F1", "F2"] }) },
    });
    expect(u!.media).toHaveLength(2);
    expect(u!.media![0].fileId).toBe("F1");
  });

  it("renders UnifiedResponse with buttons into Mattermost interactive props", () => {
    const body = unifiedResponseToMattermostBody("C1", {
      text: "Choose",
      buttons: [[{ text: "Yes", callbackData: "yes" }, { text: "No", callbackData: "no" }]],
    });
    const props = body["props"] as { attachments: Array<{ actions: unknown[] }> };
    expect(props.attachments[0].actions.length).toBe(2);
  });

  it("start() bails without serverUrl/token", async () => {
    const bot = new MattermostBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(false);
  });

  it("ingestEvent calls the handler and posts back", async () => {
    const bot = new MattermostBot({
      enabled: true,
      serverUrl: "https://mm.example.com",
      token: "tok",
    });
    bot.onMessage(async (m) => ({ text: `echo:${m.text}` }));
    await bot.start();
    const resp = await bot.ingestEvent({
      event: "posted",
      data: { post: samplePost({ message: "hi" }) },
    });
    expect(resp?.text).toBe("echo:hi");
  });
});
