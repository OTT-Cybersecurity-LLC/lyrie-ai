/**
 * Tests for the Matrix channel adapter — Lyrie Gateway.
 * Lyrie.ai by OTT Cybersecurity LLC.
 */

import { describe, expect, it } from "bun:test";
import {
  MatrixBot,
  matrixEventToUnified,
  unifiedResponseToMatrixContent,
} from "./bot";

describe("MatrixBot", () => {
  it("normalises a m.room.message event", () => {
    const u = matrixEventToUnified({
      type: "m.room.message",
      event_id: "$abc",
      sender: "@alice:matrix.org",
      room_id: "!room:matrix.org",
      origin_server_ts: 1700000000000,
      content: { msgtype: "m.text", body: "!scan example.com" },
    });
    expect(u).not.toBeNull();
    expect(u!.channel).toBe("matrix");
    expect(u!.command?.name).toBe("scan");
    expect(u!.command?.argv).toEqual(["example.com"]);
  });

  it("ignores echoes from the bot itself", () => {
    const u = matrixEventToUnified(
      {
        type: "m.room.message",
        event_id: "$x",
        sender: "@lyrie:matrix.org",
        room_id: "!r:matrix.org",
        origin_server_ts: 1,
        content: { msgtype: "m.text", body: "hi" },
      },
      "@lyrie:matrix.org",
    );
    expect(u).toBeNull();
  });

  it("captures media for non-text events", () => {
    const u = matrixEventToUnified({
      type: "m.room.message",
      event_id: "$f",
      sender: "@alice:matrix.org",
      room_id: "!r:matrix.org",
      origin_server_ts: 1,
      content: {
        msgtype: "m.image",
        url: "mxc://matrix.org/aabbcc",
        info: { mimetype: "image/png", size: 4096 },
      },
    });
    expect(u!.media).toHaveLength(1);
    expect(u!.media![0].fileId).toBe("mxc://matrix.org/aabbcc");
    expect(u!.media![0].type).toBe("photo");
  });

  it("renders markdown UnifiedResponse with HTML formatting", () => {
    const content = unifiedResponseToMatrixContent({
      text: "**bold**",
      parseMode: "markdown",
      replyToMessageId: "$parent",
    });
    expect(content["msgtype"]).toBe("m.text");
    expect(content["body"]).toBe("**bold**");
    expect(content["format"]).toBe("org.matrix.custom.html");
    expect(content["m.relates_to"]).toBeDefined();
  });

  it("start() bails without homeserverUrl/accessToken", async () => {
    const bot = new MatrixBot({ enabled: true });
    await bot.start();
    expect(bot.isConnected()).toBe(false);
  });

  it("ingestEvent calls the handler", async () => {
    const bot = new MatrixBot({
      enabled: true,
      homeserverUrl: "https://matrix.example.com",
      accessToken: "syt_x",
      userId: "@lyrie:example.com",
    });
    let seen = "";
    bot.onMessage(async (m) => {
      seen = m.text;
      return { text: "ok" };
    });
    await bot.start();
    await bot.ingestEvent({
      type: "m.room.message",
      event_id: "$1",
      sender: "@u:example.com",
      room_id: "!r:example.com",
      origin_server_ts: 1,
      content: { msgtype: "m.text", body: "hello" },
    });
    expect(seen).toBe("hello");
  });
});
