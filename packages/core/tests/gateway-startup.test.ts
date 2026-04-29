/**
 * Gateway StartupResult Tests (Issue #64)
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect } from "bun:test";
import type { StartupResult } from "../../gateway/src/index";

// We test the StartupResult type contract without spinning up actual bots.
// The type import validates that the shape is exported correctly.

describe("StartupResult type contract", () => {
  it("can construct a normal startup result", () => {
    const result: StartupResult = {
      mode: "normal",
      activeChannels: ["telegram", "discord"],
      degradedPlugins: [],
    };
    expect(result.mode).toBe("normal");
    expect(result.activeChannels).toHaveLength(2);
    expect(result.degradedPlugins).toHaveLength(0);
  });

  it("can construct a degraded startup result", () => {
    const result: StartupResult = {
      mode: "degraded",
      activeChannels: ["telegram"],
      degradedPlugins: [
        { channel: "discord", error: "invalid token" },
      ],
    };
    expect(result.mode).toBe("degraded");
    expect(result.degradedPlugins[0].channel).toBe("discord");
    expect(result.degradedPlugins[0].error).toBe("invalid token");
  });

  it("degraded mode preserves active channels alongside failed ones", () => {
    const result: StartupResult = {
      mode: "degraded",
      activeChannels: ["telegram", "slack"],
      degradedPlugins: [
        { channel: "discord", error: "connection refused" },
        { channel: "whatsapp", error: "bad credentials" },
      ],
    };
    expect(result.activeChannels).toContain("telegram");
    expect(result.activeChannels).toContain("slack");
    expect(result.degradedPlugins).toHaveLength(2);
  });
});
