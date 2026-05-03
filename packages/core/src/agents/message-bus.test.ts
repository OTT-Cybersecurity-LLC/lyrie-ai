/**
 * AgentMessageBus — unit tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { AgentMessageBus, type AgentMessage } from "./message-bus";
import type { ShieldGuardLike, ShieldVerdict } from "../engine/shield-guard";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeBus(shield?: ShieldGuardLike): AgentMessageBus {
  return new AgentMessageBus(shield);
}

/** Shield that blocks everything. */
const blockAllShield: ShieldGuardLike = {
  scanRecalled: () => ({ blocked: true, severity: "critical", reason: "test-block" }),
  scanInbound: () => ({ blocked: true, severity: "critical", reason: "test-block" }),
};

/** Shield that passes everything. */
const passAllShield: ShieldGuardLike = {
  scanRecalled: () => ({ blocked: false }),
  scanInbound: () => ({ blocked: false }),
};

/** Shield that blocks only messages containing "INJECT". */
const selectiveShield: ShieldGuardLike = {
  scanRecalled: (text) =>
    text.includes("INJECT")
      ? { blocked: true, severity: "high", reason: "injection pattern" }
      : { blocked: false },
  scanInbound: () => ({ blocked: false }),
};

beforeEach(() => {
  AgentMessageBus.resetInstance();
});

// ─── Singleton ────────────────────────────────────────────────────────────────

describe("Singleton", () => {
  test("getInstance returns the same instance on repeated calls", () => {
    const a = AgentMessageBus.getInstance();
    const b = AgentMessageBus.getInstance();
    expect(a).toBe(b);
  });

  test("resetInstance returns a new instance afterward", () => {
    const a = AgentMessageBus.getInstance();
    AgentMessageBus.resetInstance();
    const b = AgentMessageBus.getInstance();
    expect(a).not.toBe(b);
  });
});

// ─── Channel lifecycle ────────────────────────────────────────────────────────

describe("Channel lifecycle", () => {
  test("registerChannel makes agent visible in registeredAgents()", () => {
    const bus = makeBus();
    bus.registerChannel("agent-1");
    expect(bus.registeredAgents().has("agent-1")).toBe(true);
  });

  test("registerChannel is idempotent", () => {
    const bus = makeBus();
    bus.registerChannel("agent-1");
    bus.registerChannel("agent-1");
    expect(bus.registeredAgents().size).toBe(1);
  });

  test("unregisterChannel removes agent from registeredAgents()", () => {
    const bus = makeBus();
    bus.registerChannel("agent-1");
    bus.unregisterChannel("agent-1");
    expect(bus.registeredAgents().has("agent-1")).toBe(false);
  });

  test("subscribing without registerChannel still works", () => {
    const bus = makeBus();
    const received: AgentMessage[] = [];
    bus.subscribe("agent-x", (m) => received.push(m));
    bus.publish("agent-x", {
      fromAgentId: "sender",
      toAgentId: "agent-x",
      content: "hello",
      type: "alert",
    });
    expect(received).toHaveLength(1);
  });
});

// ─── Publish / Subscribe ──────────────────────────────────────────────────────

describe("Publish / Subscribe", () => {
  test("published message reaches subscriber", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("agent-1", (m) => received.push(m));
    bus.publish("agent-1", {
      fromAgentId: "agent-0",
      toAgentId: "agent-1",
      content: "ping",
      type: "alert",
    });
    expect(received).toHaveLength(1);
    expect(received[0].content).toBe("ping");
  });

  test("published message has auto-assigned id and timestamp", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));
    bus.publish("a1", {
      fromAgentId: "a0",
      toAgentId: "a1",
      content: "x",
      type: "query",
    });
    expect(received[0].id).toMatch(/^msg-\d+-\d+$/);
    expect(received[0].timestamp).toBeGreaterThan(0);
  });

  test("multiple subscribers on the same channel all receive the message", () => {
    const bus = makeBus(passAllShield);
    const r1: AgentMessage[] = [];
    const r2: AgentMessage[] = [];
    bus.subscribe("agent-1", (m) => r1.push(m));
    bus.subscribe("agent-1", (m) => r2.push(m));
    bus.publish("agent-1", {
      fromAgentId: "a0",
      toAgentId: "agent-1",
      content: "hello",
      type: "alert",
    });
    expect(r1).toHaveLength(1);
    expect(r2).toHaveLength(1);
  });

  test("unsubscribe stops delivery", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    const unsub = bus.subscribe("agent-1", (m) => received.push(m));
    unsub();
    bus.publish("agent-1", {
      fromAgentId: "a0",
      toAgentId: "agent-1",
      content: "after-unsub",
      type: "alert",
    });
    expect(received).toHaveLength(0);
  });

  test("publishing to an unknown channel (no subscribers) does not throw", () => {
    const bus = makeBus(passAllShield);
    expect(() =>
      bus.publish("nobody", {
        fromAgentId: "a0",
        content: "x",
        type: "alert",
      }),
    ).not.toThrow();
  });

  test("message does NOT reach wrong channel", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("agent-2", (m) => received.push(m));
    bus.publish("agent-1", {
      fromAgentId: "a0",
      toAgentId: "agent-1",
      content: "for 1",
      type: "alert",
    });
    expect(received).toHaveLength(0);
  });

  test("shieldPassed is true on a clean message", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));
    bus.publish("a1", {
      fromAgentId: "a0",
      content: "clean",
      type: "alert",
    });
    expect(received[0].shieldPassed).toBe(true);
  });
});

// ─── Shield gate on publish ───────────────────────────────────────────────────

describe("Shield gate — publish", () => {
  test("blocked message is NOT delivered to subscriber", () => {
    const bus = makeBus(blockAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));
    bus.publish("a1", {
      fromAgentId: "a0",
      content: "evil payload",
      type: "alert",
    });
    expect(received).toHaveLength(0);
  });

  test("selective shield blocks only injection-containing messages", () => {
    const bus = makeBus(selectiveShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));
    bus.publish("a1", { fromAgentId: "a0", content: "INJECT", type: "alert" });
    bus.publish("a1", { fromAgentId: "a0", content: "clean", type: "alert" });
    expect(received).toHaveLength(1);
    expect(received[0].content).toBe("clean");
  });
});

// ─── Request / Reply ──────────────────────────────────────────────────────────

describe("Request / Reply", () => {
  test("request resolves when target agent replies", async () => {
    const bus = makeBus(passAllShield);

    // Simulate target agent responding
    bus.subscribe("agent-b", (msg) => {
      // Echo back with re:<queryId> prefix
      bus.publish("agent-b", {
        fromAgentId: "agent-b",
        toAgentId: "agent-a",
        content: `re:${msg.id}\nworld`,
        type: "response",
      });
    });

    const reply = await bus.request("agent-a", "agent-b", "hello", 1000);
    expect(reply.content).toMatch(/^re:msg-/);
    expect(reply.type).toBe("response");
  });

  test("request times out when no reply arrives", async () => {
    const bus = makeBus(passAllShield);
    bus.subscribe("agent-b", () => { /* intentionally no reply */ });

    await expect(
      bus.request("agent-a", "agent-b", "hello", 100),
    ).rejects.toThrow(/timed out/);
  });

  test("request rejects immediately when query blocked by Shield", async () => {
    const bus = makeBus(blockAllShield);
    await expect(
      bus.request("agent-a", "agent-b", "evil", 1000),
    ).rejects.toThrow(/blocked by Shield/);
  });

  test("pending request count tracks in-flight requests", async () => {
    const bus = makeBus(passAllShield);
    bus.subscribe("agent-b", () => { /* no reply */ });

    const p = bus.request("agent-a", "agent-b", "q", 500).catch(() => {});
    expect(bus.pendingRequestCount()).toBe(1);
    await p;
    expect(bus.pendingRequestCount()).toBe(0);
  });

  test("multiple concurrent requests resolve independently", async () => {
    const bus = makeBus(passAllShield);

    const queryIds: string[] = [];
    bus.subscribe("agent-b", (msg) => {
      queryIds.push(msg.id);
      bus.publish("agent-b", {
        fromAgentId: "agent-b",
        toAgentId: "agent-a",
        content: `re:${msg.id}\nanswer`,
        type: "response",
      });
    });

    const [r1, r2] = await Promise.all([
      bus.request("agent-a", "agent-b", "q1", 1000),
      bus.request("agent-a", "agent-b", "q2", 1000),
    ]);
    expect(r1.type).toBe("response");
    expect(r2.type).toBe("response");
  });

  test("request to agent with no subscriber times out", async () => {
    const bus = makeBus(passAllShield);
    await expect(
      bus.request("agent-a", "ghost", "hello", 100),
    ).rejects.toThrow(/timed out/);
  });
});

// ─── Broadcast ────────────────────────────────────────────────────────────────

describe("Broadcast", () => {
  test("broadcast delivers to all registered agents except sender", () => {
    const bus = makeBus(passAllShield);
    bus.registerChannel("a1");
    bus.registerChannel("a2");
    bus.registerChannel("a3");

    const msgs: { id: string; content: string }[] = [];
    bus.subscribe("a1", (m) => msgs.push({ id: "a1", content: m.content }));
    bus.subscribe("a2", (m) => msgs.push({ id: "a2", content: m.content }));
    bus.subscribe("a3", (m) => msgs.push({ id: "a3", content: m.content }));

    bus.broadcast("a1", {
      fromAgentId: "a1",
      content: "attention all",
      type: "broadcast",
    });

    const subs = msgs.filter((m) => m.id !== "a1");
    expect(subs).toHaveLength(2);
    expect(subs.every((m) => m.content === "attention all")).toBe(true);
  });

  test("broadcast does NOT deliver to the sender", () => {
    const bus = makeBus(passAllShield);
    bus.registerChannel("a1");
    bus.registerChannel("a2");

    const senderReceived: AgentMessage[] = [];
    bus.subscribe("a1", (m) => senderReceived.push(m));

    bus.broadcast("a1", {
      fromAgentId: "a1",
      content: "hi",
      type: "broadcast",
    });

    expect(senderReceived).toHaveLength(0);
  });

  test("broadcast blocked by Shield delivers nothing", () => {
    const bus = makeBus(blockAllShield);
    bus.registerChannel("a1");
    bus.registerChannel("a2");

    const received: AgentMessage[] = [];
    bus.subscribe("a2", (m) => received.push(m));

    bus.broadcast("a1", {
      fromAgentId: "a1",
      content: "evil",
      type: "broadcast",
    });

    expect(received).toHaveLength(0);
  });

  test("broadcast to empty bus does not throw", () => {
    const bus = makeBus(passAllShield);
    expect(() =>
      bus.broadcast("a1", {
        fromAgentId: "a1",
        content: "x",
        type: "broadcast",
      }),
    ).not.toThrow();
  });

  test("broadcast selective shield blocks only injection payload", () => {
    const bus = makeBus(selectiveShield);
    bus.registerChannel("a1");
    bus.registerChannel("a2");

    const received: AgentMessage[] = [];
    bus.subscribe("a2", (m) => received.push(m));

    bus.broadcast("a1", { fromAgentId: "a1", content: "INJECT evil", type: "broadcast" });
    bus.broadcast("a1", { fromAgentId: "a1", content: "clean message", type: "broadcast" });

    expect(received).toHaveLength(1);
    expect(received[0].content).toBe("clean message");
  });

  test("unregistered agents do not receive broadcasts", () => {
    const bus = makeBus(passAllShield);
    // a2 subscribes but is NOT registered
    const received: AgentMessage[] = [];
    bus.subscribe("a2", (m) => received.push(m));
    bus.registerChannel("a1");

    bus.broadcast("a1", { fromAgentId: "a1", content: "hi", type: "broadcast" });

    expect(received).toHaveLength(0);
  });
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

describe("Edge cases", () => {
  test("a throwing subscriber does not crash the bus", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", () => { throw new Error("boom"); });
    bus.subscribe("a1", (m) => received.push(m));

    expect(() =>
      bus.publish("a1", { fromAgentId: "a0", content: "hi", type: "alert" }),
    ).not.toThrow();
    expect(received).toHaveLength(1);
  });

  test("type field is preserved in delivered message", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));

    for (const t of ["query", "response", "alert", "broadcast"] as const) {
      bus.publish("a1", { fromAgentId: "a0", content: t, type: t });
    }
    expect(received.map((m) => m.type)).toEqual(["query", "response", "alert", "broadcast"]);
  });

  test("empty content message is delivered (empty string is not blocked by default shield)", () => {
    const bus = makeBus(); // default FallbackShieldGuard
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));
    bus.publish("a1", { fromAgentId: "a0", content: "", type: "alert" });
    expect(received).toHaveLength(1);
  });

  test("fromAgentId is preserved on delivery", () => {
    const bus = makeBus(passAllShield);
    const received: AgentMessage[] = [];
    bus.subscribe("a1", (m) => received.push(m));
    bus.publish("a1", { fromAgentId: "my-agent-007", content: "hi", type: "alert" });
    expect(received[0].fromAgentId).toBe("my-agent-007");
  });
});
