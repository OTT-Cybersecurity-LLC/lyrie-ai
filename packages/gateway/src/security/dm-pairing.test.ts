/**
 * DM Pairing — unit tests
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DmPairingManager,
  evaluateDmPolicy,
  type DmPolicy,
} from "./dm-pairing";
import type { UnifiedMessage } from "../common/types";

let storeDir: string;
let storePath: string;

function makeMsg(over: Partial<UnifiedMessage> = {}): UnifiedMessage {
  return {
    id: "m1",
    channel: "telegram",
    senderId: "user-123",
    senderName: "Alice",
    chatId: "chat-1",
    text: "hi",
    timestamp: new Date().toISOString(),
    ...over,
  };
}

beforeEach(() => {
  storeDir = mkdtempSync(join(tmpdir(), "lyrie-pairing-"));
  storePath = join(storeDir, "pairing.json");
});

afterEach(() => {
  rmSync(storeDir, { recursive: true, force: true });
});

describe("DmPairingManager", () => {
  test("greet produces a pairing code and persists pending record", () => {
    const m = new DmPairingManager({ storePath });
    const reply = m.greet(makeMsg());
    expect(reply.text).toContain("pairing approve telegram");

    // Same sender greeted twice → still a single pending record
    m.greet(makeMsg());
    const pending = m.list().pending;
    expect(pending.length).toBe(1);
    expect(pending[0].code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  });

  test("approve moves record from pending to approved", () => {
    const m = new DmPairingManager({ storePath });
    m.greet(makeMsg());
    const code = m.list().pending[0].code!;

    const approved = m.approve("telegram", code);
    expect(approved).not.toBeNull();
    expect(approved!.senderId).toBe("user-123");
    expect(m.list().pending.length).toBe(0);
    expect(m.list().approved.length).toBe(1);
    expect(m.isApproved("telegram", "user-123")).toBe(true);
  });

  test("approve with invalid code returns null", () => {
    const m = new DmPairingManager({ storePath });
    expect(m.approve("telegram", "BAD-CODE")).toBeNull();
  });

  test("revoke removes an approved sender", () => {
    const m = new DmPairingManager({ storePath });
    m.greet(makeMsg());
    const code = m.list().pending[0].code!;
    m.approve("telegram", code);
    expect(m.revoke("telegram", "user-123")).toBe(true);
    expect(m.isApproved("telegram", "user-123")).toBe(false);
    // Idempotent
    expect(m.revoke("telegram", "user-123")).toBe(false);
  });

  test("store persists across instances", () => {
    const a = new DmPairingManager({ storePath });
    a.greet(makeMsg());
    const code = a.list().pending[0].code!;
    a.approve("telegram", code);

    const b = new DmPairingManager({ storePath });
    expect(b.isApproved("telegram", "user-123")).toBe(true);
  });
});

describe("evaluateDmPolicy", () => {
  function setup(policy: DmPolicy, allowedUsers?: string[]) {
    const manager = new DmPairingManager({ storePath });
    return {
      manager,
      run: (msg = makeMsg()) =>
        evaluateDmPolicy(msg, { policy, allowedUsers }, manager),
    };
  }

  test("open: passes everything through", () => {
    const { run } = setup("open");
    expect(run()).toBeNull();
  });

  test("closed: blocks unknown sender", () => {
    const { run } = setup("closed");
    const reply = run();
    expect(reply).not.toBeNull();
    expect(reply!.text).toContain("locked down");
  });

  test("closed: allows allowlisted sender", () => {
    const { run } = setup("closed", ["user-123"]);
    expect(run()).toBeNull();
  });

  test("pairing: gates unknown sender with code", () => {
    const { run, manager } = setup("pairing");
    const reply = run();
    expect(reply).not.toBeNull();
    expect(reply!.text).toContain("pairing approve");
    expect(manager.list().pending.length).toBe(1);
  });

  test("pairing: lets approved sender through", () => {
    const { run, manager } = setup("pairing");
    run(); // first greet
    const code = manager.list().pending[0].code!;
    manager.approve("telegram", code);
    expect(run()).toBeNull();
  });

  test("pairing: allowedUsers bypasses pairing", () => {
    const { run, manager } = setup("pairing", ["user-123"]);
    expect(run()).toBeNull();
    expect(manager.list().pending.length).toBe(0);
  });
});
