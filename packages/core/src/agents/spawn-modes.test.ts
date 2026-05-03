/**
 * SpawnModes — fork/fresh + ATP scope narrowing tests.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  resolveSpawn,
  buildSpawnPromptAddendum,
  applySpawnToTask,
  ScopeWideningError,
  ForkMisuseError,
} from "./spawn-modes";

describe("resolveSpawn — ATP scope narrowing", () => {
  test("inherits parent scope when child scope omitted", () => {
    const r = resolveSpawn({ mode: "fork", parentScope: ["exec", "read_file"] });
    expect(r.scope).toEqual(["exec", "read_file"]);
  });

  test("allows narrower scope (subset of parent)", () => {
    const r = resolveSpawn({
      mode: "fresh",
      scope: ["read_file"],
      parentScope: ["exec", "read_file", "write_file"],
    });
    expect(r.scope).toEqual(["read_file"]);
  });

  test("rejects scope widening (ATP rule)", () => {
    expect(() =>
      resolveSpawn({
        mode: "fresh",
        scope: ["exec", "write_file"],
        parentScope: ["exec"],
      }),
    ).toThrow(ScopeWideningError);
  });

  test("fork mode forbids model override (cache-sharing rule)", () => {
    expect(() =>
      resolveSpawn({
        mode: "fork",
        // @ts-expect-error — accepts any object as ModelInstance for the test
        model: { config: { id: "different" }, complete: async () => ({}) },
      }),
    ).toThrow(ForkMisuseError);
  });

  test("fresh mode allows model override", () => {
    expect(() =>
      resolveSpawn({
        mode: "fresh",
        // @ts-expect-error — see above
        model: { config: { id: "different" }, complete: async () => ({}) },
      }),
    ).not.toThrow();
  });
});

describe("buildSpawnPromptAddendum", () => {
  test("fork addendum says 'forked continuation'", () => {
    const out = buildSpawnPromptAddendum({ mode: "fork" });
    expect(out).toContain("FORK");
    expect(out).toContain("forked continuation");
  });

  test("fresh addendum says 'freshly-instantiated'", () => {
    const out = buildSpawnPromptAddendum({ mode: "fresh" });
    expect(out).toContain("FRESH");
    expect(out).toContain("freshly-instantiated");
  });
});

describe("applySpawnToTask", () => {
  test("appends fork context to existing context array", () => {
    const merged = applySpawnToTask(
      {
        id: "t1",
        instruction: "do thing",
        input: "go",
        context: ["already there"],
      },
      {
        mode: "fork",
        parentContext: [
          { role: "user", content: "earlier message" },
          { role: "assistant", content: "earlier reply" },
        ],
      },
    );
    expect(merged.instruction).toContain("FORK");
    expect(merged.context).toContain("already there");
    expect(merged.context).toContain("[user] earlier message");
    expect(merged.context).toContain("[assistant] earlier reply");
  });

  test("fresh spawn does NOT inherit parent context", () => {
    const merged = applySpawnToTask(
      { id: "t2", instruction: "do thing", input: "go" },
      {
        mode: "fresh",
        parentContext: [{ role: "user", content: "should not be here" }],
      },
    );
    expect(merged.context ?? []).not.toContain("[user] should not be here");
    expect(merged.instruction).toContain("FRESH");
  });
});
