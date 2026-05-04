import { describe, expect, test, mock, beforeEach } from "bun:test";
import { WebSearch } from "./web-search";
import { WebFetch } from "./web-fetch";
import { MessageTool } from "../messaging/message-tool";

// ─── WebSearch ────────────────────────────────────────────────────────────────

describe("WebSearch", () => {
  test("returns SearchResult array with required fields", async () => {
    const mockFetch = mock(async () => ({
      ok: true,
      json: async () => ({
        web: { results: [
          { title: "Test", url: "https://example.com/page", description: "A snippet" },
          { title: "Test2", url: "https://other.com/page", description: "Another snippet" },
        ]}
      })
    }));
    globalThis.fetch = mockFetch as any;

    const s = new WebSearch("test-key");
    const results = await s.search("test query");
    expect(results).toBeArray();
    expect(results[0].title).toBe("Test");
    expect(results[0].url).toBe("https://example.com/page");
    expect(results[0].snippet).toBe("A snippet");
  });

  test("deduplicates same domain", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      json: async () => ({
        web: { results: [
          { title: "A", url: "https://example.com/a", description: "a" },
          { title: "B", url: "https://example.com/b", description: "b" }, // same domain
          { title: "C", url: "https://other.com/c", description: "c" },
        ]}
      })
    })) as any;

    const s = new WebSearch("test-key");
    const results = await s.search("dedup test", { count: 10 });
    const domains = results.map(r => new URL(r.url).hostname);
    const unique = new Set(domains);
    expect(unique.size).toBe(domains.length);
  });

  test("caches same query", async () => {
    let callCount = 0;
    globalThis.fetch = mock(async () => {
      callCount++;
      return { ok: true, json: async () => ({ web: { results: [] } }) };
    }) as any;

    const s = new WebSearch("test-key");
    await s.search("cached query abc123");
    await s.search("cached query abc123");
    expect(callCount).toBe(1); // second call hits cache
  });

  test("throws when API key missing", async () => {
    const s = new WebSearch("");
    expect(s.search("test")).rejects.toThrow("BRAVE_API_KEY not set");
  });

  test("handles API error gracefully", async () => {
    globalThis.fetch = mock(async () => ({ ok: false, status: 429, statusText: "Too Many Requests" })) as any;
    const s = new WebSearch("test-key");
    expect(s.search("error test")).rejects.toThrow("429");
  });

  test("respects count param", async () => {
    let capturedUrl = "";
    globalThis.fetch = mock(async (url: string) => {
      capturedUrl = url;
      return { ok: true, json: async () => ({ web: { results: [] } }) };
    }) as any;
    const s = new WebSearch("test-key");
    await s.search("count test xyz999", { count: 3 });
    expect(capturedUrl).toContain("count=3");
  });

  test("passes country param", async () => {
    let capturedUrl = "";
    globalThis.fetch = mock(async (url: string) => {
      capturedUrl = url;
      return { ok: true, json: async () => ({ web: { results: [] } }) };
    }) as any;
    const s = new WebSearch("test-key");
    await s.search("country test xyz777", { country: "AE" });
    expect(capturedUrl).toContain("country=AE");
  });
});

// ─── WebFetch ─────────────────────────────────────────────────────────────────

describe("WebFetch", () => {
  test("extracts title from HTML", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      headers: { get: () => "text/html" },
      text: async () => "<html><head><title>Test Page</title></head><body><p>Content</p></body></html>",
    })) as any;
    const f = new WebFetch();
    const result = await f.fetch("https://example.com/test1a");
    expect(result.title).toBe("Test Page");
  });

  test("strips script and style tags", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      headers: { get: () => "text/html" },
      text: async () => "<html><body><script>alert('x')</script><style>.a{}</style><p>Real content</p></body></html>",
    })) as any;
    const f = new WebFetch();
    const result = await f.fetch("https://example.com/test2b");
    expect(result.content).not.toContain("alert");
    expect(result.content).not.toContain(".a{}");
    expect(result.content).toContain("Real content");
  });

  test("converts headings to markdown", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      headers: { get: () => "text/html" },
      text: async () => "<h1>Big Title</h1><h2>Section</h2><p>Text</p>",
    })) as any;
    const f = new WebFetch();
    const result = await f.fetch("https://example.com/test3c");
    expect(result.content).toContain("# Big Title");
    expect(result.content).toContain("## Section");
  });

  test("truncates at maxChars and sets truncated=true", async () => {
    const longContent = "word ".repeat(20000); // ~100k chars
    globalThis.fetch = mock(async () => ({
      ok: true,
      headers: { get: () => "text/html" },
      text: async () => `<p>${longContent}</p>`,
    })) as any;
    const f = new WebFetch();
    const result = await f.fetch("https://example.com/test4d", { maxChars: 100 });
    expect(result.truncated).toBe(true);
    expect(result.content.length).toBeLessThan(200);
  });

  test("truncated=false for short content", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      headers: { get: () => "text/html" },
      text: async () => "<p>Short</p>",
    })) as any;
    const f = new WebFetch();
    const result = await f.fetch("https://example.com/test5e");
    expect(result.truncated).toBe(false);
  });

  test("detects PDF", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      headers: { get: () => "application/pdf" },
      text: async () => "",
    })) as any;
    const f = new WebFetch();
    const result = await f.fetch("https://example.com/doc.pdf");
    expect(result.content).toContain("PDF");
  });

  test("throws on HTTP error", async () => {
    globalThis.fetch = mock(async () => ({ ok: false, status: 404, statusText: "Not Found" })) as any;
    const f = new WebFetch();
    expect(f.fetch("https://example.com/test6f")).rejects.toThrow("404");
  });
});

// ─── MessageTool ─────────────────────────────────────────────────────────────

describe("MessageTool", () => {
  test("sends to Telegram with correct API URL", async () => {
    let capturedUrl = "";
    globalThis.fetch = mock(async (url: string) => {
      capturedUrl = url;
      return { ok: true, json: async () => ({ ok: true, result: { message_id: 123 } }) };
    }) as any;
    const tool = new MessageTool("test-token");
    const result = await tool.send({ channel: "telegram", target: "12345", message: "hello" });
    expect(capturedUrl).toContain("test-token");
    expect(capturedUrl).toContain("sendMessage");
    expect(result.success).toBe(true);
    expect(result.messageId).toBe(123);
  });

  test("throws when telegram token missing", async () => {
    const tool = new MessageTool("");
    expect(tool.send({ channel: "telegram", target: "123", message: "hi" })).rejects.toThrow("LYRIE_TELEGRAM_TOKEN not set");
  });

  test("sends to Discord webhook", async () => {
    let capturedBody = "";
    globalThis.fetch = mock(async (_url: string, opts: any) => {
      capturedBody = opts.body;
      return { ok: true };
    }) as any;
    const tool = new MessageTool("tok");
    await tool.send({ channel: "discord", target: "https://discord.com/api/webhooks/123", message: "discord msg" });
    expect(JSON.parse(capturedBody).content).toBe("discord msg");
  });

  test("sends to Slack webhook", async () => {
    let capturedBody = "";
    globalThis.fetch = mock(async (_url: string, opts: any) => {
      capturedBody = opts.body;
      return { ok: true };
    }) as any;
    const tool = new MessageTool("tok");
    await tool.send({ channel: "slack", target: "https://hooks.slack.com/services/xxx", message: "slack msg" });
    expect(JSON.parse(capturedBody).text).toBe("slack msg");
  });

  test("sends photo when media provided", async () => {
    let capturedUrl = "";
    globalThis.fetch = mock(async (url: string) => {
      capturedUrl = url;
      return { ok: true, json: async () => ({ ok: true, result: { message_id: 1 } }) };
    }) as any;
    const tool = new MessageTool("tok");
    await tool.send({ channel: "telegram", target: "123", message: "caption", media: "https://img.com/pic.jpg" });
    expect(capturedUrl).toContain("sendPhoto");
  });

  test("throws on Telegram API error", async () => {
    globalThis.fetch = mock(async () => ({
      ok: true,
      json: async () => ({ ok: false, description: "Bad Request" }),
    })) as any;
    const tool = new MessageTool("tok");
    expect(tool.send({ channel: "telegram", target: "123", message: "x" })).rejects.toThrow("Bad Request");
  });
});
