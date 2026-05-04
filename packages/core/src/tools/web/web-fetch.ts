/**
 * Lyrie web_fetch tool — fetch URL and extract readable content
 * Readability extraction, 30min cache, PDF detection
 *
 * Lyrie.ai by OTT Cybersecurity LLC — MIT License
 */

export interface FetchOptions {
  extractMode?: "markdown" | "text";
  maxChars?: number;
}

export interface FetchResult {
  url: string;
  title?: string;
  content: string;
  truncated: boolean;
  contentType: string;
}

const CACHE_TTL_MS = 30 * 60 * 1000; // 30 min
const cache = new Map<string, { result: FetchResult; expiresAt: number }>();

function htmlToMarkdown(html: string): { title?: string; content: string } {
  // Extract title
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : undefined;

  let text = html
    // Remove scripts, styles, nav, footer, header
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<nav[\s\S]*?<\/nav>/gi, "")
    .replace(/<footer[\s\S]*?<\/footer>/gi, "")
    .replace(/<header[\s\S]*?<\/header>/gi, "")
    // Headings
    .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, "\n# $1\n")
    .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, "\n## $1\n")
    .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, "\n### $1\n")
    .replace(/<h[4-6][^>]*>([\s\S]*?)<\/h[4-6]>/gi, "\n#### $1\n")
    // Bold/italic
    .replace(/<strong[^>]*>([\s\S]*?)<\/strong>/gi, "**$1**")
    .replace(/<b[^>]*>([\s\S]*?)<\/b>/gi, "**$1**")
    .replace(/<em[^>]*>([\s\S]*?)<\/em>/gi, "_$1_")
    .replace(/<i[^>]*>([\s\S]*?)<\/i>/gi, "_$1_")
    // Links
    .replace(/<a[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)")
    // Lists
    .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, "- $1\n")
    .replace(/<[uo]l[^>]*>/gi, "\n")
    .replace(/<\/[uo]l>/gi, "\n")
    // Paragraphs and line breaks
    .replace(/<p[^>]*>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<div[^>]*>/gi, "\n")
    .replace(/<\/div>/gi, "")
    // Strip remaining tags
    .replace(/<[^>]+>/g, "")
    // Decode HTML entities
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    // Clean whitespace
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return { title, content: text };
}

export class WebFetch {
  async fetch(url: string, options: FetchOptions = {}): Promise<FetchResult> {
    const maxChars = options.maxChars ?? 50000;
    const cacheKey = `${url}:${options.extractMode ?? "markdown"}:${maxChars}`;
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) return cached.result;

    const res = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 Lyrie/1.2 (+https://lyrie.ai)" },
      redirect: "follow",
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    const contentType = res.headers.get("content-type") ?? "";

    let content: string;
    let title: string | undefined;
    let truncated = false;

    if (contentType.includes("pdf")) {
      content = `[PDF document at ${url} — use a PDF tool to extract text content]`;
    } else if (contentType.includes("text/html") || contentType.includes("text/plain")) {
      const raw = await res.text();
      if (options.extractMode === "text") {
        content = raw.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      } else {
        const extracted = htmlToMarkdown(raw);
        content = extracted.content;
        title = extracted.title;
      }
    } else {
      content = `[Binary content: ${contentType}]`;
    }

    if (content.length > maxChars) {
      content = content.slice(0, maxChars) + `\n\n... (truncated — ${content.length - maxChars} more characters)`;
      truncated = true;
    }

    const result: FetchResult = { url, title, content, truncated, contentType };
    cache.set(cacheKey, { result, expiresAt: Date.now() + CACHE_TTL_MS });
    return result;
  }
}

export const webFetchTool = {
  name: "web_fetch",
  description: "Fetch a URL and extract readable content as markdown. Results cached for 30 minutes.",
  parameters: {
    type: "object",
    properties: {
      url: { type: "string", description: "URL to fetch" },
      extractMode: { type: "string", enum: ["markdown", "text"], description: "Output format (default: markdown)" },
      maxChars: { type: "number", description: "Max characters to return (default 50000)" },
    },
    required: ["url"],
  },
  async execute(params: { url: string; extractMode?: "markdown" | "text"; maxChars?: number }) {
    const fetcher = new WebFetch();
    return await fetcher.fetch(params.url, params);
  },
};
