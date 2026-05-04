/**
 * Lyrie web_search tool — Brave Search API
 * Better than OpenClaw: 1hr cache + domain dedup
 *
 * Lyrie.ai by OTT Cybersecurity LLC — MIT License
 */

export interface SearchOptions {
  count?: number;
  country?: string;
  freshness?: "day" | "week" | "month";
  language?: string;
}

export interface SearchResult {
  title: string;
  url: string;
  snippet: string;
  age?: string;
}

interface CacheEntry {
  results: SearchResult[];
  expiresAt: number;
}

const BRAVE_API = "https://api.search.brave.com/res/v1/web/search";
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const cache = new Map<string, CacheEntry>();

export class WebSearch {
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey ?? process.env.BRAVE_API_KEY ?? process.env.BRAVE_SEARCH_API_KEY ?? "";
  }

  async search(query: string, options: SearchOptions = {}): Promise<SearchResult[]> {
    const count = Math.min(options.count ?? 5, 10);
    const cacheKey = JSON.stringify({ query, count, country: options.country, freshness: options.freshness });
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) return cached.results;

    if (!this.apiKey) throw new Error("BRAVE_API_KEY not set");

    const params = new URLSearchParams({ q: query, count: String(count) });
    if (options.country) params.set("country", options.country);
    if (options.freshness) params.set("freshness", options.freshness);
    if (options.language) params.set("search_lang", options.language);

    const res = await fetch(`${BRAVE_API}?${params}`, {
      headers: { "Accept": "application/json", "Accept-Encoding": "gzip", "X-Subscription-Token": this.apiKey },
    });

    if (!res.ok) throw new Error(`Brave Search API error: ${res.status} ${res.statusText}`);
    const data = await res.json() as any;

    const results: SearchResult[] = [];
    const seenDomains = new Set<string>();

    for (const item of data?.web?.results ?? []) {
      try {
        const domain = new URL(item.url).hostname;
        if (seenDomains.has(domain)) continue; // dedup same domain
        seenDomains.add(domain);
      } catch {}
      results.push({
        title: item.title ?? "",
        url: item.url ?? "",
        snippet: item.description ?? "",
        age: item.age,
      });
    }

    cache.set(cacheKey, { results, expiresAt: Date.now() + CACHE_TTL_MS });
    return results;
  }
}

export const webSearchTool = {
  name: "web_search",
  description: "Search the web using Brave Search. Returns titles, URLs, and snippets. Results are cached for 1 hour.",
  parameters: {
    type: "object",
    properties: {
      query: { type: "string", description: "Search query" },
      count: { type: "number", description: "Number of results (1-10, default 5)" },
      country: { type: "string", description: "2-letter country code (e.g. US, AE)" },
      freshness: { type: "string", enum: ["day", "week", "month"], description: "Filter by recency" },
    },
    required: ["query"],
  },
  async execute(params: { query: string; count?: number; country?: string; freshness?: string }) {
    const searcher = new WebSearch();
    return await searcher.search(params.query, params);
  },
};
