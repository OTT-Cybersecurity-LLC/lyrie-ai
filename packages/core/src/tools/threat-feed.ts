/**
 * threat-feed — Live threat intelligence from research.lyrie.ai
 *
 * Fetches the latest security advisories from the Lyrie AI research newsroom
 * and filters them by severity, CVE, and stream (category).
 *
 * Usage (CLI):
 *   lyrie threat-feed
 *   lyrie threat-feed --severity CRITICAL
 *   lyrie threat-feed --cve CVE-2025-1234
 *   lyrie threat-feed --stream active-exploitation
 *   lyrie threat-feed --limit 5
 *
 * Output: structured JSON array with CVE, CVSS, headline, lyrie_verdict.
 * Integrates with Lyrie Shield threat attribution (research.lyrie.ai).
 *
 * Feed endpoint: https://research.lyrie.ai/api/feed.json
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type ThreatSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type ThreatStream =
  | "cve-deepdive"
  | "active-exploitation"
  | "zero-day"
  | "patch-tuesday"
  | "ransomware"
  | "supply-chain"
  | "nation-state"
  | "threat-intel"
  | string;

export interface ThreatAdvisory {
  /** CVE identifier, e.g. "CVE-2025-12345". May be null for non-CVE advisories. */
  cve: string | null;
  /** CVSS v3.1 base score (0.0 – 10.0) */
  cvss: number | null;
  /** Severity label derived from CVSS or editorial classification */
  severity: ThreatSeverity;
  /** Article headline */
  headline: string;
  /** Short description / summary */
  summary: string;
  /** Affected products or vendors */
  affected: string[];
  /** Stream / category tag */
  stream: ThreatStream;
  /** Publication timestamp (ISO 8601) */
  published: string;
  /** Full article URL on research.lyrie.ai */
  url: string;
  /** Lyrie Shield attribution — threat actor / campaign if known */
  lyrie_verdict: string | null;
}

export interface ThreatFeedOptions {
  /** Filter to only CRITICAL and/or HIGH severities (default: all) */
  severity?: ThreatSeverity | ThreatSeverity[];
  /** Filter by specific CVE ID */
  cve?: string;
  /** Filter by stream/category */
  stream?: ThreatStream;
  /** Maximum advisories to return (default: 20) */
  limit?: number;
  /** Custom feed URL (default: https://research.lyrie.ai/api/feed.json) */
  feedUrl?: string;
}

export interface ThreatFeedResult {
  /** Number of advisories returned */
  count: number;
  /** Timestamp when feed was fetched */
  fetchedAt: string;
  /** Feed source URL */
  source: string;
  /** Matched advisories */
  advisories: ThreatAdvisory[];
  /** Active filters applied */
  filters: {
    severity?: string | string[];
    cve?: string;
    stream?: string;
    limit: number;
  };
}

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_FEED_URL = "https://research.lyrie.ai/api/feed.json";
const DEFAULT_LIMIT = 20;
const REQUEST_TIMEOUT_MS = 15_000;

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

function cvssToSeverity(cvss: number): ThreatSeverity {
  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  if (cvss > 0.0) return "LOW";
  return "INFO";
}

// ─── Feed fetcher ─────────────────────────────────────────────────────────────

async function fetchRawFeed(url: string): Promise<ThreatAdvisory[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Lyrie-ThreatFeed/0.8.0 (https://lyrie.ai)",
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      throw new Error(
        `Threat feed fetch failed: ${res.status} ${res.statusText} — ${url}`
      );
    }

    const data = await res.json() as any;

    // Normalise — feed may return { advisories: [...] } or a bare array
    const raw: any[] = Array.isArray(data)
      ? data
      : Array.isArray(data?.advisories)
      ? data.advisories
      : Array.isArray(data?.items)
      ? data.items
      : [];

    return raw.map((item: any): ThreatAdvisory => {
      const cvss = typeof item.cvss === "number" ? item.cvss : null;
      const severity: ThreatSeverity =
        item.severity?.toUpperCase() in SEVERITY_RANK
          ? (item.severity.toUpperCase() as ThreatSeverity)
          : cvss !== null
          ? cvssToSeverity(cvss)
          : "INFO";

      return {
        cve: item.cve ?? item.cve_id ?? null,
        cvss,
        severity,
        headline: item.headline ?? item.title ?? item.name ?? "(no headline)",
        summary: item.summary ?? item.description ?? item.excerpt ?? "",
        affected: Array.isArray(item.affected)
          ? item.affected
          : item.affected
          ? [item.affected]
          : [],
        stream: item.stream ?? item.category ?? item.tag ?? "threat-intel",
        published: item.published ?? item.date ?? item.created_at ?? new Date().toISOString(),
        url: item.url ?? item.link ?? url,
        lyrie_verdict: item.lyrie_verdict ?? item.attribution ?? null,
      };
    });
  } finally {
    clearTimeout(timer);
  }
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Fetch and filter live threat advisories from research.lyrie.ai.
 *
 * @example
 * const result = await fetchThreatFeed({ severity: ["CRITICAL", "HIGH"], limit: 10 });
 * console.log(result.advisories);
 */
export async function fetchThreatFeed(
  options: ThreatFeedOptions = {}
): Promise<ThreatFeedResult> {
  const feedUrl = options.feedUrl ?? DEFAULT_FEED_URL;
  const limit = options.limit ?? DEFAULT_LIMIT;
  const severityFilter = options.severity
    ? (Array.isArray(options.severity) ? options.severity : [options.severity])
    : null;
  const cveFilter = options.cve?.trim().toUpperCase() ?? null;
  const streamFilter = options.stream?.toLowerCase() ?? null;

  const raw = await fetchRawFeed(feedUrl);

  let filtered = raw;

  if (severityFilter?.length) {
    const ranks = severityFilter.map((s) => SEVERITY_RANK[s] ?? 0);
    const minRank = Math.min(...ranks);
    filtered = filtered.filter(
      (a) => (SEVERITY_RANK[a.severity] ?? 0) >= minRank
    );
  }

  if (cveFilter) {
    filtered = filtered.filter(
      (a) => a.cve?.toUpperCase() === cveFilter
    );
  }

  if (streamFilter) {
    filtered = filtered.filter(
      (a) => a.stream.toLowerCase() === streamFilter
    );
  }

  // Sort: highest severity first, then newest
  filtered.sort((a, b) => {
    const rankDiff =
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (rankDiff !== 0) return rankDiff;
    return new Date(b.published).getTime() - new Date(a.published).getTime();
  });

  const advisories = filtered.slice(0, limit);

  return {
    count: advisories.length,
    fetchedAt: new Date().toISOString(),
    source: feedUrl,
    advisories,
    filters: {
      ...(severityFilter ? { severity: severityFilter } : {}),
      ...(cveFilter ? { cve: cveFilter } : {}),
      ...(streamFilter ? { stream: streamFilter } : {}),
      limit,
    },
  };
}

// ─── Tool executor integration ────────────────────────────────────────────────

/**
 * Lyrie tool definition for `threat_feed`.
 * Register this with ToolExecutor.register() to expose it as an agent tool.
 */
export const threatFeedTool = {
  name: "threat_feed",
  description:
    "Fetch real-time threat intelligence advisories from the Lyrie AI research newsroom (research.lyrie.ai). " +
    "Filters by severity (CRITICAL/HIGH/MEDIUM/LOW), CVE ID, and stream (cve-deepdive, active-exploitation, etc.). " +
    "Returns CVE, CVSS score, headline, summary, affected products, and Lyrie Shield verdict.",
  parameters: {
    severity: {
      type: "string" as const,
      description:
        'Minimum severity filter. Options: CRITICAL, HIGH, MEDIUM, LOW, INFO. ' +
        'Default: all severities. Pass "CRITICAL" to see only critical advisories.',
      required: false,
      enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    },
    cve: {
      type: "string" as const,
      description: "Filter by exact CVE ID, e.g. CVE-2025-12345.",
      required: false,
    },
    stream: {
      type: "string" as const,
      description:
        "Filter by research stream/category: cve-deepdive, active-exploitation, " +
        "zero-day, patch-tuesday, ransomware, supply-chain, nation-state, threat-intel.",
      required: false,
    },
    limit: {
      type: "number" as const,
      description: "Maximum number of advisories to return (default: 20, max: 100).",
      required: false,
      default: 20,
    },
  },
  risk: "safe" as const,
  untrustedOutput: true,
  execute: async (args: Record<string, any>) => {
    try {
      const result = await fetchThreatFeed({
        severity: args.severity as ThreatSeverity | undefined,
        cve: args.cve as string | undefined,
        stream: args.stream as string | undefined,
        limit: Math.min(Number(args.limit) || DEFAULT_LIMIT, 100),
      });

      return {
        success: true,
        output: JSON.stringify(result, null, 2),
        metadata: { count: result.count, source: result.source },
      };
    } catch (err: any) {
      return {
        success: false,
        output: "",
        error: err?.message ?? String(err),
      };
    }
  },
};
