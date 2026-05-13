import { promises as dns } from "node:dns";

export class SsrfError extends Error {
  readonly code = "SSRF_BLOCKED";
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

export interface UrlGuardOptions {
  /**
   * Optional allowlist of host patterns. Each entry can be:
   *   - exact host match: "api.example.com"
   *   - leading dot wildcard: ".example.com" (matches example.com + any subdomain)
   *   - "*" (matches anything not blocked by the IP guard)
   * When omitted the only check is the private-IP/loopback guard.
   */
  allowList?: string[];
  /** Allow loopback (127.0.0.0/8, ::1). Default false. */
  allowLoopback?: boolean;
  /** Allow private RFC1918 / ULA. Default false. */
  allowPrivate?: boolean;
  /** Allow link-local (169.254/16, fe80::/10). Default false. */
  allowLinkLocal?: boolean;
  /** Allowed schemes. Default ["http","https"]. */
  allowedSchemes?: string[];
  /** Resolve DNS and re-check the resolved IP. Default true. */
  resolveDns?: boolean;
}

const DEFAULT_OPTS: Required<Omit<UrlGuardOptions, "allowList">> = {
  allowLoopback: false,
  allowPrivate: false,
  allowLinkLocal: false,
  allowedSchemes: ["http:", "https:"],
  resolveDns: true,
};

// ─── IP classification ───────────────────────────────────────────────────────

function ipv4ToBytes(addr: string): number[] | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out.push(n);
  }
  return out;
}

function isIPv4Address(addr: string): boolean {
  return ipv4ToBytes(addr) !== null;
}

function isIPv6Address(addr: string): boolean {
  // Strip zone id
  const a = addr.replace(/%.*$/, "");
  return /^[0-9a-f:]+$/i.test(a) && a.includes(":");
}

function expandIPv6(addr: string): number[] | null {
  // Returns 16 bytes or null. Supports `::` and IPv4-mapped (::ffff:127.0.0.1).
  let a = addr.replace(/%.*$/, "").toLowerCase();
  // Handle embedded IPv4 (e.g. ::ffff:127.0.0.1)
  const v4Match = a.match(/^(.*:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Match) {
    const v4 = ipv4ToBytes(v4Match[2]);
    if (!v4) return null;
    a = (v4Match[1] ?? "") + v4
      .map((b, i) => (i % 2 === 0 ? b.toString(16).padStart(2, "0") : b.toString(16).padStart(2, "0") + (i === 3 ? "" : ":")))
      .join("")
      .replace(/^/, "");
    // Re-format manually:
    const hi = (v4[0] << 8) | v4[1];
    const lo = (v4[2] << 8) | v4[3];
    a = (v4Match[1] ?? "") + hi.toString(16) + ":" + lo.toString(16);
  }

  const halves = a.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const g of groups) {
    if (g === "") return null;
    const n = parseInt(g, 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null;
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  return bytes;
}

function ipv4InRange(bytes: number[], cidr: string): boolean {
  const [net, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const netBytes = ipv4ToBytes(net);
  if (!netBytes) return false;
  let acc = 0;
  let netAcc = 0;
  for (let i = 0; i < 4; i++) {
    acc = (acc << 8) | bytes[i];
    netAcc = (netAcc << 8) | netBytes[i];
  }
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((acc >>> 0) & mask) === ((netAcc >>> 0) & mask);
}

const PRIVATE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const LOOPBACK_V4 = ["127.0.0.0/8"];
const LINK_LOCAL_V4 = ["169.254.0.0/16"];
const RESERVED_V4 = [
  "0.0.0.0/8",
  "100.64.0.0/10", // CGNAT
  "192.0.0.0/24",
  "192.0.2.0/24",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // class E
];

interface IpClass {
  loopback: boolean;
  privateNet: boolean;
  linkLocal: boolean;
  reserved: boolean;
}

function classifyV4(addr: string): IpClass | null {
  const bytes = ipv4ToBytes(addr);
  if (!bytes) return null;
  return {
    loopback: LOOPBACK_V4.some((c) => ipv4InRange(bytes, c)),
    privateNet: PRIVATE_V4.some((c) => ipv4InRange(bytes, c)),
    linkLocal: LINK_LOCAL_V4.some((c) => ipv4InRange(bytes, c)),
    reserved: RESERVED_V4.some((c) => ipv4InRange(bytes, c)),
  };
}

function classifyV6(addr: string): IpClass | null {
  const bytes = expandIPv6(addr);
  if (!bytes) return null;
  // ::1 = loopback
  const loopback =
    bytes.slice(0, 15).every((b) => b === 0) && bytes[15] === 1;
  // fc00::/7 = unique local addresses (private)
  const privateNet = (bytes[0] & 0xfe) === 0xfc;
  // fe80::/10 = link local
  const linkLocal = bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80;
  // ff00::/8 = multicast (reserved here)
  const multicast = bytes[0] === 0xff;
  // ::ffff:0:0/96 = IPv4-mapped
  const mapped =
    bytes.slice(0, 10).every((b) => b === 0) &&
    bytes[10] === 0xff &&
    bytes[11] === 0xff;
  if (mapped) {
    const v4 = `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
    const v4cls = classifyV4(v4);
    if (v4cls) return v4cls;
  }
  return { loopback, privateNet, linkLocal, reserved: multicast };
}

function classifyIp(addr: string): IpClass | null {
  if (isIPv4Address(addr)) return classifyV4(addr);
  if (isIPv6Address(addr)) return classifyV6(addr);
  return null;
}

// ─── Allowlist matching ──────────────────────────────────────────────────────

function hostnameMatchesAllow(hostname: string, allowList: string[]): boolean {
  const h = hostname.toLowerCase();
  for (const entry of allowList) {
    if (entry === "*") return true;
    const e = entry.toLowerCase();
    if (e.startsWith(".")) {
      if (h === e.slice(1) || h.endsWith(e)) return true;
    } else if (h === e) {
      return true;
    }
  }
  return false;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/** Synchronous host check (no DNS). Returns false if the URL is unsafe. */
export function isAllowedHost(input: string | URL, opts: UrlGuardOptions = {}): boolean {
  try {
    assertSafeUrlSync(input, opts);
    return true;
  } catch {
    return false;
  }
}

/** Throws SsrfError if the URL is unsafe (does not perform DNS). */
export function assertSafeUrlSync(input: string | URL, opts: UrlGuardOptions = {}): URL {
  const o = { ...DEFAULT_OPTS, ...opts };
  const u = input instanceof URL ? input : new URL(input);
  if (!o.allowedSchemes.includes(u.protocol)) {
    throw new SsrfError(`Disallowed scheme: ${u.protocol}`);
  }
  const host = u.hostname;
  if (!host) throw new SsrfError("URL has no hostname");

  // Direct IP literal — classify immediately.
  const ipClass = classifyIp(host) ?? classifyIp(host.replace(/^\[|\]$/g, ""));
  if (ipClass) {
    if (ipClass.loopback && !o.allowLoopback) throw new SsrfError(`Loopback IP blocked: ${host}`);
    if (ipClass.privateNet && !o.allowPrivate) throw new SsrfError(`Private IP blocked: ${host}`);
    if (ipClass.linkLocal && !o.allowLinkLocal) throw new SsrfError(`Link-local IP blocked: ${host}`);
    if (ipClass.reserved) throw new SsrfError(`Reserved IP blocked: ${host}`);
  }

  if (opts.allowList && opts.allowList.length > 0) {
    if (!hostnameMatchesAllow(host, opts.allowList)) {
      throw new SsrfError(`Host not on allowlist: ${host}`);
    }
  }

  return u;
}

/** Async version — also performs DNS resolution and re-checks the IP. */
export async function assertSafeUrl(input: string | URL, opts: UrlGuardOptions = {}): Promise<URL> {
  const u = assertSafeUrlSync(input, opts);
  const o = { ...DEFAULT_OPTS, ...opts };
  if (!o.resolveDns) return u;

  // Skip DNS for IP literals (already classified above).
  if (classifyIp(u.hostname) || classifyIp(u.hostname.replace(/^\[|\]$/g, ""))) {
    return u;
  }

  let addrs: { address: string; family: number }[] = [];
  try {
    addrs = await dns.lookup(u.hostname, { all: true });
  } catch (err: any) {
    throw new SsrfError(`DNS lookup failed for ${u.hostname}: ${err.message}`);
  }
  for (const a of addrs) {
    const cls = classifyIp(a.address);
    if (!cls) continue;
    if (cls.loopback && !o.allowLoopback) throw new SsrfError(`DNS resolves to loopback: ${a.address}`);
    if (cls.privateNet && !o.allowPrivate) throw new SsrfError(`DNS resolves to private IP: ${a.address}`);
    if (cls.linkLocal && !o.allowLinkLocal) throw new SsrfError(`DNS resolves to link-local: ${a.address}`);
    if (cls.reserved) throw new SsrfError(`DNS resolves to reserved IP: ${a.address}`);
  }
  return u;
}

export interface SafeFetchOptions extends UrlGuardOptions {
  /** Request timeout in ms (default 30 000). */
  timeoutMs?: number;
  /** Max bytes to read from response (default 10 MiB). */
  maxBytes?: number;
  /** Max number of redirects to manually follow (default 5; set 0 to disallow). */
  maxRedirects?: number;
}

/**
 * Drop-in `fetch()` replacement with SSRF protection.
 *  - Validates the URL synchronously and after DNS.
 *  - Forces `redirect: "manual"` and re-validates each Location header.
 *  - Enforces a timeout and a response-size limit.
 */
export async function safeFetch(
  url: string | URL,
  init: RequestInit = {},
  opts: SafeFetchOptions = {},
): Promise<Response> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const maxBytes = opts.maxBytes ?? 10 * 1024 * 1024;
  const maxRedirects = opts.maxRedirects ?? 5;

  let current = await assertSafeUrl(url, opts);
  let redirects = 0;

  for (;;) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(current, {
        ...init,
        redirect: "manual",
        signal: ctl.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      if (redirects >= maxRedirects) {
        throw new SsrfError(`Too many redirects (>${maxRedirects})`);
      }
      const loc = res.headers.get("location") as string;
      const next = new URL(loc, current);
      current = await assertSafeUrl(next, opts);
      redirects++;
      continue;
    }

    // Enforce response size by streaming.
    const cl = Number(res.headers.get("content-length") ?? "0");
    if (cl > maxBytes) {
      throw new SsrfError(`Response too large: ${cl} > ${maxBytes}`);
    }
    return res;
  }
}
