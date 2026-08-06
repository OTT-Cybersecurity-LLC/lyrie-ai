/**
 * watch/probe.ts — Single point-in-time posture capture for a domain.
 *
 * Pure-ish: all I/O is behind injectable hooks (`fetchFn`, `tlsInspector`,
 * `subdomainEnum`) so the probe is fully unit-testable without real network
 * access, matching the pattern used by `MCPSecurityScanner.scan()` and
 * `evaluateMcpTrust()` elsewhere in this repo.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { connect, type TLSSocket } from "node:tls";
import { createHash } from "node:crypto";

import {
  COMMON_EXPOSED_PATHS,
  WATCHED_HEADERS,
  type ExposedPathResult,
  type PostureSnapshot,
  type ProbeOptions,
  type TlsInfo,
  type WatchedHeader,
} from "./types";

/**
 * Real (non-test) TLS inspector — opens a raw TLS socket to `domain:443`
 * and reads the peer certificate. Not used in unit tests (see probe.test.ts
 * for the injected-fake-inspector path); exported so an integration test or
 * `scripts/watch.ts` can use it directly.
 */
export function realTlsInspector(domain: string, timeoutMs = 8000): Promise<TlsInfo | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: TlsInfo | undefined) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };

    const socket: TLSSocket = connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        timeout: timeoutMs,
        // Intentional: this is a read-only certificate *inspector*, not a
        // data channel. We must still complete the handshake against
        // expired/self-signed/misconfigured certs so posture scans can
        // report *why* a cert is bad (expiry, issuer, fingerprint) instead
        // of just failing to connect. No request/response body ever
        // traverses this socket — see fetchWithTimeout() below for the
        // actual data-fetching path, which uses normal validated TLS via
        // the injected `fetchFn`. Do not reuse this socket for anything
        // beyond reading the peer certificate.
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          if (!cert || !cert.valid_to) {
            done(undefined);
          } else {
            const raw = (cert as { raw?: Buffer }).raw;
            done({
              expiresAt: new Date(cert.valid_to).getTime(),
              fingerprintSha256: raw ? createHash("sha256").update(raw).digest("hex") : undefined,
              issuer: cert.issuer ? Object.values(cert.issuer).join(", ") : undefined,
              subject: cert.subject ? Object.values(cert.subject).join(", ") : undefined,
            });
          }
        } catch {
          done(undefined);
        } finally {
          socket.end();
        }
      },
    );
    socket.on("error", () => done(undefined));
    socket.on("timeout", () => {
      socket.destroy();
      done(undefined);
    });
  });
}

async function fetchWithTimeout(
  fetchFn: typeof fetch,
  url: string,
  timeoutMs: number,
): Promise<Response | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchFn(url, { signal: controller.signal, redirect: "manual" });
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Take a single posture snapshot of `domain`. Never throws — connection
 * failures are captured as `unreachable: true` in the returned snapshot so
 * a scheduled watch tick can diff cleanly instead of crashing the loop.
 */
export async function probeDomain(domain: string, opts: ProbeOptions = {}): Promise<PostureSnapshot> {
  const fetchFn = opts.fetchFn ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 8000;
  const takenAt = Date.now();

  const base: PostureSnapshot = {
    domain,
    takenAt,
    headers: {},
    exposedPaths: [],
    subdomains: [],
  };

  const rootUrl = `https://${domain}/`;
  const rootRes = await fetchWithTimeout(fetchFn, rootUrl, timeoutMs);
  if (!rootRes) {
    return { ...base, unreachable: true, error: `failed to reach ${rootUrl}` };
  }

  const headers: Partial<Record<WatchedHeader, string>> = {};
  for (const name of WATCHED_HEADERS) {
    const v = rootRes.headers.get(name);
    if (v !== null && v !== undefined) headers[name] = v;
  }

  let tls: TlsInfo | undefined;
  try {
    tls = opts.tlsInspector ? await opts.tlsInspector(domain) : await realTlsInspector(domain, timeoutMs);
  } catch {
    // TLS inspection is best-effort — a broken/throwing inspector should
    // degrade to "no TLS info this tick", not crash the whole probe.
    tls = undefined;
  }

  const exposedPaths: ExposedPathResult[] = [];
  for (const path of COMMON_EXPOSED_PATHS) {
    const res = await fetchWithTimeout(fetchFn, `https://${domain}${path}`, timeoutMs);
    if (!res) {
      exposedPaths.push({ path, exposed: false });
      continue;
    }
    // A 2xx (or 3xx not aimed at a generic error/login page) on a path that
    // should not exist publicly is the signal. Conservative: only 2xx counts
    // as "exposed" to keep false positives low (many sites 200 their SPA
    // shell for every path).
    exposedPaths.push({ path, exposed: res.status >= 200 && res.status < 300, status: res.status });
  }

  const subdomains = opts.subdomainEnum ? await opts.subdomainEnum(domain) : [];

  return { ...base, headers, tls, exposedPaths, subdomains };
}
