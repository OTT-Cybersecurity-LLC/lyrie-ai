/**
 * watch/diff.ts — Delta detection between two PostureSnapshots.
 *
 * The entire point of `lyrie watch` is low noise: a scheduled `lyrie hack`
 * re-run would re-report every finding every tick. This module only ever
 * emits an `AdapterFinding` for something that CHANGED between the previous
 * and current snapshot (or, for TLS expiry, is approaching a threshold).
 *
 * Reuses `AdapterFinding` from `../engine/daemon` (per the prompt contract:
 * "reuse the type from daemon.ts") rather than inventing a parallel finding
 * shape.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { AdapterFinding } from "../engine/daemon";
import { WATCHED_HEADERS, type PostureSnapshot, type WatchedHeader } from "./types";

/** Headers whose *removal* or *weakening* is a regression worth alerting on. */
const SECURITY_HARDENING_HEADERS: readonly WatchedHeader[] = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];

/** Headers whose *appearance/change* (version disclosure) is the regression. */
const DISCLOSURE_HEADERS: readonly WatchedHeader[] = ["server", "x-powered-by"];

/** Warn when a TLS cert expires within this many ms (14 days). */
const TLS_EXPIRY_WARNING_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

function findingId(domain: string, kind: string): string {
  return `watch:${domain}:${kind}:${Date.now()}`;
}

/**
 * Diff `previous` → `current` for a domain and return only the deltas as
 * `AdapterFinding[]`. Returns `[]` when nothing meaningfully changed (the
 * "idle tick" case) or when `previous` is `undefined` (first-ever run has
 * nothing to diff against — this establishes the baseline instead).
 */
export function diffPostureSnapshots(
  domain: string,
  previous: PostureSnapshot | undefined,
  current: PostureSnapshot,
): AdapterFinding[] {
  if (!previous) return [];

  const findings: AdapterFinding[] = [];

  // ── Reachability transition ──────────────────────────────────────────────
  if (!previous.unreachable && current.unreachable) {
    findings.push({
      id: findingId(domain, "unreachable"),
      title: `${domain} became unreachable`,
      severity: "high",
      description: current.error ?? "probe could not reach the domain (DNS/connect/timeout)",
      source: "watch",
      timestamp: current.takenAt,
    });
    // Once unreachable, header/path/TLS diffs are meaningless this tick.
    return findings;
  }
  if (previous.unreachable && !current.unreachable) {
    findings.push({
      id: findingId(domain, "reachable-again"),
      title: `${domain} is reachable again`,
      severity: "info",
      description: "domain recovered after a prior unreachable tick",
      source: "watch",
      timestamp: current.takenAt,
    });
  }
  if (current.unreachable) return findings;

  // ── Security-hardening header regressions ────────────────────────────────
  for (const header of SECURITY_HARDENING_HEADERS) {
    const before = previous.headers[header];
    const after = current.headers[header];
    if (before && !after) {
      findings.push({
        id: findingId(domain, `header-removed-${header}`),
        title: `${header} header was removed`,
        severity: "high",
        description: `${domain} previously sent \`${header}: ${before}\` — it is now absent.`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { header, before, after: null },
      });
    } else if (before && after && before !== after) {
      findings.push({
        id: findingId(domain, `header-changed-${header}`),
        title: `${header} header changed`,
        severity: "medium",
        description: `${domain}'s \`${header}\` changed from \`${before}\` to \`${after}\`.`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { header, before, after },
      });
    } else if (!before && after) {
      findings.push({
        id: findingId(domain, `header-added-${header}`),
        title: `${header} header added`,
        severity: "info",
        description: `${domain} now sends \`${header}: ${after}\` (improvement).`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { header, before: null, after },
      });
    }
  }

  // ── Server/version disclosure changes ────────────────────────────────────
  for (const header of DISCLOSURE_HEADERS) {
    const before = previous.headers[header];
    const after = current.headers[header];
    if (before !== after && (before || after)) {
      findings.push({
        id: findingId(domain, `disclosure-${header}`),
        title: `${header} disclosure changed`,
        severity: "low",
        description: `${domain}'s \`${header}\` header went from \`${before ?? "(absent)"}\` to \`${after ?? "(absent)"}\`.`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { header, before: before ?? null, after: after ?? null },
      });
    }
  }

  // ── Newly-exposed common paths ────────────────────────────────────────────
  const prevExposed = new Set(previous.exposedPaths.filter((p) => p.exposed).map((p) => p.path));
  for (const p of current.exposedPaths) {
    if (p.exposed && !prevExposed.has(p.path)) {
      findings.push({
        id: findingId(domain, `path-exposed-${p.path}`),
        title: `Newly-exposed path: ${p.path}`,
        severity: "critical",
        description: `${domain}${p.path} started returning HTTP ${p.status} (was not exposed on the previous check).`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { path: p.path, status: p.status ?? null },
      });
    }
  }

  // ── TLS cert fingerprint / expiry changes ────────────────────────────────
  if (previous.tls && current.tls) {
    if (previous.tls.fingerprintSha256 && current.tls.fingerprintSha256 && previous.tls.fingerprintSha256 !== current.tls.fingerprintSha256) {
      findings.push({
        id: findingId(domain, "tls-fingerprint-changed"),
        title: "TLS certificate fingerprint changed",
        severity: "medium",
        description:
          `${domain}'s certificate fingerprint changed (was ${previous.tls.fingerprintSha256.slice(0, 12)}…, ` +
          `now ${current.tls.fingerprintSha256.slice(0, 12)}…). Expected on routine renewal — verify the new cert is legitimate if unplanned.`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { before: previous.tls.fingerprintSha256, after: current.tls.fingerprintSha256 },
      });
    }
  }
  if (current.tls) {
    const msUntilExpiry = current.tls.expiresAt - current.takenAt;
    if (msUntilExpiry <= TLS_EXPIRY_WARNING_WINDOW_MS) {
      const alreadyWarned =
        previous.tls && previous.tls.expiresAt - previous.takenAt <= TLS_EXPIRY_WARNING_WINDOW_MS;
      if (!alreadyWarned) {
        findings.push({
          id: findingId(domain, "tls-expiry-approaching"),
          title: "TLS certificate expiry approaching",
          severity: msUntilExpiry <= 0 ? "critical" : "medium",
          description:
            msUntilExpiry <= 0
              ? `${domain}'s TLS certificate has EXPIRED.`
              : `${domain}'s TLS certificate expires in ${Math.round(msUntilExpiry / (24 * 60 * 60 * 1000))} day(s).`,
          source: "watch",
          timestamp: current.takenAt,
          metadata: { expiresAt: current.tls.expiresAt },
        });
      }
    }
  }

  // ── New subdomains (only meaningful when an enumerator is actually wired) ─
  if (current.subdomains.length > 0 || previous.subdomains.length > 0) {
    const prevSet = new Set(previous.subdomains);
    const newOnes = current.subdomains.filter((s) => !prevSet.has(s));
    if (newOnes.length > 0) {
      findings.push({
        id: findingId(domain, "new-subdomains"),
        title: `${newOnes.length} new subdomain(s) discovered`,
        severity: "medium",
        description: `New subdomain(s) since last check: ${newOnes.join(", ")}`,
        source: "watch",
        timestamp: current.takenAt,
        metadata: { subdomains: newOnes },
      });
    }
  }

  return findings;
}

export { WATCHED_HEADERS };
