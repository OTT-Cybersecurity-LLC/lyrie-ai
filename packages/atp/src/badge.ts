/**
 * badge.ts — ATP Compliance Badge.
 *
 * Generates a human-visible SVG badge plus a machine-readable JSON
 * attestation for an agent. Designed to be embedded in READMEs, dashboards,
 * and agent metadata so anyone glancing at an agent can tell:
 *
 *   - what compliance level it claims (Basic / Standard / Full)
 *   - where to verify it (a URL anchored on the cert hash)
 *
 * The badge is NOT cryptographic on its own — it's a UI surface. The
 * `json` payload it ships alongside, however, is verifiable: it embeds the
 * full AIC and the latest BreachAttestation. A consumer that fetches the
 * badge JSON can run the standard `verifyArtifact` pipeline locally without
 * trusting the badge issuer.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  AgentIdentityCertificate,
  BreachAttestation,
  ComplianceLevel,
} from "./types";
import { certIdOf } from "./aic";

export interface BadgeOptions {
  /** Verification base URL (badge links to `${baseUrl}?cert=<hash>`). Default: lyrie.ai. */
  verifyBaseUrl?: string;
  /** Override the displayed compliance label. Auto-derived otherwise. */
  level?: ComplianceLevel;
  /** Short human-readable label shown on the badge (default: "ATP"). */
  label?: string;
}

export interface BadgeOutput {
  svg: string;
  json: {
    version: "1.0";
    level: ComplianceLevel;
    cert: AgentIdentityCertificate;
    attestation: BreachAttestation;
    certId: string;
    verifyUrl: string;
  };
  verifyUrl: string;
}

/**
 * Auto-derive compliance level from the artifacts a caller supplies.
 *   - Has attestation? → ATP-Full
 *   - Has cert with a non-empty scope? → ATP-Standard
 *   - Else → ATP-Basic
 */
function deriveLevel(
  cert: AgentIdentityCertificate,
  attestation: BreachAttestation | undefined,
): ComplianceLevel {
  if (attestation) return "ATP-Full";
  if (cert.scope && cert.scope.allowedTools.length > 0) return "ATP-Standard";
  return "ATP-Basic";
}

/**
 * Generate a verifiable ATP compliance badge for an agent.
 */
export function generateBadge(
  cert: AgentIdentityCertificate,
  attestation: BreachAttestation,
  opts: BadgeOptions = {},
): BadgeOutput {
  const level = opts.level ?? deriveLevel(cert, attestation);
  const baseUrl = opts.verifyBaseUrl ?? "https://lyrie.ai/verify";
  const label = opts.label ?? "ATP";
  const id = certIdOf(cert);
  const verifyUrl = `${baseUrl}?cert=${id}`;

  const color = badgeColor(level);
  const status = level.replace("ATP-", "");
  const svg = renderBadgeSvg({ label, status, color, verifyUrl });

  return {
    svg,
    json: {
      version: "1.0",
      level,
      cert,
      attestation,
      certId: id,
      verifyUrl,
    },
    verifyUrl,
  };
}

function badgeColor(level: ComplianceLevel): string {
  switch (level) {
    case "ATP-Full":
      return "#2EA043"; // green
    case "ATP-Standard":
      return "#1F6FEB"; // blue
    case "ATP-Basic":
      return "#8B949E"; // grey
  }
}

interface RenderInput {
  label: string;
  status: string;
  color: string;
  verifyUrl: string;
}

/**
 * Render a 6.6em-tall shields-style badge as inline SVG.
 *
 * Implementation note: we deliberately produce ASCII-only output (no
 * non-ASCII characters) and hard-code widths so the badge renders identically
 * in any browser without depending on font metrics. Width approximation:
 * label = 6 chars * 7px = 42, status = 7 chars * 7px = 49.
 */
function renderBadgeSvg(input: RenderInput): string {
  const labelWidth = Math.max(40, input.label.length * 7 + 14);
  const statusWidth = Math.max(50, input.status.length * 7 + 14);
  const total = labelWidth + statusWidth;
  const safeUrl = escapeXml(input.verifyUrl);
  const safeLabel = escapeXml(input.label);
  const safeStatus = escapeXml(input.status);

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="20" role="img" aria-label="${safeLabel}: ${safeStatus}">`,
    `<title>${safeLabel}: ${safeStatus}</title>`,
    `<linearGradient id="g" x2="0" y2="100%">`,
    `<stop offset="0" stop-color="#fff" stop-opacity=".12"/>`,
    `<stop offset="1" stop-opacity=".12"/>`,
    `</linearGradient>`,
    `<rect rx="3" width="${total}" height="20" fill="#555"/>`,
    `<rect rx="3" x="${labelWidth}" width="${statusWidth}" height="20" fill="${input.color}"/>`,
    `<rect rx="3" width="${total}" height="20" fill="url(#g)"/>`,
    `<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">`,
    `<text x="${labelWidth / 2}" y="14">${safeLabel}</text>`,
    `<text x="${labelWidth + statusWidth / 2}" y="14">${safeStatus}</text>`,
    `</g>`,
    `<a href="${safeUrl}"><rect width="${total}" height="20" fill-opacity="0"/></a>`,
    `</svg>`,
  ].join("");
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
