/**
 * sbom/generate.ts — generate a minimal CycloneDX-style SBOM artifact from a
 * manifest (a flat list of components), plus a small in-memory/file-backed
 * store so a "living" SBOM can be re-validated over time (Feature 5).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { Ecosystem, SbomArtifact, SbomComponent } from "./types";

export const SBOM_TOOL_VERSION = "lyrie-sbom-1.0.0";

/** A single input component (what the caller knows before we build the SBOM). */
export interface ManifestComponent {
  name: string;
  version?: string;
  ecosystem: Ecosystem;
}

export interface SbomManifest {
  /** Optional subject name (project/app). */
  name?: string;
  components: ManifestComponent[];
}

/** Map an ecosystem to its purl "type" segment. */
function purlType(eco: Ecosystem): string {
  switch (eco) {
    case "npm": return "npm";
    case "cargo": return "cargo";
    case "pip": return "pypi";
    case "go": return "golang";
    case "ruby": return "gem";
    case "php": return "composer";
    case "java": return "maven";
    default: return "generic";
  }
}

/** Build a Package URL for a component. */
export function toPurl(c: ManifestComponent): string {
  const base = `pkg:${purlType(c.ecosystem)}/${c.name}`;
  return c.version ? `${base}@${c.version}` : base;
}

/**
 * Generate an SBOM artifact from a manifest. Deterministic apart from the
 * serial number + timestamp, which can be injected for reproducible tests.
 */
export function generateSbom(
  manifest: SbomManifest,
  opts: { serialNumber?: string; timestamp?: string } = {},
): SbomArtifact {
  const components: SbomComponent[] = manifest.components.map((c, i) => ({
    bomRef: `${c.ecosystem}:${c.name}@${c.version ?? "*"}#${i}`,
    type: "library",
    name: c.name,
    version: c.version,
    ecosystem: c.ecosystem,
    purl: toPurl(c),
  }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: opts.serialNumber ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tool: { vendor: "OTT Cybersecurity LLC", name: "Lyrie SBOM", version: SBOM_TOOL_VERSION },
      component: manifest.name ? { type: "application", name: manifest.name } : undefined,
    },
    components,
  };
}

/** Canonical JSON (stable key order) for hashing/attestation. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

/** SHA-256 hex digest over canonical JSON. */
export function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

// ─── Living-SBOM store ──────────────────────────────────────────────────────

import type { SbomExploitabilitySnapshot } from "./types";

interface StoredSbom {
  artifact: SbomArtifact;
  /** Most recent exploitability snapshot, if any. */
  lastSnapshot?: SbomExploitabilitySnapshot;
}

export interface SbomStoreOptions {
  /** Optional JSON file to persist to / load from. */
  filePath?: string;
}

/**
 * In-memory (optionally file-backed) store keyed by SBOM serial number.
 * Holds the artifact + the last exploitability snapshot so revalidation can
 * compute deltas across runs (the "living" part).
 */
export class SbomStore {
  private map = new Map<string, StoredSbom>();
  private readonly filePath?: string;

  constructor(opts: SbomStoreOptions = {}) {
    this.filePath = opts.filePath;
    if (this.filePath && existsSync(this.filePath)) this.load();
  }

  put(artifact: SbomArtifact): void {
    const existing = this.map.get(artifact.serialNumber);
    this.map.set(artifact.serialNumber, { artifact, lastSnapshot: existing?.lastSnapshot });
    this.persist();
  }

  get(serialNumber: string): SbomArtifact | undefined {
    return this.map.get(serialNumber)?.artifact;
  }

  getLastSnapshot(serialNumber: string): SbomExploitabilitySnapshot | undefined {
    return this.map.get(serialNumber)?.lastSnapshot;
  }

  setLastSnapshot(serialNumber: string, snapshot: SbomExploitabilitySnapshot): void {
    const entry = this.map.get(serialNumber);
    if (!entry) return;
    entry.lastSnapshot = snapshot;
    this.persist();
  }

  list(): SbomArtifact[] {
    return [...this.map.values()].map((s) => s.artifact);
  }

  private persist(): void {
    if (!this.filePath) return;
    try {
      mkdirSync(dirname(this.filePath), { recursive: true });
      writeFileSync(this.filePath, JSON.stringify([...this.map.entries()]), "utf8");
    } catch {
      /* best-effort */
    }
  }

  private load(): void {
    try {
      const raw = readFileSync(this.filePath!, "utf8");
      const entries = JSON.parse(raw) as Array<[string, StoredSbom]>;
      this.map = new Map(entries);
    } catch {
      /* start empty */
    }
  }
}
