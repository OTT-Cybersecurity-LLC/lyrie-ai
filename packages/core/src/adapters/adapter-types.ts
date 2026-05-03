/**
 * Lyrie Scanner Adapter — Shared Types
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Every external scanner (Nuclei, Trivy, Semgrep CE, TruffleHog) implements
 * the `ScannerAdapter` interface so the orchestrator can call them uniformly.
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

// ─── Core types ──────────────────────────────────────────────────────────────

export type AdapterSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface AdapterFinding {
  /** Stable finding id (from upstream tool or generated). */
  id: string;
  title: string;
  severity: AdapterSeverity;
  description: string;
  location?: {
    file: string;
    line?: number;
  };
  cve?: string;
  cwe?: string;
  remediation?: string;
  /** Arbitrary extra metadata from the upstream tool. */
  extra?: Record<string, unknown>;
}

export interface AdapterOptions {
  /** Raw extra flags passed through to the binary. */
  extraArgs?: string[];
  /** Max time to wait for the scanner to finish (ms). Default: 60_000. */
  timeoutMs?: number;
}

export interface AdapterResult {
  findings: AdapterFinding[];
  scannerName: string;
  scannerVersion: string;
  durationMs: number;
  /** Set to false if binary verification failed (Trivy). */
  binaryVerified?: boolean;
  /** Raw stdout of the scanner process. */
  rawOutput?: string;
  /** Non-fatal warnings (e.g. binary-verification mismatch). */
  warnings?: string[];
}

export interface ScannerAdapter {
  readonly name: string;
  readonly version: string;
  /** Returns true if the scanner binary is reachable on PATH. */
  isAvailable(): Promise<boolean>;
  scan(target: string, options?: AdapterOptions): Promise<AdapterResult>;
}
