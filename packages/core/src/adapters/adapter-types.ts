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

export type AdapterSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface AdapterFinding {
  id: string;
  title: string;
  severity: AdapterSeverity;
  description: string;
  location?: { file: string; line?: number };
  cve?: string;
  cwe?: string;
  remediation?: string;
  extra?: Record<string, unknown>;
}

export interface AdapterOptions {
  extraArgs?: string[];
  timeoutMs?: number;
}

export interface AdapterResult {
  findings: AdapterFinding[];
  scannerName: string;
  scannerVersion: string;
  durationMs: number;
  binaryVerified?: boolean;
  rawOutput?: string;
  warnings?: string[];
}

export interface ScannerAdapter {
  readonly name: string;
  readonly version: string;
  isAvailable(): Promise<boolean>;
  scan(target: string, options?: AdapterOptions): Promise<AdapterResult>;
}
