/**
 * Lyrie Scanner Adapters — Public API
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Exports all four external scanner adapters:
 *   • NucleiAdapter   — projectdiscovery/nuclei (web vuln scanning)
 *   • TrivyAdapter    — aquasecurity/trivy (container + fs + CVE)
 *   • SemgrepAdapter  — semgrep/semgrep CE (SAST, 30 langs, 20k rules)
 *   • TruffleHogAdapter — trufflesecurity/trufflehog (secret detection)
 *
 * Usage:
 *   import { NucleiAdapter, TrivyAdapter, SemgrepAdapter, TruffleHogAdapter } from "./adapters";
 *
 * © OTT Cybersecurity LLC — Released under MIT License.
 */

export type {
  ScannerAdapter,
  AdapterFinding,
  AdapterResult,
  AdapterOptions,
  AdapterSeverity,
} from "./adapter-types";

export { NucleiAdapter, parseNucleiOutput } from "./nuclei";
export type { NucleiOptions } from "./nuclei";

export {
  TrivyAdapter,
  parseTrivyOutput,
  verifyBinaryHash,
  hashBinary,
  TRIVY_KNOWN_HASHES,
} from "./trivy";
export type { TrivyOptions, BinaryVerificationResult } from "./trivy";

export { SemgrepAdapter, parseSemgrepOutput } from "./semgrep";
export type { SemgrepOptions } from "./semgrep";

export { TruffleHogAdapter, parseTruffleHogOutput } from "./trufflehog";
