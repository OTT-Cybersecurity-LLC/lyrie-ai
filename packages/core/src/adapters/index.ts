/**
 * Lyrie Scanner Adapters — Public API
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
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
  defaultHasher,
  TRIVY_KNOWN_HASHES,
} from "./trivy";
export type { TrivyOptions, BinaryVerificationResult, BinaryHasher } from "./trivy";

export { SemgrepAdapter, parseSemgrepOutput } from "./semgrep";
export type { SemgrepOptions } from "./semgrep";

export { TruffleHogAdapter, parseTruffleHogOutput, detectPlaceholderHint } from "./trufflehog";
