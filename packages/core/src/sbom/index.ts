/**
 * sbom/ — Living SBOM exploitability revalidation (Feature 5).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export {
  generateSbom,
  toPurl,
  canonicalJson,
  sha256,
  SbomStore,
  SBOM_TOOL_VERSION,
  type ManifestComponent,
  type SbomManifest,
  type SbomStoreOptions,
} from "./generate";
export {
  revalidateSbom,
  computeDeltas,
  reattest,
} from "./revalidate";
export {
  runScheduledRevalidation,
  type ScheduledRevalidationResult,
} from "./scheduler";
export type {
  Ecosystem,
  SbomComponent,
  SbomArtifact,
  ComponentExploitability,
  SbomExploitabilitySnapshot,
  DeltaKind,
  ExploitabilityDelta,
  RevalidationReport,
  Reattestation,
} from "./types";
