/**
 * Lyrie Hack — public exports.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

export {
  HackOrchestrator,
  runHack,
  ORCHESTRATOR_VERSION,
  type HackEvent,
  type HackEventListener,
  type HackMode,
  type HackOptions,
  type OutputFormat,
  type Phase,
  type PhaseEvent,
  type FindingEvent,
} from "./orchestrator";

export {
  extractDependencyGraph,
  languagesFromEcosystems,
  DEPENDENCY_GRAPH_VERSION,
  type DependencyGraph,
  type DependencyGraphOptions,
  type DependencyPackage,
  type Ecosystem,
} from "./dependency-graph";

export {
  detectSecrets,
  scanContent as scanContentForSecrets,
  SECRET_DETECTOR_VERSION,
  type SecretDetectorOptions,
  type SecretFinding,
  type SecretReport,
  type SecretType,
} from "./secret-detector";

export {
  suggestRemediation,
  suggestSecretRemediation,
  AUTO_REMEDIATION_VERSION,
  type RemediationSuggestion,
} from "./auto-remediation";

export {
  toJson,
  toMarkdown,
  toSarif,
  REPORT_ENGINE_VERSION,
  type HackReport,
  type SarifLog,
  type Severity,
} from "./report-engine";
