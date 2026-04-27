/**
 * Lyrie Execution Backends — public entry.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

export {
  SUPPORTED_BACKENDS,
  type AnyBackendConfig,
  type Backend,
  type BackendKind,
  type BackendResourceHints,
  type BackendRunRequest,
  type BackendRunResult,
  type DaytonaBackendConfig,
  type LocalBackendConfig,
  type ModalBackendConfig,
} from "./types";
export { LocalBackend, emptySarif } from "./local";
export { DaytonaBackend, extractSarifSummary, type FetchFn } from "./daytona";
export { ModalBackend } from "./modal";
export {
  describeBackend,
  getBackend,
  readDaytonaConfigFromEnv,
  readLocalConfigFromEnv,
  readModalConfigFromEnv,
  resolveBackendKind,
  type BackendFactoryOptions,
} from "./factory";
