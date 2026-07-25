/**
 * @lyrie/core watch module — continuous exposure monitoring (`lyrie watch`).
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export { probeDomain, realTlsInspector } from "./probe";
export { diffPostureSnapshots } from "./diff";
export { loadLastSnapshot, saveSnapshot, snapshotPath, watchDir } from "./store";
export { WatchEngine } from "./engine";
export type { WatchEngineConfig } from "./engine";
export type {
  PostureSnapshot,
  ProbeOptions,
  ExposedPathResult,
  TlsInfo,
  WatchedHeader,
} from "./types";
export { WATCHED_HEADERS, COMMON_EXPOSED_PATHS } from "./types";
