/**
 * dashboard/ — public Agentic-Attack-Compression live radar (Feature 3).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export {
  anonymizeSignal,
  aggregateFeed,
  type AnonymizedSignal,
  type FeedAggregate,
  type ThreatLevel,
  type Band,
} from "./aggregate";
export {
  CompressionSignalStore,
  type CompressionStoreOptions,
  type FeedSnapshot,
} from "./store";
export {
  handleDashboardRequest,
  createDashboardServer,
  startDashboardServer,
  type DashboardServerOptions,
} from "./server";
export { renderRadarHtml } from "./ui";
