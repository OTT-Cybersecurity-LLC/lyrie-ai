/**
 * watch/engine.ts — WatchEngine, the tick-driven core of `lyrie watch <domain>`.
 *
 * Deliberately built as a thin subclass of `DaemonEngine` (packages/core/src
 * /engine/daemon.ts) rather than a second tick loop — reuses its start/stop/
 * interruptible-sleep/event-emitter machinery wholesale and only overrides
 * `_checkThreatIntel()` (the pluggable hook `DaemonEngine` already exposes
 * for exactly this kind of "what changed since last time" check) to run the
 * probe→diff→persist cycle for one or more watched domains.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { DaemonEngine, type AdapterFinding, type DaemonEngineConfig } from "../engine/daemon";
import { diffPostureSnapshots } from "./diff";
import { probeDomain } from "./probe";
import { loadLastSnapshot, saveSnapshot, watchDir } from "./store";
import type { ProbeOptions } from "./types";

export interface WatchEngineConfig extends DaemonEngineConfig {
  /** Domains to monitor on every tick. */
  domains: string[];
  /** Snapshot storage directory override (tests use a tmp dir). */
  storeDir?: string;
  /** Probe hooks (fetch/tls/subdomain injection — see probe.ts). */
  probeOptions?: ProbeOptions;
}

/**
 * WatchEngine — continuous exposure monitoring over `DaemonEngine`'s tick
 * loop. Each tick probes every configured domain, diffs against the last
 * stored snapshot, and only surfaces `AdapterFinding[]` for what changed
 * (see diff.ts's module doc for why — this is the whole point vs. a naive
 * `lyrie hack` cron re-run).
 */
export class WatchEngine extends DaemonEngine {
  private _watchConfig: WatchEngineConfig | null = null;

  async start(config: WatchEngineConfig): Promise<void> {
    this._watchConfig = config;
    // threatWatch must be true for DaemonEngine.tick() to invoke
    // _checkThreatIntel() at all — WatchEngine's entire job lives there.
    await super.start({ ...config, threatWatch: true });
  }

  /**
   * One probe+diff+persist pass over every configured domain. Overrides
   * DaemonEngine's default (network-free) no-op implementation.
   */
  protected async _checkThreatIntel(_config: DaemonEngineConfig): Promise<AdapterFinding[]> {
    const wc = this._watchConfig;
    if (!wc) return [];

    const dir = wc.storeDir ?? watchDir();
    const allFindings: AdapterFinding[] = [];

    for (const domain of wc.domains) {
      try {
        const previous = loadLastSnapshot(domain, dir);
        const current = await probeDomain(domain, wc.probeOptions);
        const findings = diffPostureSnapshots(domain, previous, current);
        allFindings.push(...findings);
        saveSnapshot(current, dir);
      } catch (err) {
        allFindings.push({
          id: `watch-err-${domain}-${Date.now()}`,
          title: `lyrie watch probe failed for ${domain}`,
          severity: "low",
          description: String(err),
          source: "watch",
          timestamp: Date.now(),
        });
      }
    }

    return allFindings;
  }
}
