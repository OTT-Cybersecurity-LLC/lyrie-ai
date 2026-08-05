/**
 * dashboard.test.ts — anonymization/aggregation pipeline + feed endpoint +
 * daemon publish wiring for the public Agentic-Attack-Compression radar
 * (Feature 3). No real sockets are bound for the handler tests; the
 * end-to-end server test binds an ephemeral loopback port.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import type { AttackCompressionSignature } from "../engine/agentic-threat-bridge";
import { anonymizeSignal, aggregateFeed } from "./aggregate";
import { CompressionSignalStore } from "./store";
import { handleDashboardRequest, startDashboardServer } from "./server";
import { DaemonEngine, type DaemonEngineConfig } from "../engine/daemon";
import type { AgenticBridgeResponse } from "../engine/agentic-threat-bridge";

function sig(overrides: Partial<AttackCompressionSignature> = {}): AttackCompressionSignature {
  return {
    phases_observed: ["Recon", "Execution", "Exfiltration"],
    compression_ratio: 4.2,
    channel: 3,
    ttp_entropy: 1.5,
    confidence: 0.9,
    threat_level: "High",
    ...overrides,
  };
}

// ─── anonymizeSignal ────────────────────────────────────────────────────────

describe("anonymizeSignal", () => {
  test("floors time to the minute + buckets bands + counts phases", () => {
    const t = 1_700_000_123_456;
    const a = anonymizeSignal(sig({ phases_observed: ["Recon", "Recon", "Execution"] }), t);
    expect(a.timeBucketMs).toBe(Math.floor(t / 60000) * 60000);
    expect(a.channel).toBe(3);
    expect(a.threatLevel).toBe("High");
    expect(a.phaseCounts.Recon).toBe(2);
    expect(a.phaseCounts.Execution).toBe(1);
    expect(a.phases).toEqual(["Execution", "Recon"]); // sorted + deduped
    expect(a.compressionBand).toBe("high"); // 4.2 -> high band
    expect(a.entropyBand).toBe("high"); // 1.5 -> high band
    expect(a.confidenceBand).toBe("severe"); // 0.9 -> severe band
  });

  test("strips everything host/tool-specific — output keys are a fixed allowlist", () => {
    const a = anonymizeSignal(sig(), 0);
    const keys = Object.keys(a).sort();
    expect(keys).toEqual(
      [
        "channel",
        "compressionBand",
        "confidenceBand",
        "entropyBand",
        "phaseCounts",
        "phases",
        "threatLevel",
        "timeBucketMs",
      ].sort(),
    );
    // No free-text / fingerprint fields leaked.
    expect(JSON.stringify(a)).not.toContain("tool_fingerprint");
  });

  test("clamps out-of-range channel into 1..3", () => {
    expect(anonymizeSignal(sig({ channel: 0 }), 0).channel).toBe(1);
    expect(anonymizeSignal(sig({ channel: 9 }), 0).channel).toBe(3);
  });
});

// ─── aggregateFeed ──────────────────────────────────────────────────────────

describe("aggregateFeed", () => {
  test("rolls up channel/threat/phase counts + window bounds", () => {
    const a1 = anonymizeSignal(sig({ channel: 3, threat_level: "High", phases_observed: ["Recon"] }), 60_000);
    const a2 = anonymizeSignal(sig({ channel: 1, threat_level: "Low", phases_observed: ["Recon", "Execution"] }), 120_000);
    const agg = aggregateFeed([a1, a2]);
    expect(agg.total).toBe(2);
    expect(agg.byChannel[3]).toBe(1);
    expect(agg.byChannel[1]).toBe(1);
    expect(agg.byThreatLevel.High).toBe(1);
    expect(agg.byThreatLevel.Low).toBe(1);
    expect(agg.byPhase.Recon).toBe(2);
    expect(agg.byPhase.Execution).toBe(1);
    expect(agg.windowStartMs).toBe(60_000);
    expect(agg.windowEndMs).toBe(120_000);
  });

  test("empty input yields zeroed aggregate", () => {
    const agg = aggregateFeed([]);
    expect(agg.total).toBe(0);
    expect(agg.windowStartMs).toBeNull();
  });
});

// ─── CompressionSignalStore ─────────────────────────────────────────────────

describe("CompressionSignalStore", () => {
  test("ring capacity is enforced", () => {
    const store = new CompressionSignalStore({ capacity: 3 });
    for (let i = 0; i < 5; i++) store.publish(anonymizeSignal(sig(), 60_000 * (i + 1)));
    expect(store.size()).toBe(3);
  });

  test("snapshot returns most-recent-first + aggregate", () => {
    const store = new CompressionSignalStore();
    store.publish(anonymizeSignal(sig(), 60_000));
    store.publish(anonymizeSignal(sig(), 120_000));
    const snap = store.snapshot(180_000);
    expect(snap.signals[0].timeBucketMs).toBe(120_000);
    expect(snap.aggregate.total).toBe(2);
  });

  test("retention window drops stale signals from snapshot", () => {
    const store = new CompressionSignalStore({ retentionMs: 60_000 });
    store.publish(anonymizeSignal(sig(), 0)); // old
    store.publish(anonymizeSignal(sig(), 120_000)); // recent
    const snap = store.snapshot(120_000);
    // Only the recent one (>= 120000-60000) survives.
    expect(snap.aggregate.total).toBe(1);
    expect(snap.signals[0].timeBucketMs).toBe(120_000);
  });
});

// ─── handleDashboardRequest ─────────────────────────────────────────────────

describe("handleDashboardRequest", () => {
  const store = new CompressionSignalStore();
  store.publish(anonymizeSignal(sig(), 60_000));

  test("GET /api/compression/feed returns JSON snapshot", () => {
    const r = handleDashboardRequest("GET", "/api/compression/feed", { store, now: () => 60_000 });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("application/json");
    const parsed = JSON.parse(r.body);
    expect(parsed.aggregate.total).toBe(1);
  });

  test("GET / returns the self-contained HTML radar", () => {
    const r = handleDashboardRequest("GET", "/", { store });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("text/html");
    expect(r.body).toContain("COMPRESSION RADAR");
    expect(r.body).toContain("/api/compression/feed");
  });

  test("GET /healthz returns ok", () => {
    const r = handleDashboardRequest("GET", "/healthz", { store });
    expect(JSON.parse(r.body).ok).toBe(true);
  });

  test("non-GET is 405", () => {
    const r = handleDashboardRequest("POST", "/api/compression/feed", { store });
    expect(r.status).toBe(405);
  });

  test("unknown path is 404", () => {
    const r = handleDashboardRequest("GET", "/nope", { store });
    expect(r.status).toBe(404);
  });
});

// ─── end-to-end server ──────────────────────────────────────────────────────

describe("dashboard server (loopback)", () => {
  test("serves the feed over a real ephemeral port", async () => {
    const store = new CompressionSignalStore();
    store.publish(anonymizeSignal(sig(), Date.now()));
    const { server, port } = await startDashboardServer({ store, host: "127.0.0.1" });
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/compression/feed`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.aggregate.total).toBe(1);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

// ─── daemon publish wiring ──────────────────────────────────────────────────

/**
 * Subclass that shims the private Rust-bridge field with a canned response so
 * the REAL base `_checkAgenticThreats` (which contains the publish wiring)
 * runs unchanged — this exercises the actual production code path, not a
 * reimplementation of it.
 */
class FakeDaemon extends DaemonEngine {
  constructor(canned: AgenticBridgeResponse) {
    super();
    // Replace the private bridge with a fake that is "available" and returns
    // the canned response. Cast through unknown to reach the private field.
    (this as unknown as { _agenticBridge: { isAvailable: () => boolean; run: () => Promise<AgenticBridgeResponse> } })._agenticBridge = {
      isAvailable: () => true,
      run: async () => canned,
    };
  }
}

describe("DaemonEngine → dashboard publish", () => {
  const cfg: DaemonEngineConfig = {
    intervalMs: 1000,
    threatWatch: true,
    selfHeal: false,
    provider: "test",
    channels: [],
    maxTicksBeforeRest: 1,
  };

  test("publishes an anonymized signal when a non-None compression signature is seen", async () => {
    const canned: AgenticBridgeResponse = {
      compression: sig({ threat_level: "Critical" }),
      prompt_injection: null,
      self_propagation: null,
      ai_sink_write: null,
    };
    const daemon = new FakeDaemon(canned);
    const store = new CompressionSignalStore();
    daemon.setCompressionStore(store);
    await daemon.start(cfg);
    expect(store.size()).toBeGreaterThanOrEqual(1);
    const snap = store.snapshot();
    expect(snap.aggregate.byThreatLevel.Critical).toBeGreaterThanOrEqual(1);
  });

  test("does NOT publish when threat_level is None", async () => {
    const canned: AgenticBridgeResponse = {
      compression: sig({ threat_level: "None" }),
      prompt_injection: null,
      self_propagation: null,
      ai_sink_write: null,
    };
    const daemon = new FakeDaemon(canned);
    const store = new CompressionSignalStore();
    daemon.setCompressionStore(store);
    await daemon.start(cfg);
    expect(store.size()).toBe(0);
  });
});
