/**
 * FallbackClassifier Tests
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { describe, it, expect } from "bun:test";
import { classifyFallback, strategyForReason } from "../src/agents/fallback-classifier";
import type { FallbackReason } from "../src/agents/fallback-classifier";

describe("classifyFallback", () => {
  describe("empty / null inputs", () => {
    it("returns empty_response when both error and response are absent", () => {
      expect(classifyFallback(null, null)).toBe("empty_response");
      expect(classifyFallback(undefined, undefined)).toBe("empty_response");
      expect(classifyFallback(null)).toBe("empty_response");
    });
  });

  describe("HTTP status codes", () => {
    it("returns provider_overload for 429", () => {
      expect(classifyFallback(null, { status: 429 })).toBe("provider_overload");
    });

    it("returns provider_overload for 503", () => {
      expect(classifyFallback(null, { status: 503 })).toBe("provider_overload");
    });

    it("returns provider_overload for 529", () => {
      expect(classifyFallback(null, { status: 529 })).toBe("provider_overload");
    });

    it("returns context_too_large for 413", () => {
      expect(classifyFallback(null, { status: 413 })).toBe("context_too_large");
    });

    it("returns model_not_available for 404", () => {
      expect(classifyFallback(null, { status: 404 })).toBe("model_not_available");
    });

    it("returns live_session_conflict for 409", () => {
      expect(classifyFallback(null, { status: 409 })).toBe("live_session_conflict");
    });

    it("reads status from error.status", () => {
      const err = Object.assign(new Error("err"), { status: 429 });
      expect(classifyFallback(err)).toBe("provider_overload");
    });

    it("reads statusCode from error.statusCode", () => {
      const err = Object.assign(new Error("err"), { statusCode: 503 });
      expect(classifyFallback(err)).toBe("provider_overload");
    });
  });

  describe("error message patterns", () => {
    it("detects rate limit", () => {
      expect(classifyFallback(new Error("Rate limit exceeded"))).toBe("provider_overload");
    });

    it("detects overloaded", () => {
      expect(classifyFallback(new Error("Provider is overloaded"))).toBe("provider_overload");
    });

    it("detects too many requests", () => {
      expect(classifyFallback(new Error("Too Many Requests"))).toBe("provider_overload");
    });

    it("detects context length exceeded", () => {
      expect(classifyFallback(new Error("context length exceeded"))).toBe("context_too_large");
    });

    it("detects token limit", () => {
      expect(classifyFallback(new Error("token limit reached"))).toBe("context_too_large");
    });

    it("detects model not found", () => {
      expect(classifyFallback(new Error("model not found: xyz"))).toBe("model_not_available");
    });

    it("detects model deprecated", () => {
      expect(classifyFallback(new Error("model deprecated"))).toBe("model_not_available");
    });

    it("detects session conflict", () => {
      expect(classifyFallback(new Error("live session conflict detected"))).toBe("live_session_conflict");
    });

    it("detects empty response", () => {
      expect(classifyFallback(new Error("empty response from provider"))).toBe("empty_response");
    });

    it("returns no_error_details for very short messages", () => {
      expect(classifyFallback(new Error("??"))).toBe("no_error_details");
    });

    it("returns unclassified for unknown errors", () => {
      expect(classifyFallback(new Error("something completely unexpected happened at layer 7"))).toBe("unclassified");
    });

    it("handles string errors", () => {
      expect(classifyFallback("rate limit hit")).toBe("provider_overload");
    });
  });

  describe("error objects without message", () => {
    it("returns no_error_details for non-Error objects", () => {
      expect(classifyFallback({ code: 42 })).toBe("no_error_details");
    });
  });
});

describe("strategyForReason", () => {
  const cases: Array<[FallbackReason, { retry: boolean; switchProvider: boolean; reduceContext: boolean }]> = [
    ["provider_overload",     { retry: true,  switchProvider: true,  reduceContext: false }],
    ["context_too_large",     { retry: true,  switchProvider: false, reduceContext: true  }],
    ["model_not_available",   { retry: false, switchProvider: true,  reduceContext: false }],
    ["live_session_conflict", { retry: true,  switchProvider: false, reduceContext: false }],
    ["empty_response",        { retry: true,  switchProvider: true,  reduceContext: false }],
    ["no_error_details",      { retry: true,  switchProvider: true,  reduceContext: false }],
    ["unclassified",          { retry: false, switchProvider: true,  reduceContext: false }],
  ];

  for (const [reason, expected] of cases) {
    it(`returns correct strategy for ${reason}`, () => {
      const strategy = strategyForReason(reason);
      expect(strategy.retry).toBe(expected.retry);
      expect(strategy.switchProvider).toBe(expected.switchProvider);
      expect(strategy.reduceContext).toBe(expected.reduceContext);
    });
  }

  it("provider_overload has non-zero retry delay", () => {
    expect(strategyForReason("provider_overload").retryDelayMs).toBeGreaterThan(0);
  });

  it("model_not_available has zero retry delay", () => {
    expect(strategyForReason("model_not_available").retryDelayMs).toBe(0);
  });
});
