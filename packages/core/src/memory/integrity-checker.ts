/**
 * MemoryIntegrityChecker — ASI06 memory-poisoning defense for Lyrie v1.0.0.
 *
 * Threat model: an adversary poisons Lyrie's memory by injecting false facts.
 * This checker catches drift by:
 *   1. Hashing every memory entry at write time (SHA-256).
 *   2. Periodically re-hashing all entries and flagging mismatches.
 *   3. Optionally running cross-model verification for high-stakes entries.
 *
 * The checker is intentionally stateless between runs so it can be called
 * from a cron job or on-demand CLI without holding open DB handles.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { createHash } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MemoryEntry {
  id: string;
  content: string;
  /** Arbitrary metadata stored alongside the entry. */
  metadata?: Record<string, unknown>;
}

export interface HashedEntry extends MemoryEntry {
  /** SHA-256 hex digest of `content` at write time. */
  contentHash: string;
  /** Unix ms timestamp when the entry was hashed and stored. */
  hashedAt: number;
}

export interface FailedEntry {
  id: string;
  storedHash: string;
  computedHash: string;
  /** Current content (possibly tampered). */
  content: string;
  /** Unix ms timestamp when the entry was originally hashed. */
  createdAt: number;
}

export interface IntegrityReport {
  totalEntries: number;
  passedEntries: number;
  failedEntries: FailedEntry[];
  checkDurationMs: number;
}

export interface VerificationResult {
  /** True if ≥ 2 out of 3 (majority) models agreed on the answer. */
  agreement: boolean;
  /** Number of models that agreed with the majority answer. */
  agreementCount: number;
  /** Total models consulted. */
  totalModels: number;
  /** The majority answer (or null if no majority). */
  majorityAnswer: string | null;
  /** Per-model answers keyed by model id. */
  answers: Record<string, string>;
  /** Disagreeing model ids (those that returned a different answer). */
  disagreements: string[];
}

// ─── Storage interface ────────────────────────────────────────────────────────

/**
 * Minimal storage interface so the checker isn't coupled to a specific DB.
 * In production: backed by MemoryCore's SQLite.
 * In tests: backed by an in-memory Map.
 */
export interface IntegrityStore {
  /** Persist a hashed entry. Overwrites if id already exists. */
  put(entry: HashedEntry): Promise<void>;
  /** Retrieve a single entry by id. */
  get(id: string): Promise<HashedEntry | null>;
  /** Retrieve all entries. */
  getAll(): Promise<HashedEntry[]>;
}

// ─── LLM provider interface ───────────────────────────────────────────────────

/**
 * Minimal interface for an LLM that can answer a question about content.
 * In tests: provide a mock that returns deterministic answers.
 */
export interface LlmProvider {
  id: string;
  ask(question: string): Promise<string>;
}

// ─── MemoryIntegrityChecker ───────────────────────────────────────────────────

export class MemoryIntegrityChecker {
  private store: IntegrityStore;

  constructor(store: IntegrityStore) {
    this.store = store;
  }

  // ─── Hashing ───────────────────────────────────────────────────────────────

  /**
   * Compute the SHA-256 hex digest of a string.
   * Deterministic: same content always produces the same hash.
   */
  static sha256(content: string): string {
    return createHash("sha256").update(content, "utf8").digest("hex");
  }

  /**
   * Hash an entry's content and store it alongside the entry.
   * Call this at write time for every memory entry that needs integrity protection.
   */
  async hashAndStore(entry: MemoryEntry): Promise<HashedEntry> {
    if (!entry.id) throw new Error("MemoryEntry.id is required");
    if (typeof entry.content !== "string") throw new Error("MemoryEntry.content must be a string");

    const hashed: HashedEntry = {
      ...entry,
      contentHash: MemoryIntegrityChecker.sha256(entry.content),
      hashedAt: Date.now(),
    };
    await this.store.put(hashed);
    return hashed;
  }

  // ─── Integrity check ───────────────────────────────────────────────────────

  /**
   * Re-hash all stored entries and report any that have drifted from their
   * stored hash. Drift = content was modified after the hash was captured.
   *
   * Safe to run at any time (read-only — never modifies stored entries).
   */
  async runIntegrityCheck(): Promise<IntegrityReport> {
    const startMs = Date.now();
    const all = await this.store.getAll();
    const failed: FailedEntry[] = [];

    for (const entry of all) {
      const computedHash = MemoryIntegrityChecker.sha256(entry.content);
      if (computedHash !== entry.contentHash) {
        failed.push({
          id: entry.id,
          storedHash: entry.contentHash,
          computedHash,
          content: entry.content,
          createdAt: entry.hashedAt,
        });
      }
    }

    return {
      totalEntries: all.length,
      passedEntries: all.length - failed.length,
      failedEntries: failed,
      checkDurationMs: Date.now() - startMs,
    };
  }

  /**
   * Re-hash all entries and update their stored hashes to the current content.
   * Use with caution: this trusts that current content is correct.
   * Equivalent to `lyrie memory integrity-check --fix`.
   */
  async fixHashes(): Promise<{ fixed: number }> {
    const all = await this.store.getAll();
    let fixed = 0;

    for (const entry of all) {
      const freshHash = MemoryIntegrityChecker.sha256(entry.content);
      if (freshHash !== entry.contentHash) {
        await this.store.put({ ...entry, contentHash: freshHash, hashedAt: Date.now() });
        fixed++;
      }
    }

    return { fixed };
  }

  // ─── Cross-model verification ──────────────────────────────────────────────

  /**
   * Ask multiple LLM models the same question about the given content.
   * Returns a VerificationResult indicating whether a majority agreed.
   *
   * Designed for high-stakes memory (rules, projects) that should be
   * verified by more than one model before being trusted.
   *
   * Example:
   * ```ts
   * const result = await checker.crossModelVerify(
   *   ruleContent,
   *   [hermesProvider, anthropicProvider, openaiProvider],
   *   "Is this rule consistent with a defensive security policy? Answer YES or NO."
   * );
   * if (!result.agreement) alert("Rule disagreement detected — possible tampering");
   * ```
   */
  async crossModelVerify(
    content: string,
    models: LlmProvider[],
    question: string
  ): Promise<VerificationResult> {
    if (models.length === 0) {
      return {
        agreement: false,
        agreementCount: 0,
        totalModels: 0,
        majorityAnswer: null,
        answers: {},
        disagreements: [],
      };
    }

    const answers: Record<string, string> = {};

    // Ask all models in parallel
    const settled = await Promise.allSettled(
      models.map(async (m) => {
        const prompt = `Content:\n${content}\n\nQuestion: ${question}`;
        const answer = await m.ask(prompt);
        return { id: m.id, answer: answer.trim() };
      })
    );

    for (const result of settled) {
      if (result.status === "fulfilled") {
        answers[result.value.id] = result.value.answer;
      }
      // Rejected = model unavailable; omit from voting but don't crash
    }

    const answerValues = Object.values(answers);
    const totalModels = answerValues.length;

    if (totalModels === 0) {
      return {
        agreement: false,
        agreementCount: 0,
        totalModels: 0,
        majorityAnswer: null,
        answers,
        disagreements: [],
      };
    }

    // Find majority answer (case-insensitive comparison)
    const freq: Record<string, number> = {};
    const normalized: Record<string, string> = {}; // normalized → canonical
    for (const ans of answerValues) {
      const key = ans.toLowerCase();
      freq[key] = (freq[key] ?? 0) + 1;
      normalized[key] = ans;
    }

    const [majorityKey, majorityCount] = Object.entries(freq).reduce(
      (best, cur) => (cur[1] > best[1] ? cur : best),
      ["", 0]
    );

    const majorityAnswer = majorityCount > 0 ? normalized[majorityKey] : null;
    const agreement = majorityCount > totalModels / 2; // strict majority (> 50%)

    const disagreements = Object.entries(answers)
      .filter(([, ans]) => ans.toLowerCase() !== majorityKey)
      .map(([id]) => id);

    return {
      agreement,
      agreementCount: majorityCount,
      totalModels,
      majorityAnswer,
      answers,
      disagreements,
    };
  }
}

// ─── In-memory store (for tests + CLI) ───────────────────────────────────────

/**
 * Simple in-memory implementation of IntegrityStore.
 * Useful for unit tests and one-shot CLI runs.
 */
export class InMemoryIntegrityStore implements IntegrityStore {
  private _data = new Map<string, HashedEntry>();

  async put(entry: HashedEntry): Promise<void> {
    this._data.set(entry.id, { ...entry });
  }

  async get(id: string): Promise<HashedEntry | null> {
    return this._data.get(id) ?? null;
  }

  async getAll(): Promise<HashedEntry[]> {
    return Array.from(this._data.values());
  }

  /** Number of entries in the store. */
  size(): number { return this._data.size; }

  /** Clear all entries. */
  clear(): void { this._data.clear(); }
}
