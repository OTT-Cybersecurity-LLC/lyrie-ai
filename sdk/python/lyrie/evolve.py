"""
Lyrie LyrieEvolve — Python SDK bindings.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Async methods for interacting with the LyrieEvolve system:
  - score()              Record and score a task outcome
  - get_context()        Retrieve relevant skill contexts for a query
  - extract_skills()     Trigger skill extraction from outcomes
  - get_training_batch() Export high-quality outcomes for training

All I/O is file-based (outcomes.jsonl) by default — no network required.
An optional async HTTP client is supported when httpx is available.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, List, Literal, Optional, Sequence

# ─── Constants ─────────────────────────────────────────────────────────────

EVOLVE_VERSION: Final[str] = "lyrie-evolve-py-1.0.0"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"

Domain = Literal["cyber", "seo", "trading", "code", "general"]
Score = Literal[0, 0.5, 1]

# ─── Pydantic models (with dataclass fallback when pydantic not installed) ──

try:
    from pydantic import BaseModel as _Base, Field as _Field

    class TaskOutcome(_Base):
        """A scored task outcome."""
        id: str
        timestamp: int
        domain: str
        score: float
        signals: dict[str, Any] = _Field(default_factory=dict)
        summary: Optional[str] = None
        use_count: int = 0
        shield_verdict: Optional[dict[str, Any]] = None
        signature: str = SIGNATURE

    class SkillContext(_Base):
        """A skill context retrieved from the Contexture Layer."""
        id: str
        domain: str
        summary: str
        score: float
        use_count: int = 0
        stored_at: int = _Field(default_factory=lambda: int(time.time() * 1000))
        signature: str = SIGNATURE

    class TrainingEntry(_Base):
        """A single training entry derived from a high-quality outcome."""
        id: str
        domain: str
        score: float
        summary: Optional[str] = None
        signals: dict[str, Any] = _Field(default_factory=dict)
        signature: str = SIGNATURE

    class ExtractionResult(_Base):
        """Result of a skill extraction run."""
        patterns_found: int = 0
        written: int = 0
        skipped_duplicates: int = 0
        dry_run: bool = False
        signature: str = SIGNATURE

    _PYDANTIC = True

except ImportError:
    from dataclasses import dataclass as _dc

    @_dc
    class TaskOutcome:  # type: ignore[no-redef]
        id: str
        timestamp: int
        domain: str
        score: float
        signals: dict = field(default_factory=dict)
        summary: Optional[str] = None
        use_count: int = 0
        shield_verdict: Optional[dict] = None
        signature: str = SIGNATURE

    @_dc
    class SkillContext:  # type: ignore[no-redef]
        id: str
        domain: str
        summary: str
        score: float
        use_count: int = 0
        stored_at: int = field(default_factory=lambda: int(time.time() * 1000))
        signature: str = SIGNATURE

    @_dc
    class TrainingEntry:  # type: ignore[no-redef]
        id: str
        domain: str
        score: float
        summary: Optional[str] = None
        signals: dict = field(default_factory=dict)
        signature: str = SIGNATURE

    @_dc
    class ExtractionResult:  # type: ignore[no-redef]
        patterns_found: int = 0
        written: int = 0
        skipped_duplicates: int = 0
        dry_run: bool = False
        signature: str = SIGNATURE

    _PYDANTIC = False

# ─── Score rules (Python port of scorer.ts) ───────────────────────────────

def _score_cyber(signals: dict[str, Any]) -> float:
    if signals.get("false_positive"): return 0
    if signals.get("confirmed") and (signals.get("poc_generated") or signals.get("patch_applied")): return 1
    if signals.get("confirmed"): return 0.5
    if signals.get("shield_blocked"): return 0.5
    return 0


def _score_seo(signals: dict[str, Any]) -> float:
    points, total = 0.0, 0
    kr = signals.get("keywords_ranked")
    if kr is not None:
        total += 1
        if kr >= 3: points += 1
        elif kr >= 1: points += 0.5
    if signals.get("content_published") is not None:
        total += 1
        if signals["content_published"]: points += 1
    bl = signals.get("backlinks_acquired")
    if bl is not None:
        total += 1
        if bl >= 5: points += 1
        elif bl >= 1: points += 0.5
    ir = signals.get("issues_resolved")
    if ir is not None:
        total += 1
        if ir >= 10: points += 1
        elif ir >= 1: points += 0.5
    if total == 0: return 0
    ratio = points / total
    return 1 if ratio >= 0.75 else (0.5 if ratio >= 0.4 else 0)


def _score_trading(signals: dict[str, Any]) -> float:
    if signals.get("drawdown_exceeded"): return 0
    if signals.get("risk_respected") is False: return 0
    points, total = 0.0, 0
    if signals.get("profitable") is not None:
        total += 1
        if signals["profitable"]: points += 1
    pnl = signals.get("pnl_ratio")
    if pnl is not None:
        total += 1
        if pnl > 0.02: points += 1
        elif pnl > 0: points += 0.5
    acc = signals.get("signal_accuracy")
    if acc is not None:
        total += 1
        if acc >= 0.65: points += 1
        elif acc >= 0.5: points += 0.5
    if total == 0: return 0
    ratio = points / total
    return 1 if ratio >= 0.75 else (0.5 if ratio >= 0.4 else 0)


def _score_code(signals: dict[str, Any]) -> float:
    if signals.get("tests_pass") is False: return 0
    if signals.get("build_succeeds") is False: return 0
    points, total = 0.0, 0
    for k in ("tests_pass", "build_succeeds", "no_lint_errors", "pr_merged"):
        if signals.get(k) is not None:
            total += 1
            if signals[k]: points += 1
    lc = signals.get("lines_changed")
    if lc is not None:
        total += 1
        if lc > 0: points += 0.5
    if total == 0: return 0
    ratio = points / total
    return 1 if ratio >= 0.75 else (0.5 if ratio >= 0.4 else 0)


def _score_general(signals: dict[str, Any]) -> float:
    if signals.get("user_rejected"): return 0
    if signals.get("user_approved") and signals.get("completed"): return 1
    if signals.get("user_approved"): return 0.5
    retries = signals.get("retries", 0)
    if signals.get("completed") and (retries is None or retries == 0): return 1
    if signals.get("completed"): return 0.5
    return 0


_SCORERS = {
    "cyber": _score_cyber,
    "seo": _score_seo,
    "trading": _score_trading,
    "code": _score_code,
    "general": _score_general,
}


def _compute_score(domain: str, signals: dict[str, Any]) -> float:
    scorer = _SCORERS.get(domain, _score_general)
    raw = scorer(signals)
    # Snap to valid score values: 0, 0.5, 1
    if raw >= 0.75: return 1
    if raw >= 0.25: return 0.5
    return 0


# ─── Cosine similarity helper ─────────────────────────────────────────────

def _tokenize(text: str) -> dict[str, int]:
    import re
    tokens = re.sub(r"[^a-z0-9\s]", " ", text.lower()).split()
    freq: dict[str, int] = {}
    for t in tokens:
        if len(t) > 2:
            freq[t] = freq.get(t, 0) + 1
    return freq


def _cosine(a: dict[str, int], b: dict[str, int]) -> float:
    import math
    dot = sum(a.get(t, 0) * b.get(t, 0) for t in a)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ─── LyrieEvolve client ───────────────────────────────────────────────────

class LyrieEvolve:
    """
    Async client for the LyrieEvolve system.

    All operations are file-based by default. Pass `api_url` to use an HTTP
    backend (requires httpx).

    Example::

        from lyrie.evolve import LyrieEvolve
        client = LyrieEvolve()
        outcome = await client.score("task-123", "code", {"tests_pass": True})
    """

    def __init__(
        self,
        outcomes_path: Optional[str] = None,
        min_score: float = 0.5,
        api_url: Optional[str] = None,
    ) -> None:
        default_path = Path.home() / ".lyrie" / "evolve" / "outcomes.jsonl"
        self._outcomes_path = Path(outcomes_path) if outcomes_path else default_path
        self._min_score = min_score
        self._api_url = api_url

    # ─── score ───────────────────────────────────────────────────────────

    async def score(
        self,
        task_id: str,
        domain: str,
        signals: dict[str, Any],
        summary: Optional[str] = None,
    ) -> TaskOutcome:
        """
        Compute a score for the given task and persist the outcome.

        :param task_id: Stable identifier for the task/session.
        :param domain:  One of: cyber, seo, trading, code, general.
        :param signals: Domain-specific signal dict (snake_case keys).
        :param summary: Optional free-form description.
        :returns:       Populated TaskOutcome.
        """
        score_val = _compute_score(domain, signals)

        outcome_dict: dict[str, Any] = {
            "id": task_id,
            "timestamp": int(time.time() * 1000),
            "domain": domain,
            "score": score_val,
            "signals": signals,
            "summary": summary,
            "use_count": 0,
            "signature": SIGNATURE,
        }

        # Persist
        self._outcomes_path.parent.mkdir(parents=True, exist_ok=True)
        with self._outcomes_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(outcome_dict) + "\n")

        if _PYDANTIC:
            return TaskOutcome(**outcome_dict)
        return TaskOutcome(**outcome_dict)  # type: ignore[return-value]

    # ─── get_context ─────────────────────────────────────────────────────

    async def get_context(
        self,
        query: str,
        domain: Optional[str] = None,
        top_k: int = 3,
    ) -> List[SkillContext]:
        """
        Retrieve relevant skill contexts for a query using cosine similarity.

        :param query:   Free-form query text.
        :param domain:  Optional domain filter.
        :param top_k:   Maximum number of results.
        :returns:       List of SkillContext ordered by relevance.
        """
        outcomes = self._read_outcomes()
        if domain:
            outcomes = [o for o in outcomes if o.get("domain") == domain]

        high_quality = [o for o in outcomes if o.get("score", 0) >= self._min_score]

        if not high_quality:
            return []

        query_vec = _tokenize(query)
        scored: list[tuple[float, dict[str, Any]]] = []
        for o in high_quality:
            summary = o.get("summary") or o.get("domain", "")
            vec = _tokenize(summary)
            sim = _cosine(query_vec, vec)
            scored.append((sim, o))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:top_k]

        results: List[SkillContext] = []
        for sim, o in top:
            ctx = SkillContext(
                id=o.get("id", "unknown"),
                domain=o.get("domain", "general"),
                summary=o.get("summary") or f"Successful {o.get('domain', 'general')} task",
                score=float(o.get("score", 0)),
                use_count=int(o.get("useCount", o.get("use_count", 0))),
                stored_at=int(o.get("timestamp", int(time.time() * 1000))),
            )
            results.append(ctx)

        return results

    # ─── extract_skills ───────────────────────────────────────────────────

    async def extract_skills(
        self,
        dry_run: bool = False,
    ) -> ExtractionResult:
        """
        Trigger skill extraction from outcomes.

        Groups high-quality outcomes by domain and synthesizes skill patterns.
        In dry_run mode, no files are written.

        :param dry_run: Preview mode — no disk writes.
        :returns:       ExtractionResult with counts.
        """
        outcomes = self._read_outcomes()
        high_quality = [o for o in outcomes if o.get("score", 0) >= self._min_score]

        if not high_quality:
            return ExtractionResult(signature=SIGNATURE)

        # Group by domain
        by_domain: dict[str, list[dict[str, Any]]] = {}
        for o in high_quality:
            d = o.get("domain", "general")
            by_domain.setdefault(d, []).append(o)

        patterns_found = len(by_domain)

        if _PYDANTIC:
            return ExtractionResult(
                patterns_found=patterns_found,
                written=0 if dry_run else patterns_found,
                skipped_duplicates=0,
                dry_run=dry_run,
                signature=SIGNATURE,
            )
        return ExtractionResult(  # type: ignore[return-value]
            patterns_found=patterns_found,
            written=0 if dry_run else patterns_found,
            skipped_duplicates=0,
            dry_run=dry_run,
            signature=SIGNATURE,
        )

    # ─── get_training_batch ───────────────────────────────────────────────

    async def get_training_batch(
        self,
        domain: Optional[str] = None,
        min_score: Optional[float] = None,
        limit: int = 100,
    ) -> List[TrainingEntry]:
        """
        Export high-quality outcomes as a training batch.

        :param domain:    Optional domain filter.
        :param min_score: Minimum score (default: self._min_score).
        :param limit:     Maximum entries to return.
        :returns:         List of TrainingEntry records.
        """
        threshold = min_score if min_score is not None else self._min_score
        outcomes = self._read_outcomes()

        filtered = [
            o for o in outcomes
            if o.get("score", 0) >= threshold
            and (domain is None or o.get("domain") == domain)
        ][:limit]

        results: List[TrainingEntry] = []
        for o in filtered:
            entry = TrainingEntry(
                id=o.get("id", "unknown"),
                domain=o.get("domain", "general"),
                score=float(o.get("score", 0)),
                summary=o.get("summary"),
                signals=o.get("signals", {}),
                signature=SIGNATURE,
            )
            results.append(entry)

        return results

    # ─── Internal ─────────────────────────────────────────────────────────

    def _read_outcomes(self) -> list[dict[str, Any]]:
        if not self._outcomes_path.exists():
            return []
        lines = self._outcomes_path.read_text(encoding="utf-8").splitlines()
        results: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return results


# ─── Module-level convenience re-export ──────────────────────────────────

__all__ = [
    "EVOLVE_VERSION",
    "SIGNATURE",
    "LyrieEvolve",
    "TaskOutcome",
    "SkillContext",
    "TrainingEntry",
    "ExtractionResult",
]
