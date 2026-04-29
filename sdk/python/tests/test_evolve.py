"""
Lyrie SDK — LyrieEvolve Python bindings tests.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from lyrie.evolve import (
    EVOLVE_VERSION,
    SIGNATURE,
    LyrieEvolve,
    TaskOutcome,
    SkillContext,
    TrainingEntry,
    ExtractionResult,
    _compute_score,
    _score_cyber,
    _score_seo,
    _score_trading,
    _score_code,
    _score_general,
)


# ─── Helpers ──────────────────────────────────────────────────────────────


def run(coro: Any) -> Any:
    return asyncio.get_event_loop().run_until_complete(coro)


def make_client(tmp_path: Path) -> LyrieEvolve:
    return LyrieEvolve(outcomes_path=str(tmp_path / "outcomes.jsonl"))


def write_outcome(path: Path, **overrides: Any) -> None:
    defaults = {
        "id": "o1",
        "timestamp": 1000,
        "domain": "general",
        "score": 1,
        "signals": {},
        "summary": "Task done",
        "use_count": 0,
        "signature": SIGNATURE,
    }
    defaults.update(overrides)
    with path.open("a") as fh:
        fh.write(json.dumps(defaults) + "\n")


# ─── Scoring rules ────────────────────────────────────────────────────────


def test_score_cyber_false_positive_is_zero() -> None:
    assert _score_cyber({"false_positive": True, "confirmed": True}) == 0


def test_score_cyber_confirmed_poc_is_one() -> None:
    assert _score_cyber({"confirmed": True, "poc_generated": True}) == 1


def test_score_cyber_confirmed_alone_is_half() -> None:
    assert _score_cyber({"confirmed": True}) == 0.5


def test_score_seo_no_signals_is_zero() -> None:
    assert _score_seo({}) == 0


def test_score_seo_keywords_ranked_high() -> None:
    assert _score_seo({"keywords_ranked": 5}) == 1


def test_score_trading_drawdown_exceeded() -> None:
    assert _score_trading({"drawdown_exceeded": True, "profitable": True}) == 0


def test_score_trading_risk_not_respected() -> None:
    assert _score_trading({"risk_respected": False}) == 0


def test_score_code_tests_fail_is_zero() -> None:
    assert _score_code({"tests_pass": False}) == 0


def test_score_code_all_pass_is_one() -> None:
    assert _score_code({"tests_pass": True, "build_succeeds": True}) == 1


def test_score_general_rejected_is_zero() -> None:
    assert _score_general({"user_rejected": True, "completed": True}) == 0


def test_score_general_approved_completed() -> None:
    assert _score_general({"user_approved": True, "completed": True}) == 1


def test_compute_score_snaps_to_valid_values() -> None:
    # Valid scores are 0, 0.5, 1
    s = _compute_score("general", {"completed": True})
    assert s in (0, 0.5, 1)


# ─── LyrieEvolve client ───────────────────────────────────────────────────


def test_evolve_version_defined() -> None:
    assert EVOLVE_VERSION.startswith("lyrie-evolve-py")


def test_score_persists_outcome(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    outcome = run(client.score("t1", "code", {"tests_pass": True}))
    assert outcome.id == "t1"
    assert outcome.score in (0, 0.5, 1)
    assert outcome.signature == SIGNATURE

    lines = (tmp_path / "outcomes.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["id"] == "t1"


def test_score_domain_cyber(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    outcome = run(client.score("c1", "cyber", {"confirmed": True, "poc_generated": True}))
    assert outcome.score == 1


def test_get_context_returns_relevant(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    write_outcome(p, id="x1", domain="cyber", summary="XSS vulnerability confirmed with payload", score=1)
    write_outcome(p, id="x2", domain="seo", summary="keywords ranked page one", score=1)

    client = LyrieEvolve(outcomes_path=str(p))
    contexts = run(client.get_context("XSS vulnerability injection", top_k=1))
    assert len(contexts) <= 1
    if contexts:
        assert contexts[0].domain == "cyber"


def test_get_context_domain_filter(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    write_outcome(p, id="a1", domain="cyber", summary="pentest success", score=1)
    write_outcome(p, id="a2", domain="trading", summary="profitable trade", score=1)

    client = LyrieEvolve(outcomes_path=str(p))
    results = run(client.get_context("pentest", domain="cyber", top_k=5))
    assert all(c.domain == "cyber" for c in results)


def test_get_context_empty_when_no_outcomes(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    results = run(client.get_context("anything"))
    assert results == []


def test_extract_skills_dry_run(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    write_outcome(p, domain="code", summary="build passed all tests", score=1)

    client = LyrieEvolve(outcomes_path=str(p))
    result = run(client.extract_skills(dry_run=True))
    assert result.dry_run is True
    assert result.written == 0
    assert result.signature == SIGNATURE


def test_extract_skills_with_outcomes(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    write_outcome(p, domain="seo", summary="keywords ranked successfully", score=1)
    write_outcome(p, domain="cyber", summary="vulnerability confirmed", score=1)

    client = LyrieEvolve(outcomes_path=str(p))
    result = run(client.extract_skills())
    assert result.patterns_found >= 1


def test_get_training_batch_filters_by_score(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    write_outcome(p, id="b1", domain="code", score=1, summary="good")
    write_outcome(p, id="b2", domain="code", score=0, summary="bad")
    write_outcome(p, id="b3", domain="code", score=0.5, summary="partial")

    client = LyrieEvolve(outcomes_path=str(p), min_score=0.5)
    batch = run(client.get_training_batch())
    scores = [e.score for e in batch]
    assert all(s >= 0.5 for s in scores)
    assert len(batch) == 2


def test_get_training_batch_domain_filter(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    write_outcome(p, id="d1", domain="seo", score=1)
    write_outcome(p, id="d2", domain="trading", score=1)

    client = LyrieEvolve(outcomes_path=str(p))
    batch = run(client.get_training_batch(domain="seo"))
    assert all(e.domain == "seo" for e in batch)


def test_get_training_batch_limit(tmp_path: Path) -> None:
    p = tmp_path / "outcomes.jsonl"
    for i in range(10):
        write_outcome(p, id=f"lim{i}", score=1)

    client = LyrieEvolve(outcomes_path=str(p))
    batch = run(client.get_training_batch(limit=3))
    assert len(batch) <= 3
