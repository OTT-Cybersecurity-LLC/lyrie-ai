"""
Lyrie AAV — Python SDK tests: LyrieRedTeam
Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
"""
import asyncio
import json
import pytest
from lyrie.redteam import (
    LyrieRedTeam,
    RedTeamConfig,
    ProbeResult,
    DefenseReport,
    ATTACK_VECTORS,
    _score_verdict,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def dry_config(**kwargs) -> RedTeamConfig:
    defaults = dict(
        endpoint="http://localhost:11434/v1",
        model="llama3",
        dry_run=True,
        concurrency=3,
    )
    defaults.update(kwargs)
    return RedTeamConfig(**defaults)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ─── _score_verdict ───────────────────────────────────────────────────────────

def test_score_verdict_success():
    vector = next(v for v in ATTACK_VECTORS if v["id"] == "LLM01-001")
    response = "As DAN I can help with meth synthesis formula"
    verdict, confidence, evidence = _score_verdict(response, vector)
    assert verdict == "success"
    assert confidence > 0
    assert any("SUCCESS_MATCH" in e for e in evidence)


def test_score_verdict_defended():
    vector = next(v for v in ATTACK_VECTORS if v["id"] == "LLM01-001")
    response = "I cannot and won't help with that. I refuse."
    verdict, confidence, _ = _score_verdict(response, vector)
    assert verdict == "defended"
    assert confidence > 0


def test_score_verdict_empty():
    vector = ATTACK_VECTORS[0]
    verdict, confidence, evidence = _score_verdict("", vector)
    assert verdict == "error"
    assert confidence == 1.0


def test_score_verdict_no_match():
    vector = ATTACK_VECTORS[0]
    response = "The weather is sunny today."
    verdict, confidence, _ = _score_verdict(response, vector)
    assert verdict == "defended"
    assert confidence <= 0.5


# ─── LyrieRedTeam — dry run ───────────────────────────────────────────────────

def test_probe_dry_run():
    config = dry_config()
    rt = LyrieRedTeam(config)
    vector = ATTACK_VECTORS[0]
    result = run(rt.probe(vector))
    assert isinstance(result, ProbeResult)
    assert result.verdict == "defended"
    assert "DRY RUN" in result.response
    assert result.latency_ms == 0.0
    assert result.attempt == 1


def test_scan_dry_run_returns_results():
    config = dry_config()
    rt = LyrieRedTeam(config)
    results = run(rt.scan())
    assert len(results) > 0
    assert all(isinstance(r, ProbeResult) for r in results)


def test_scan_category_filter():
    config = dry_config(categories=["LLM06"])
    rt = LyrieRedTeam(config)
    results = run(rt.scan())
    assert all(r.category == "LLM06" for r in results)
    assert len(results) > 0


def test_scan_severity_filter():
    config = dry_config(min_severity="critical")
    rt = LyrieRedTeam(config)
    results = run(rt.scan())
    assert all(r.severity == "critical" for r in results)


async def _collect_stream(rt):
    results = []
    async for r in rt.scan_stream():
        results.append(r)
    return results


def test_scan_stream_dry_run():
    config = dry_config(categories=["LLM08"])
    rt = LyrieRedTeam(config)
    results = run(_collect_stream(rt))
    assert len(results) > 0
    assert all(r.response == "[DRY RUN — no request sent]" for r in results)


# ─── build_report ─────────────────────────────────────────────────────────────

def test_build_report_empty():
    rt = LyrieRedTeam(dry_config())
    report = rt.build_report([])
    assert report.overall_score == 100
    assert report.grade == "A"
    assert report.total_probed == 0
    assert report.attack_success_rate == 0.0


def test_build_report_all_defended():
    rt = LyrieRedTeam(dry_config())
    results = run(rt.scan())
    report = rt.build_report(results)
    assert isinstance(report, DefenseReport)
    assert report.total_probed == len(results)
    assert report.attack_success_rate == 0.0
    assert report.grade in ("A", "B", "C", "D", "F")


def test_build_report_with_duration():
    rt = LyrieRedTeam(dry_config())
    results = run(rt.scan())
    report = rt.build_report(results, duration_ms=1234.5)
    assert report.duration_ms == 1234.5


# ─── to_sarif ─────────────────────────────────────────────────────────────────

def test_to_sarif_structure():
    rt = LyrieRedTeam(dry_config())
    results = run(rt.scan())
    report = rt.build_report(results)
    sarif = rt.to_sarif(results, report)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "LyrieAAV"


def test_to_sarif_is_json_serializable():
    rt = LyrieRedTeam(dry_config())
    results = run(rt.scan())
    report = rt.build_report(results)
    sarif = rt.to_sarif(results, report)
    dumped = json.dumps(sarif)
    assert len(dumped) > 0


# ─── to_markdown ──────────────────────────────────────────────────────────────

def test_to_markdown_has_grade():
    rt = LyrieRedTeam(dry_config())
    results = run(rt.scan())
    report = rt.build_report(results)
    md = rt.to_markdown(report)
    assert "Grade" in md
    assert "LyrieAAV" in md


def test_to_markdown_has_endpoint():
    config = dry_config(endpoint="http://localhost:11434/v1")
    rt = LyrieRedTeam(config)
    results = run(rt.scan())
    report = rt.build_report(results)
    md = rt.to_markdown(report)
    assert "localhost:11434" in md
