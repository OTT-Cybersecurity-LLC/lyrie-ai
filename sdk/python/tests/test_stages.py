"""
Lyrie SDK — Stages A–F tests.

Lyrie.ai by OTT Cybersecurity LLC.
"""

from __future__ import annotations

from lyrie import Finding, StagesValidator


def _f(**over: object) -> Finding:
    base = dict(
        id="f-1",
        title="Test finding",
        severity="high",
        description="test",
        file="src/handler.ts",
        line=10,
        category="shell-injection",
        evidence="execSync(req.body.command)",
    )
    base.update(over)
    return Finding(**base)  # type: ignore[arg-type]


def test_stage_a_filters_comments() -> None:
    v = StagesValidator().validate(_f(evidence="// execSync(req.body.command)"))
    a = next(s for s in v.stages if s.stage == "A")
    assert a.passed is False
    assert v.confirmed is False


def test_stage_a_filters_js_method_exec() -> None:
    v = StagesValidator().validate(_f(evidence="regex.exec(body); scanner.exec(buf)"))
    a = next(s for s in v.stages if s.stage == "A")
    assert a.passed is False


def test_stage_a_filters_parameterized_sql() -> None:
    v = StagesValidator().validate(_f(
        category="sql-injection",
        evidence="db.query('SELECT * FROM u WHERE id = ?', [id])",
    ))
    a = next(s for s in v.stages if s.stage == "A")
    assert a.passed is False


def test_stage_b_filters_test_files() -> None:
    v = StagesValidator().validate(_f(file="src/handler.test.ts"))
    b = next(s for s in v.stages if s.stage == "B")
    assert b.passed is False


def test_stage_c_filters_build_artifacts() -> None:
    v = StagesValidator().validate(_f(file="packages/ui/.next/server/app/page.js"))
    c = next(s for s in v.stages if s.stage == "C")
    assert c.passed is False
    assert v.confirmed is False


def test_stage_e_auto_pocs_for_shell_injection() -> None:
    v = StagesValidator().validate(_f())
    assert v.poc is not None
    assert v.poc.kind == "automatic"
    assert "curl" in v.poc.payload
    assert "Lyrie PoC" in v.poc.payload


def test_stage_e_auto_pocs_for_sql_injection() -> None:
    v = StagesValidator().validate(_f(
        category="sql-injection",
        evidence="db.query(`SELECT * FROM u WHERE id = ${req.body.id}`)",
    ))
    assert v.poc is not None
    assert v.poc.kind == "automatic"
    assert "UNION" in v.poc.payload.upper()


def test_stage_e_falls_back_for_unsupported_category() -> None:
    v = StagesValidator().validate(_f(category="race-condition"))
    assert v.poc is not None
    assert v.poc.kind == "needs-human-poc"


def test_stage_e_skipped_in_fast_mode() -> None:
    v = StagesValidator(fast_mode=True).validate(_f())
    assert v.poc is None


def test_stage_f_provides_remediation() -> None:
    v = StagesValidator().validate(_f(category="ssrf", evidence="fetch(req.body.url)"))
    assert v.remediation is not None
    assert "allowlist" in v.remediation.summary.lower()


def test_validate_batch_drops_unconfirmed_by_default() -> None:
    findings = [
        _f(id="real"),
        _f(id="in-test", file="src/handler.test.ts"),
        _f(id="in-comment", evidence="// execSync(...)"),
    ]
    out = StagesValidator().validate_batch(findings)
    assert len(out) == 1
    assert out[0].finding.id == "real"


def test_validate_batch_keeps_observations_when_requested() -> None:
    findings = [
        _f(id="real"),
        _f(id="in-test", file="src/handler.test.ts"),
    ]
    out = StagesValidator().validate_batch(findings, keep_observations=True)
    assert len(out) == 2
    in_test = next(v for v in out if v.finding.id == "in-test")
    assert in_test.confirmed is False


def test_validated_finding_signature() -> None:
    v = StagesValidator().validate(_f())
    assert v.signature == "Lyrie.ai by OTT Cybersecurity LLC"


def test_confidence_high_on_clean() -> None:
    v = StagesValidator().validate(_f())
    assert v.confidence >= 0.8


def test_confidence_low_on_unconfirmed() -> None:
    v = StagesValidator().validate(_f(file="src/handler.test.ts"))
    assert v.confidence <= 0.2
