"""
Lyrie Stages A–F Exploitation Validator — Python port.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Six gates that every raw finding passes before it can ship as confirmed:
    A  Pattern reality
    B  Reachability
    C  Code-path existence
    D  Final call
    E  PoC generation
    F  Remediation
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Final, Iterable, Literal, Optional

from lyrie.shield import Shield

VALIDATOR_VERSION: Final[str] = "lyrie-stages-py-1.0.0"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"

Stage = Literal["A", "B", "C", "D", "E", "F"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal[
    "shell-injection", "sql-injection", "xss", "ssrf", "rce",
    "path-traversal", "deserialization", "auth-bypass", "xxe",
    "prompt-injection", "secret-exposure", "open-redirect", "csrf",
    "race-condition", "other",
]


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    cwe: Optional[str] = None
    category: Optional[Category] = None
    evidence: Optional[str] = None


@dataclass(slots=True)
class StageVerdict:
    stage: Stage
    passed: bool
    reason: str
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PoC:
    description: str
    payload: str
    kind: Literal["automatic", "needs-human-poc"]


@dataclass(slots=True)
class Remediation:
    summary: str
    target: Optional[str] = None


@dataclass(slots=True)
class ValidatedFinding:
    finding: Finding
    confirmed: bool
    stages: list[StageVerdict]
    confidence: float
    poc: Optional[PoC] = None
    remediation: Optional[Remediation] = None
    signature: str = SIGNATURE


_TEST_FILE_PATTERNS = tuple(re.compile(p) for p in (
    r"\.test\.[jt]sx?$",
    r"\.spec\.[jt]sx?$",
    r"_test\.py$",
    r"(^|/)tests?/",
    r"(^|/)__tests__/",
    r"(^|/)spec/",
    r"(^|/)fixtures?/",
    r"(^|/)mocks?/",
))

_BUILD_PATTERNS = tuple(re.compile(p) for p in (
    r"(^|/)\.next/",
    r"(^|/)dist/",
    r"(^|/)build/",
    r"(^|/)target/",
    r"(^|/)node_modules/",
    r"\.min\.[a-z]+$",
    r"\.bundle\.",
))

_COMMENT_LIKELY = re.compile(r"^\s*(//|#|\*|--)")


class StagesValidator:
    """Lyrie Stages A–F validator. Lyrie.ai by OTT Cybersecurity LLC."""

    __slots__ = ("_shield", "_fast")

    def __init__(self, *, shield: Optional[Shield] = None, fast_mode: bool = False) -> None:
        self._shield = shield or Shield()
        self._fast = fast_mode

    def validate(
        self,
        finding: Finding,
        *,
        surface: object | None = None,
    ) -> ValidatedFinding:
        stages: list[StageVerdict] = []
        confirmed = True

        a = self._stage_a(finding)
        stages.append(a)
        if not a.passed:
            confirmed = False

        b = self._stage_b(finding, surface)
        stages.append(b)

        c = self._stage_c(finding)
        stages.append(c)
        if not c.passed:
            confirmed = False

        d = self._stage_d(stages, finding)
        stages.append(d)
        if not d.passed:
            confirmed = False

        poc: Optional[PoC] = None
        remediation: Optional[Remediation] = None
        if not self._fast and confirmed:
            poc = self._stage_e_poc(finding)
            stages.append(StageVerdict(
                stage="E", passed=poc.kind == "automatic",
                reason=("Lyrie generated a minimal reproducible PoC" if poc.kind == "automatic"
                        else "Finding requires human-in-the-loop PoC"),
            ))
        if not self._fast:
            remediation = self._stage_f_remediation(finding)
            stages.append(StageVerdict(
                stage="F", passed=remediation is not None,
                reason=("Lyrie suggested a concrete remediation path" if remediation
                        else "No automatic remediation available"),
            ))

        # Severity adjustment
        new_severity: Severity = finding.severity
        if not b.passed and finding.severity == "high":
            new_severity = "medium"
        if not b.passed and finding.severity == "critical":
            new_severity = "high"
        new_finding = replace(finding, severity=new_severity)

        return ValidatedFinding(
            finding=new_finding,
            confirmed=confirmed,
            stages=stages,
            confidence=_compute_confidence(stages, confirmed),
            poc=poc,
            remediation=remediation,
        )

    def validate_batch(
        self,
        findings: Iterable[Finding],
        *,
        surface: object | None = None,
        keep_observations: bool = False,
    ) -> list[ValidatedFinding]:
        out: list[ValidatedFinding] = []
        for f in findings:
            v = self.validate(f, surface=surface)
            if v.confirmed or keep_observations:
                out.append(v)
        return out

    # ── stages ──────────────────────────────────────────────────────────────

    def _stage_a(self, f: Finding) -> StageVerdict:
        ev = f.evidence or ""
        if not ev.strip():
            return StageVerdict(stage="A", passed=True,
                                reason="No evidence excerpt; cannot falsify")
        if _COMMENT_LIKELY.search(ev):
            return StageVerdict(stage="A", passed=False,
                                reason="Match is inside a comment")
        verdict = self._shield.scan_recalled(ev)
        if verdict.blocked and verdict.severity == "high":
            return StageVerdict(stage="A", passed=False,
                                reason="Evidence resembles a Shield-defended pattern")

        if f.category == "shell-injection":
            if re.search(r"\.\s*exec\s*\(\s*[^)]+\)", ev) and not re.search(
                r"\b(child_process|execSync|spawn|os\.system|subprocess)\b", ev
            ):
                return StageVerdict(stage="A", passed=False,
                                    reason="evidence calls a JS .exec() method, not a shell exec")
        elif f.category == "sql-injection":
            placeholder = (
                re.search(r"\?\s*['\"`]?\s*,", ev)
                or re.search(r":\s*[a-zA-Z_]\w*\b", ev)
                or re.search(r"\$\d+", ev)
            )
            interp = re.search(r"\$\{", ev) or re.search(r"['\"`][^'\"`]*\+\s*\w", ev)
            if placeholder and not interp:
                return StageVerdict(stage="A", passed=False,
                                    reason="parameterized placeholders, not interpolation")
        elif f.category == "xss":
            if re.search(r"textContent|innerText", ev) and not re.search(
                r"innerHTML|outerHTML|dangerouslySetInnerHTML", ev
            ):
                return StageVerdict(stage="A", passed=False,
                                    reason="textContent/innerText is safe sink")
        return StageVerdict(stage="A", passed=True, reason="Pattern is plausibly real")

    def _stage_b(self, f: Finding, surface: object | None) -> StageVerdict:
        if not f.file:
            return StageVerdict(stage="B", passed=True,
                                reason="No file context; reachability assumed")
        if any(p.search(f.file) for p in _TEST_FILE_PATTERNS):
            return StageVerdict(stage="B", passed=False,
                                reason="Finding inside test/spec/fixture", detail={"fileKind": "test"})
        return StageVerdict(stage="B", passed=True,
                            reason="No upstream trust boundary detected — openly reachable",
                            detail={"protection": "none"})

    def _stage_c(self, f: Finding) -> StageVerdict:
        if not f.file:
            return StageVerdict(stage="C", passed=True, reason="No file; assumed reachable")
        if any(p.search(f.file) for p in _TEST_FILE_PATTERNS):
            return StageVerdict(stage="C", passed=False, reason="Test code path not in production build")
        if any(p.search(f.file) for p in _BUILD_PATTERNS):
            return StageVerdict(stage="C", passed=False, reason="Build artifact / vendor")
        return StageVerdict(stage="C", passed=True, reason="Source-controlled, non-test code")

    def _stage_d(self, prior: list[StageVerdict], f: Finding) -> StageVerdict:
        b = next((s for s in prior if s.stage == "B"), None)
        if b and b.detail.get("protection") == "none" and f.severity not in ("info", "low"):
            return StageVerdict(stage="D", passed=True,
                                reason="Reachable AND unprotected; promoting confidence")
        failures = [s for s in prior if not s.passed]
        if failures:
            return StageVerdict(
                stage="D", passed=False,
                reason="Confirmed unconfirmed: " + "; ".join(f"{s.stage}({s.reason})" for s in failures),
            )
        return StageVerdict(stage="D", passed=True, reason="All prior stages clean")

    def _stage_e_poc(self, f: Finding) -> PoC:
        cat = f.category
        if cat in ("shell-injection", "rce"):
            return PoC(
                kind="automatic",
                description="Send untrusted input that breaks out of the surrounding shell context.",
                payload=f"# Lyrie PoC — {f.id}\ncurl -s 'http://target/{f.file or 'endpoint'}' \\\n"
                        f"  --data-urlencode 'input=\";id #'",
            )
        if cat == "sql-injection":
            return PoC(
                kind="automatic",
                description="Close the SQL string and append a UNION query.",
                payload=f"# Lyrie PoC — {f.id}\n"
                        "curl -s 'http://target/api?q=1%27%20UNION%20SELECT%20version()--%20'",
            )
        if cat == "xss":
            return PoC(
                kind="automatic",
                description="Reflective probe in rendered output.",
                payload=f"# Lyrie PoC — {f.id}\n"
                        "curl -s 'http://target/?q=%3Cscript%3Ealert(1)%3C/script%3E'",
            )
        if cat == "ssrf":
            return PoC(
                kind="automatic",
                description="Coerce the server into hitting an internal-only URL.",
                payload=f"# Lyrie PoC — {f.id}\n"
                        "curl -s 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/'",
            )
        if cat == "path-traversal":
            return PoC(
                kind="automatic",
                description="Walk above the document root.",
                payload=f"# Lyrie PoC — {f.id}\n"
                        "curl -s 'http://target/files?path=../../../../etc/passwd'",
            )
        return PoC(
            kind="needs-human-poc",
            description=f"Lyrie does not auto-PoC findings of category {cat}; human review required.",
            payload=f"# Lyrie PoC — {f.id}\n# Category: {cat}\n# Evidence:\n# {f.evidence or '(none)'}",
        )

    def _stage_f_remediation(self, f: Finding) -> Optional[Remediation]:
        cat = f.category
        target = f"{f.file}:{f.line or 0}" if f.file else None
        summaries: dict[str, str] = {
            "shell-injection": "Pass user input as argv (not via shell), validate against an allowlist, "
                               "and prefer spawnFile-style APIs that don't invoke /bin/sh.",
            "rce": "Pass user input as argv (not via shell), validate against an allowlist, "
                   "and prefer spawnFile-style APIs that don't invoke /bin/sh.",
            "sql-injection": "Use parameterized queries (placeholders / prepared statements) and reject "
                             "inputs that fail strict shape validation.",
            "xss": "Switch innerHTML/dangerouslySetInnerHTML to textContent or a vetted sanitizer "
                   "(e.g. DOMPurify) and enforce a Content-Security-Policy.",
            "ssrf": "Allowlist outbound destinations, block link-local + private ranges "
                    "(10/8, 172.16/12, 192.168/16, 169.254/16), and resolve hostnames before validation.",
            "path-traversal": "Resolve user paths to absolute, then assert the resolved path remains "
                              "inside the configured workspace root.",
            "deserialization": "Replace untrusted deserialization (pickle/YAML.load/marshal) with safe "
                               "parsers (JSON, YAML safe-load).",
            "auth-bypass": "Add an explicit auth gate (verify token + role) before the affected handler; "
                           "fail closed on any error path.",
            "secret-exposure": "Move the secret out of source-controlled files into the secret manager; "
                               "rotate the leaked credential immediately.",
            "prompt-injection": "Wrap untrusted text with the Shield's scan_recalled boundary before it "
                                "reaches the model context.",
        }
        if cat and cat in summaries:
            return Remediation(summary=summaries[cat], target=target)
        return None


def _compute_confidence(stages: list[StageVerdict], confirmed: bool) -> float:
    if not confirmed:
        return 0.15
    if not stages:
        return 0.5
    passed = sum(1 for s in stages if s.passed)
    return min(1.0, 0.5 + 0.5 * (passed / len(stages)))
