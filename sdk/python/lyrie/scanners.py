"""
Lyrie Multi-Language Vulnerability Scanners — Python port (subset).

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Eight Lyrie-original scanners (JS / TS / Python / Go / PHP / Ruby / C / C++)
with the same rule-id namespace as the TypeScript implementation. Findings
flow into Stages A–F validation downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Final, Iterable, Optional, Pattern

from lyrie.stages import Finding, Severity, Category

SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"


@dataclass(slots=True)
class _Rule:
    id: str
    title: str
    category: Category
    severity: Severity
    cwe: str
    description: str
    pattern: Pattern[str]
    refine: Optional[Callable[[str], bool]] = None


@dataclass(slots=True)
class ScanReport:
    scanned_files: int
    findings: list[Finding]
    languages: list[tuple[str, int]] = field(default_factory=list)
    signature: str = SIGNATURE


# ─── Rules ──────────────────────────────────────────────────────────────────

def _re(p: str, flags: int = 0) -> Pattern[str]:
    return re.compile(p, flags | re.MULTILINE)


_RULES_JSTS: Final[tuple[_Rule, ...]] = (
    _Rule("lyrie-jsts-shell-001", "Possible shell injection via child_process",
          "shell-injection", "high", "CWE-78",
          "User-controlled data is passed to child_process.exec or execSync.",
          _re(r"\b(child_process\.(exec|execSync)|require\(['\"]child_process['\"]\)\.(exec|execSync))\s*\(")),
    _Rule("lyrie-jsts-eval-001", "Use of eval / Function constructor",
          "rce", "critical", "CWE-95",
          "eval / new Function execute arbitrary strings as JavaScript.",
          _re(r"(?:^|[^.\w])\b(eval|new\s+Function)\s*\(", re.IGNORECASE),
          refine=lambda line: not re.search(r"[a-zA-Z_)\]]\s*\.(eval)\s*\(", line)),
    _Rule("lyrie-jsts-xss-001", "innerHTML / dangerouslySetInnerHTML sink",
          "xss", "high", "CWE-79",
          "User strings assigned to innerHTML trigger reflective XSS.",
          _re(r"(\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML\s*[:=])")),
    _Rule("lyrie-jsts-sqli-001", "Template-string SQL with user data",
          "sql-injection", "critical", "CWE-89",
          "SQL constructed by template literal with embedded `${...}` from request data.",
          _re(r"\b(query|raw|execute)\s*\(\s*[`][^`]*\$\{[^}]+\}[^`]*[`]")),
)

_RULES_PY: Final[tuple[_Rule, ...]] = (
    _Rule("lyrie-py-shell-001", "subprocess called with shell=True",
          "shell-injection", "high", "CWE-78",
          "subprocess.run / Popen / call with shell=True passes through /bin/sh.",
          _re(r"\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True")),
    _Rule("lyrie-py-os-system-001", "os.system / os.popen with user data",
          "shell-injection", "high", "CWE-78",
          "os.system / os.popen always passes through the shell.",
          _re(r"\bos\.(system|popen)\s*\(")),
    _Rule("lyrie-py-pickle-001", "Untrusted pickle deserialization",
          "deserialization", "critical", "CWE-502",
          "pickle.loads on untrusted data is RCE-by-design.",
          _re(r"\b(pickle|cPickle)\.(loads?|Unpickler)\s*\(")),
    _Rule("lyrie-py-yaml-load-001", "yaml.load without SafeLoader",
          "deserialization", "high", "CWE-502",
          "yaml.load() without SafeLoader can execute arbitrary Python.",
          _re(r"\byaml\.load\s*\([^)]*\)"),
          refine=lambda line: not re.search(r"SafeLoader|safe_load", line, re.IGNORECASE)),
    _Rule("lyrie-py-eval-001", "eval / exec on user data",
          "rce", "critical", "CWE-95",
          "Python eval / exec on untrusted strings is direct RCE.",
          _re(r"(?:^|[^.])\b(eval|exec)\s*\("),
          refine=lambda line: (
              not re.search(r"\bast\.literal_eval\b", line)
              and not re.search(r"[a-zA-Z_)\]]\s*\.(eval|exec)\s*\(", line)
          )),
    _Rule("lyrie-py-flask-debug-001", "Flask app.run(debug=True) in source",
          "rce", "high", "CWE-489",
          "Flask debug mode exposes the Werkzeug debugger PIN console — RCE.",
          _re(r"\bapp\.run\s*\([^)]*debug\s*=\s*True")),
)

_RULES_GO: Final[tuple[_Rule, ...]] = (
    _Rule("lyrie-go-shell-001", "exec.Command with /bin/sh -c and user input",
          "shell-injection", "high", "CWE-78",
          "exec.Command(\"/bin/sh\", \"-c\", ...) is shell-injectable.",
          _re(r"\bexec\.Command\s*\(\s*\"/bin/sh\"\s*,\s*\"-c\"")),
    _Rule("lyrie-go-tls-skip-verify-001", "tls.Config InsecureSkipVerify=true",
          "auth-bypass", "high", "CWE-295",
          "Disabling TLS verification breaks the trust chain.",
          _re(r"\bInsecureSkipVerify\s*:\s*true")),
)

_RULES_PHP: Final[tuple[_Rule, ...]] = (
    _Rule("lyrie-php-rce-001", "Direct RCE via system / exec / shell_exec",
          "rce", "critical", "CWE-78",
          "PHP shell-execution functions on user input is direct RCE.",
          _re(r"\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(")),
    _Rule("lyrie-php-deserialize-001", "unserialize() on untrusted input",
          "deserialization", "critical", "CWE-502",
          "PHP unserialize() enables object-injection RCE chains.",
          _re(r"\bunserialize\s*\(")),
    _Rule("lyrie-php-include-001", "Local/Remote File Inclusion via dynamic include",
          "path-traversal", "critical", "CWE-98",
          "include / require with $_GET-derived paths permits LFI/RFI.",
          _re(r"\b(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)")),
)

_RULES_RB: Final[tuple[_Rule, ...]] = (
    _Rule("lyrie-rb-marshal-001", "Marshal.load on untrusted bytes",
          "deserialization", "critical", "CWE-502",
          "Marshal.load on untrusted data is RCE-by-design.",
          _re(r"\bMarshal\.load\s*\(")),
    _Rule("lyrie-rb-yaml-load-001", "YAML.load on untrusted input",
          "deserialization", "critical", "CWE-502",
          "YAML.load on untrusted YAML can execute arbitrary Ruby.",
          _re(r"\bYAML\.load\s*\("),
          refine=lambda line: not re.search(r"safe_load", line)),
)

_RULES_C: Final[tuple[_Rule, ...]] = (
    _Rule("lyrie-cpp-strcpy-001", "Use of strcpy / strcat / sprintf / gets",
          "rce", "high", "CWE-120",
          "Unbounded C string functions are classic overflow vectors.",
          _re(r"\b(strcpy|strcat|sprintf|gets)\s*\(")),
    _Rule("lyrie-cpp-system-001", "system() / popen() with user-controlled string",
          "shell-injection", "critical", "CWE-78",
          "system / popen pass through /bin/sh.",
          _re(r"\b(system|popen)\s*\(")),
)


_LANG_BY_EXT: Final[dict[str, tuple[str, tuple[_Rule, ...]]]] = {
    ".js": ("javascript", _RULES_JSTS),
    ".jsx": ("javascript", _RULES_JSTS),
    ".mjs": ("javascript", _RULES_JSTS),
    ".cjs": ("javascript", _RULES_JSTS),
    ".ts": ("typescript", _RULES_JSTS),
    ".tsx": ("typescript", _RULES_JSTS),
    ".py": ("python", _RULES_PY),
    ".pyi": ("python", _RULES_PY),
    ".go": ("go", _RULES_GO),
    ".php": ("php", _RULES_PHP),
    ".php5": ("php", _RULES_PHP),
    ".phtml": ("php", _RULES_PHP),
    ".rb": ("ruby", _RULES_RB),
    ".rake": ("ruby", _RULES_RB),
    ".c": ("c", _RULES_C),
    ".h": ("c", _RULES_C),
    ".cpp": ("cpp", _RULES_C),
    ".cc": ("cpp", _RULES_C),
    ".cxx": ("cpp", _RULES_C),
    ".hpp": ("cpp", _RULES_C),
    ".hh": ("cpp", _RULES_C),
}


def scan_files(
    *,
    root: str | Path = ".",
    files: Optional[Iterable[str]] = None,
    max_bytes_per_file: int = 200_000,
) -> ScanReport:
    """Scan files in *root*. If *files* is None, walk the directory."""
    root_path = Path(root).resolve()
    if files is None:
        candidates = [
            str(p.relative_to(root_path))
            for p in root_path.rglob("*")
            if p.is_file()
        ]
    else:
        candidates = list(files)

    findings: list[Finding] = []
    lang_counts: dict[str, int] = {}
    scanned = 0

    for rel in candidates:
        ext = Path(rel).suffix.lower()
        if ext not in _LANG_BY_EXT:
            continue
        abs_path = (root_path / rel) if not Path(rel).is_absolute() else Path(rel)
        if not abs_path.is_file():
            continue
        try:
            content = abs_path.read_text("utf-8", errors="replace")[:max_bytes_per_file]
        except OSError:
            continue
        if "lyrie-shield: ignore-file" in content[:4096]:
            continue

        lang, rules = _LANG_BY_EXT[ext]
        scanned += 1

        for rule in rules:
            for m in rule.pattern.finditer(content):
                idx = m.start()
                # Get surrounding line for refinement
                line_start = content.rfind("\n", 0, idx) + 1
                line_end = content.find("\n", idx)
                if line_end == -1:
                    line_end = len(content)
                line_text = content[line_start:line_end]
                if rule.refine and not rule.refine(line_text):
                    continue
                lang_counts[lang] = lang_counts.get(lang, 0) + 1
                findings.append(Finding(
                    id=f"{rule.id}-{rel}-{content.count(chr(10), 0, idx) + 1}",
                    title=rule.title,
                    severity=rule.severity,
                    description=rule.description,
                    file=rel,
                    line=content.count("\n", 0, idx) + 1,
                    cwe=rule.cwe,
                    category=rule.category,
                    evidence=line_text.strip()[:240],
                ))

    return ScanReport(
        scanned_files=scanned,
        findings=findings,
        languages=sorted(lang_counts.items()),
    )
