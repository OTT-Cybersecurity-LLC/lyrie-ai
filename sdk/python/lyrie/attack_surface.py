"""
Lyrie Attack-Surface Mapper — Python port.

Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.

Builds a structural picture of what's worth attacking BEFORE any
vulnerability scanner runs. Pure static analysis; never executes code,
never opens a network socket. Every text it ingests passes the Shield.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Iterable, Literal, Optional, Pattern, Sequence

from lyrie.shield import Shield, ShieldVerdict

MAPPER_VERSION: Final[str] = "lyrie-asm-py-1.0.0"
SIGNATURE: Final[str] = "Lyrie.ai by OTT Cybersecurity LLC"

EntryKind = Literal[
    "http-route", "cli-command", "file-reader", "env-consumer",
    "deserialization-sink", "subprocess", "render", "websocket", "cron",
]
BoundaryKind = Literal[
    "auth-gate", "rbac-check", "rate-limit", "sandbox-cross",
    "shell-exec", "network-egress", "shield-gate",
]
FlowSource = Literal[
    "http-input", "cli-arg", "env-var", "file-read", "network-fetch",
    "user-message", "mcp-tool-result", "memory-recall",
]
FlowSink = Literal[
    "shell", "filesystem-write", "sql", "http-output",
    "agent-prompt", "tool-call", "deserialization",
]


@dataclass(slots=True)
class EntryPoint:
    kind: EntryKind
    file: str
    line: int
    evidence: str
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class TrustBoundary:
    kind: BoundaryKind
    file: str
    line: int
    evidence: str


@dataclass(slots=True)
class DataFlow:
    source: FlowSource
    sink: FlowSink
    file: str
    line: int
    evidence: str
    risk: int


@dataclass(slots=True)
class DependencyEntry:
    name: str
    version: Optional[str] = None
    manifest: str = ""
    ecosystem: str = "unknown"


@dataclass(slots=True)
class RiskHotspot:
    file: str
    score: int
    reasons: list[str]


@dataclass(slots=True)
class AttackSurface:
    root: str
    files_inspected: int
    files_ignored: int
    files_shielded: int
    entry_points: list[EntryPoint]
    trust_boundaries: list[TrustBoundary]
    data_flows: list[DataFlow]
    dependencies: list[DependencyEntry]
    hotspots: list[RiskHotspot]
    generated_at: str
    mapper_version: str = MAPPER_VERSION
    signature: str = SIGNATURE


# ─── Detector regexes ───────────────────────────────────────────────────────

_ENTRY_DETECTORS: Final[Sequence[tuple[EntryKind, Pattern[str]]]] = (
    ("http-route", re.compile(
        r"\b(?:app|router|route|server|fastify|hono|elysia|express|koa)"
        r"\.(get|post|put|patch|delete|all|use)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]",
        re.IGNORECASE,
    )),
    ("http-route", re.compile(r"@(?:Get|Post|Put|Patch|Delete|All)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")),
    ("http-route", re.compile(r"@app\.route\(\s*[\"'`]([^\"'`]+)[\"'`]")),
    ("http-route", re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\([^)]*request[^)]*\)", re.MULTILINE)),
    ("cli-command", re.compile(r"\bprogram\.command\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")),
    ("cli-command", re.compile(r"\b@click\.command\(")),
    ("cli-command", re.compile(r"\bcobra\.Command\s*\{")),
    ("file-reader", re.compile(r"\b(readFileSync|readFile|fs\.readFile|os\.open|ioutil\.ReadFile)\b")),
    ("file-reader", re.compile(r"\bopen\s*\([^)]*[\"'][^\"']+[\"']")),
    ("env-consumer", re.compile(r"\bprocess\.env\.[A-Z_][A-Z0-9_]*")),
    ("env-consumer", re.compile(r"\bos\.environ\b")),
    ("env-consumer", re.compile(r"\bos\.getenv\s*\(\s*[\"'`]([A-Z_][A-Z0-9_]*)[\"'`]", re.IGNORECASE)),
    ("deserialization-sink", re.compile(
        r"\b(JSON\.parse|YAML\.parse|yaml\.load|pickle\.loads?|marshal\.loads?|deserialize|fromJSON)\b"
    )),
    ("subprocess", re.compile(
        r"\b(exec|execSync|spawn|spawnSync|child_process|subprocess\.run|os\.system|exec\.Command)\b"
    )),
    ("render", re.compile(
        r"\b(res\.render|renderTemplate|renderToString|render_template|template\.Execute)\b"
    )),
    ("websocket", re.compile(r"\b(new WebSocket|ws\.on\s*\(|wss\.on\s*\()")),
    ("cron", re.compile(r"\b(cron\.schedule|new CronJob|@Cron|crontab)")),
)

_BOUNDARY_DETECTORS: Final[Sequence[tuple[BoundaryKind, Pattern[str]]]] = (
    ("auth-gate", re.compile(
        r"\b(authenticate|requireAuth|isAuthenticated|verifyToken|jwt\.verify|passport\.authenticate)\b"
    )),
    ("rbac-check", re.compile(r"\b(hasRole|requireRole|checkPermission|authorize|policy\.|rbac)\b", re.IGNORECASE)),
    ("rate-limit", re.compile(r"\b(rateLimit|rate_limit|RateLimiter|throttle\(|express-rate-limit)\b", re.IGNORECASE)),
    ("sandbox-cross", re.compile(r"\b(sandbox|vm\.createContext|nsjail|firejail|seccomp|chroot|namespaces)\b", re.IGNORECASE)),
    ("shell-exec", re.compile(r"\b(execSync|spawnSync|os\.system|subprocess\.run)\b")),
    ("network-egress", re.compile(r"\b(fetch\s*\(|http\.get|https\.get|requests\.get|net\.Dial)\b")),
    ("shield-gate", re.compile(r"\b(scan_inbound|scan_recalled|ShieldGuard|ShieldManager|Shield\(\))\b")),
)

_FLOW_DETECTORS: Final[Sequence[tuple[FlowSource, FlowSink, Pattern[str], int]]] = (
    ("user-message", "shell", re.compile(
        r"\b(child_process\.(exec|spawn)|execSync|spawnSync|os\.system|subprocess\.(run|call|Popen))"
        r"\s*\([^)]*\b(req|request|input|message|body|userInput|args\.[a-zA-Z_])\b",
        re.IGNORECASE,
    ), 9),
    ("http-input", "sql", re.compile(
        r"\b(query|execute|raw)\s*\(\s*[`'\"][^`'\"]*\$\{[^}]+\}",
    ), 8),
    ("env-var", "shell", re.compile(
        r"(execSync|spawn|os\.system)\s*\([^)]*process\.env\.",
    ), 7),
    ("network-fetch", "agent-prompt", re.compile(
        r"\b(fetch|http\.get|requests\.get)[^;]*\.(text|json)\(\)[^;]*\b(prompt|system|message)",
        re.IGNORECASE,
    ), 8),
    ("file-read", "agent-prompt", re.compile(
        r"\b(readFileSync|readFile)[^;]*\.\s*(prompt|system|content)",
    ), 6),
    ("memory-recall", "agent-prompt", re.compile(
        r"\b(recall|searchAcrossSessions)\s*\(",
    ), 4),
)

# ─── Ignore globs ────────────────────────────────────────────────────────────

_IGNORE_PATTERNS: Final[Sequence[Pattern[str]]] = tuple(
    re.compile(p)
    for p in (
        r"(^|/)\.next/",
        r"(^|/)\.turbo/",
        r"(^|/)node_modules/",
        r"(^|/)dist/",
        r"(^|/)build/",
        r"(^|/)target/",
        r"(^|/)\.git/",
        r"(^|/)coverage/",
        r"(^|/)__pycache__/",
        r"\.lock$",
        r"\.min\.(js|css)$",
        r"\.map$",
        r"\.png$",
        r"\.jpg$",
        r"\.jpeg$",
        r"\.gif$",
        r"\.webp$",
        r"\.pdf$",
        r"\.zip$",
        r"\.tar\.gz$",
    )
)

_TEXT_EXTS: Final[frozenset[str]] = frozenset({
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".pyi", ".go", ".rs", ".rb", ".java", ".kt", ".swift",
    ".php", ".cs", ".cpp", ".cc", ".c", ".h", ".hpp",
    ".sh", ".bash", ".zsh", ".fish",
    ".html", ".vue", ".svelte",
    ".yaml", ".yml", ".toml", ".json", ".env",
})


# ─── Public API ──────────────────────────────────────────────────────────────


class AttackSurfaceMapper:
    """
    Lyrie Attack-Surface Mapper.

    Lyrie.ai by OTT Cybersecurity LLC.
    """

    __slots__ = ("_root", "_files", "_max_files", "_max_bytes", "_shield", "_deps_only")

    def __init__(
        self,
        root: str | Path = ".",
        *,
        files: Optional[Iterable[str]] = None,
        max_files: int = 5_000,
        max_bytes_per_file: int = 200_000,
        shield: Optional[Shield] = None,
        deps_only: bool = False,
    ) -> None:
        self._root = Path(root).resolve()
        self._files = list(files) if files is not None else None
        self._max_files = max_files
        self._max_bytes = max_bytes_per_file
        self._shield = shield or Shield()
        self._deps_only = deps_only

    def run(self) -> AttackSurface:
        files = self._resolve_files()
        entries: list[EntryPoint] = []
        boundaries: list[TrustBoundary] = []
        flows: list[DataFlow] = []
        inspected = ignored = shielded = 0

        if not self._deps_only:
            for rel in files:
                if any(p.search(rel) for p in _IGNORE_PATTERNS):
                    ignored += 1
                    continue
                ext = Path(rel).suffix.lower()
                if ext not in _TEXT_EXTS:
                    ignored += 1
                    continue
                abs_path = self._root / rel
                if not abs_path.is_file():
                    continue
                try:
                    content = abs_path.read_text("utf-8", errors="replace")[: self._max_bytes]
                except OSError:
                    continue
                if "lyrie-shield: ignore-file" in content[:4096]:
                    ignored += 1
                    continue

                self._detect_into(content, rel, entries, boundaries, flows)
                inspected += 1

        deps = _collect_dependencies(self._root)
        hotspots = _rank_hotspots(self._root, files, entries, boundaries, flows)

        return AttackSurface(
            root=str(self._root),
            files_inspected=inspected,
            files_ignored=ignored,
            files_shielded=shielded,
            entry_points=entries,
            trust_boundaries=boundaries,
            data_flows=flows,
            dependencies=deps,
            hotspots=hotspots,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
        )

    # ── internals ──────────────────────────────────────────────────────────

    def _resolve_files(self) -> list[str]:
        if self._files is not None:
            return self._files[: self._max_files]
        return _list_repo_files(self._root, self._max_files)

    def _detect_into(
        self,
        content: str,
        file: str,
        entries: list[EntryPoint],
        boundaries: list[TrustBoundary],
        flows: list[DataFlow],
    ) -> None:
        for kind, rx in _ENTRY_DETECTORS:
            for m in rx.finditer(content):
                entries.append(EntryPoint(
                    kind=kind, file=file, line=_line_of(content, m.start()),
                    evidence=_excerpt(content, m.start()),
                ))
        for kind, rx in _BOUNDARY_DETECTORS:
            for m in rx.finditer(content):
                boundaries.append(TrustBoundary(
                    kind=kind, file=file, line=_line_of(content, m.start()),
                    evidence=_excerpt(content, m.start()),
                ))
        for source, sink, rx, risk in _FLOW_DETECTORS:
            for m in rx.finditer(content):
                ev = _excerpt(content, m.start())
                if self._shield.scan_recalled(ev).blocked:
                    continue
                flows.append(DataFlow(
                    source=source, sink=sink, file=file,
                    line=_line_of(content, m.start()),
                    evidence=ev, risk=risk,
                ))


# ─── Helpers ────────────────────────────────────────────────────────────────


def _line_of(content: str, idx: int) -> int:
    return content.count("\n", 0, idx) + 1


def _excerpt(content: str, idx: int, *, span: int = 80) -> str:
    start = max(0, idx - 20)
    end = min(len(content), idx + span)
    return " ".join(content[start:end].split())


def _list_repo_files(root: Path, limit: int) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            check=True, text=True, capture_output=True, timeout=15,
        )
        if result.stdout:
            return [ln for ln in result.stdout.splitlines() if ln][:limit]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return _walk_dir(root, limit)


def _walk_dir(root: Path, limit: int) -> list[str]:
    out: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root))
        if any(p.search(rel) for p in _IGNORE_PATTERNS):
            continue
        out.append(rel)
        if len(out) >= limit:
            break
    return out


def _collect_dependencies(root: Path) -> list[DependencyEntry]:
    deps: list[DependencyEntry] = []
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            import json
            data = json.loads(pkg.read_text("utf-8"))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, version in (data.get(section) or {}).items():
                    deps.append(DependencyEntry(
                        name=name, version=str(version),
                        manifest="package.json", ecosystem="npm",
                    ))
        except (OSError, ValueError):
            pass
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text("utf-8")
            for m in re.finditer(r"^\s*([a-zA-Z0-9_\-]+)\s*=\s*[\"'][^\"']+[\"']", content, re.MULTILINE):
                deps.append(DependencyEntry(
                    name=m.group(1), manifest="pyproject.toml", ecosystem="pip",
                ))
        except OSError:
            pass
    return deps


_KIND_WEIGHT: Final[dict[str, int]] = {
    "http-route": 3, "websocket": 3,
    "deserialization-sink": 4, "subprocess": 4,
    "file-reader": 1, "env-consumer": 1,
    "render": 2, "cli-command": 2, "cron": 2,
}


def _rank_hotspots(
    root: Path,
    files: list[str],
    entries: list[EntryPoint],
    boundaries: list[TrustBoundary],
    flows: list[DataFlow],
) -> list[RiskHotspot]:
    scores: dict[str, dict] = {}

    def bump(file: str, score: int, reason: str) -> None:
        if file not in scores:
            scores[file] = {"score": 0, "reasons": set()}
        scores[file]["score"] += score
        scores[file]["reasons"].add(reason)

    for ep in entries:
        bump(ep.file, _KIND_WEIGHT.get(ep.kind, 1), f"entry:{ep.kind}")
    for tb in boundaries:
        bump(tb.file, 1, f"boundary:{tb.kind}")
    for f in flows:
        bump(f.file, f.risk, f"flow:{f.source}->{f.sink}")

    now = time.time()
    for file in files:
        path = root / file
        try:
            mtime = path.stat().st_mtime
            if now - mtime < 30 * 24 * 3600 and file in scores:
                scores[file]["score"] += 1
                scores[file]["reasons"].add("recently-edited")
        except OSError:
            pass

    return [
        RiskHotspot(
            file=file,
            score=min(10, info["score"]),
            reasons=sorted(info["reasons"]),
        )
        for file, info in sorted(scores.items(), key=lambda kv: -kv[1]["score"])[:25]
    ]
